# Patch asyncio.sslproto.SSLProtocol, share the same bssl.ClientContext across all connections within process
# works for: aiohttp, aiohttp_socks
# must work for any asyncio-based http client that uses standard loop for connections
# All ssl.SSLContext passed to request methods and session will be ignored
# Be aware with HTTP2 as it highly likely won't work

import asyncio


from bssl import (
    ClientContext,
    TLSClientConfiguration,
    CipherSuite,
    SignatureAlgorithms,
    Curves,
    CertificateCompressionAlgorithm,
    NextProtocol,
    TLSVersion,
    WantReadError,
    TLSError,
)


def patch(bssl_ctx: ClientContext):
    import ssl
    import collections

    from asyncio import sslproto, constants

    original_ssl_protocol = sslproto.SSLProtocol

    class BSSLProtocol(sslproto.SSLProtocol):
        def __new__(
            cls,
            loop,
            app_protocol,
            sslcontext,
            waiter,
            server_side=False,
            server_hostname=None,
            call_connection_made=True,
            ssl_handshake_timeout=None,
            ssl_shutdown_timeout=None,
        ):
            if server_side:
                return original_ssl_protocol(
                    loop,
                    app_protocol,
                    sslcontext,
                    waiter,
                    server_side,
                    server_hostname,
                    call_connection_made,
                    ssl_handshake_timeout,
                    ssl_shutdown_timeout,
                )

            return super().__new__(cls)

        def __init__(
            self,
            loop,
            app_protocol,
            sslcontext,
            waiter,
            server_side=False,
            server_hostname=None,
            call_connection_made=True,
            ssl_handshake_timeout=None,
            ssl_shutdown_timeout=None,
        ):
            self._ssl_buffer = bytearray(self.max_size)
            self._ssl_buffer_view = memoryview(self._ssl_buffer)

            if ssl_handshake_timeout is None:
                ssl_handshake_timeout = constants.SSL_HANDSHAKE_TIMEOUT
            elif ssl_handshake_timeout <= 0:
                raise ValueError(f"ssl_handshake_timeout should be a positive number, " f"got {ssl_handshake_timeout}")
            if ssl_shutdown_timeout is None:
                ssl_shutdown_timeout = constants.SSL_SHUTDOWN_TIMEOUT
            elif ssl_shutdown_timeout <= 0:
                raise ValueError(f"ssl_shutdown_timeout should be a positive number, " f"got {ssl_shutdown_timeout}")

            self._server_side = server_side
            if server_hostname and not server_side:
                self._server_hostname = server_hostname
            else:
                self._server_hostname = None
            self._sslcontext = sslcontext
            # SSL-specific extra info. More info are set when the handshake
            # completes.
            self._extra = dict(sslcontext=sslcontext)

            # App data write buffering
            self._write_backlog = collections.deque()
            self._write_buffer_size = 0

            self._waiter = waiter
            self._loop = loop
            self._set_app_protocol(app_protocol)
            self._app_transport = None
            self._app_transport_created = False
            # transport, ex: SelectorSocketTransport
            self._transport = None
            self._ssl_handshake_timeout = ssl_handshake_timeout
            self._ssl_shutdown_timeout = ssl_shutdown_timeout
            # SSL and state machine
            self._state = sslproto.SSLProtocolState.UNWRAPPED
            self._conn_lost = 0  # Set when connection_lost called
            if call_connection_made:
                self._app_state = sslproto.AppProtocolState.STATE_INIT
            else:
                self._app_state = sslproto.AppProtocolState.STATE_CON_MADE

            self._tls_buff = bssl_ctx.create_buffer(self._server_hostname)

            # Flow Control

            self._ssl_writing_paused = False

            self._app_reading_paused = False

            self._ssl_reading_paused = False
            self._incoming_high_water = 0
            self._incoming_low_water = 0
            self._set_read_buffer_limits()
            self._eof_received = False

            self._app_writing_paused = False
            self._outgoing_high_water = 0
            self._outgoing_low_water = 0
            self._set_write_buffer_limits()
            self._get_app_transport()

        def _do_handshake(self):
            try:
                try:
                    self._tls_buff.do_handshake()
                except WantReadError:
                    raise ssl.SSLWantReadError
                except TLSError:
                    raise ssl.SSLError("The handshake operation failed")

            except sslproto.SSLAgainErrors:
                self._process_outgoing()
            except ssl.SSLError as exc:
                self._on_handshake_complete(exc)
            else:
                self._on_handshake_complete(None)

        def _on_handshake_complete(self, handshake_exc):
            if self._handshake_timeout_handle is not None:
                self._handshake_timeout_handle.cancel()
                self._handshake_timeout_handle = None

            try:
                if handshake_exc is None:
                    self._set_state(sslproto.SSLProtocolState.WRAPPED)
                else:
                    raise handshake_exc

            except Exception as exc:
                handshake_exc = None
                self._set_state(sslproto.SSLProtocolState.UNWRAPPED)
                if isinstance(exc, ssl.CertificateError):
                    msg = "SSL handshake failed on verifying the certificate"
                else:
                    msg = "SSL handshake failed"
                self._fatal_error(exc, msg)
                self._wakeup_waiter(exc)
                return

            if self._loop.get_debug():
                dt = self._loop.time() - self._handshake_start_time
                sslproto.logger.debug("%r: SSL handshake took %.1f ms", self, dt * 1e3)

            # Add extra info that becomes available after handshake.
            self._extra.update(peercert=None, cipher=None, compression=None, ssl_object=None)
            if self._app_state == sslproto.AppProtocolState.STATE_INIT:
                self._app_state = sslproto.AppProtocolState.STATE_CON_MADE
                self._app_protocol.connection_made(self._get_app_transport())
            self._wakeup_waiter()
            self._do_read()

        def _do_shutdown(self):
            try:
                if not self._eof_received:
                    try:
                        self._tls_buff.shutdown()
                    except WantReadError:
                        raise ssl.SSLWantReadError
                    except TLSError:
                        raise ssl.SSLError("The shutdown operation failed")

            except sslproto.SSLAgainErrors:
                self._process_outgoing()
            except ssl.SSLError as exc:
                self._on_shutdown_complete(exc)
            else:
                self._process_outgoing()
                self._call_eof_received()
                self._on_shutdown_complete(None)

        def _do_write(self):
            try:
                while self._write_backlog:
                    data = self._write_backlog[0]
                    count = self._tls_buff.write(data)
                    data_len = len(data)
                    if count < data_len:
                        self._write_backlog[0] = data[count:]
                        self._write_buffer_size -= count
                    else:
                        del self._write_backlog[0]
                        self._write_buffer_size -= data_len
            except WantReadError:
                pass
            self._process_outgoing()

        def _do_read__buffered(self):
            offset = 0
            count = 1

            buf = self._app_protocol_get_buffer(self._get_read_buffer_size())
            wants = len(buf)

            try:
                count = self._tls_buff.read(wants, buf)

                if count > 0:
                    offset = count
                    while offset < wants:
                        count = self._tls_buff.read(wants - offset, buf[offset:])
                        if count > 0:
                            offset += count
                        else:
                            break
                    else:
                        self._loop.call_soon(self._do_read)
            except WantReadError:
                pass
            if offset > 0:
                self._app_protocol_buffer_updated(offset)
            if not count:
                # close_notify
                self._call_eof_received()
                self._start_shutdown()

        def _do_read__copied(self):
            chunk = b"1"
            zero = True
            one = False

            try:
                while True:
                    chunk = self._tls_buff.read(self.max_size)
                    if not chunk:
                        break
                    if zero:
                        zero = False
                        one = True
                        first = chunk
                    elif one:
                        one = False
                        data = [first, chunk]
                    else:
                        data.append(chunk)
            except WantReadError:
                pass
            if one:
                self._app_protocol.data_received(first)
            elif not zero:
                self._app_protocol.data_received(b"".join(data))
            if not chunk:
                # close_notify
                self._call_eof_received()
                self._start_shutdown()

        def buffer_updated(self, nbytes):
            self._tls_buff.process_incoming(bytes(self._ssl_buffer[:nbytes]))

            if self._state == sslproto.SSLProtocolState.DO_HANDSHAKE:
                self._do_handshake()

            elif self._state == sslproto.SSLProtocolState.WRAPPED:
                self._do_read()

            elif self._state == sslproto.SSLProtocolState.FLUSHING:
                self._do_flush()

            elif self._state == sslproto.SSLProtocolState.SHUTDOWN:
                self._do_shutdown()

        def _get_read_buffer_size(self):
            return self._tls_buff.incoming_bytes_buffered()

        def _process_outgoing(self):
            if not self._ssl_writing_paused:
                data = self._tls_buff.process_outgoing(-1)
                if len(data):
                    self._transport.write(data)
            self._control_app_writing()

        def _get_write_buffer_size(self):
            return self._tls_buff.outgoing_bytes_buffered() + self._write_buffer_size

        def connection_lost(self, exc):
            """Called when the low-level connection is lost or closed.

            The argument is an exception object or None (the latter
            meaning a regular EOF is received or the connection was
            aborted or closed).
            """
            self._write_backlog.clear()
            self._tls_buff.process_outgoing(-1)
            self._conn_lost += 1

            # Just mark the app transport as closed so that its __dealloc__
            # doesn't complain.
            if self._app_transport is not None:
                self._app_transport._closed = True

            if self._state != sslproto.SSLProtocolState.DO_HANDSHAKE:
                if (
                    self._app_state == sslproto.AppProtocolState.STATE_CON_MADE
                    or self._app_state == sslproto.AppProtocolState.STATE_EOF
                ):
                    self._app_state = sslproto.AppProtocolState.STATE_CON_LOST
                    self._loop.call_soon(self._app_protocol.connection_lost, exc)
            self._set_state(sslproto.SSLProtocolState.UNWRAPPED)
            self._transport = None
            self._app_transport = None
            self._app_protocol = None
            self._wakeup_waiter(exc)

            if self._shutdown_timeout_handle:
                self._shutdown_timeout_handle.cancel()
                self._shutdown_timeout_handle = None
            if self._handshake_timeout_handle:
                self._handshake_timeout_handle.cancel()
                self._handshake_timeout_handle = None

    # patch
    sslproto.SSLProtocol = BSSLProtocol


async def test(bssl_ctx: ClientContext):
    patch(bssl_ctx)

    from aiohttp import ClientSession

    async with ClientSession() as session:
        resp = await session.get("https://tls.peet.ws/api/tls")
        text = await resp.text()
        print(text)


if __name__ == "__main__":
    config = TLSClientConfiguration(grease=True)  # illustrative example

    bssl_context = ClientContext(config)

    asyncio.run(test(bssl_context))
