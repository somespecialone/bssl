# Connector for aiohttp.ClientSession, dedicated bssl.ClientContext for each session
# All ssl.SSLContext passed to request methods and session will be ignored
# Be aware with HTTP2 as it highly likely won't work

import asyncio
import sys
import socket
import ssl
import collections
import itertools
import warnings
from asyncio import staggered, selector_events, proactor_events, sslproto, constants

from python_socks.async_.asyncio.v2._proxy import (
    AsyncioProxy,
    Resolver,
    DEFAULT_TIMEOUT,
    ProxyTimeoutError,
    ProxyConnectionError,
    ProxyError,
    ReplyError,
    AsyncioSocketStream,
    create_connector,
)
from aiohttp.connector import ClientConnectorError, ResponseHandler
from aiohttp_socks import ProxyConnector, ProxyType
from aiohttp_socks.connector import NoResolver, TCPConnector, _ResponseHandler, _BaseProxyConnector

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


# move sync operation (loading certs) out from "runtime" to import time
_DEF_BSSL_CONTEXT = ClientContext(TLSClientConfiguration())


class BSSLProtocol(sslproto.SSLProtocol):
    def __init__(
        self,
        loop,
        app_protocol,
        waiter,
        server_side=False,
        server_hostname=None,
        call_connection_made=True,
        ssl_handshake_timeout=None,
        ssl_shutdown_timeout=None,
        bssl_ctx: ClientContext = _DEF_BSSL_CONTEXT,
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
        self._extra = dict()

        self._write_backlog = collections.deque()
        self._write_buffer_size = 0

        self._waiter = waiter
        self._loop = loop
        self._set_app_protocol(app_protocol)
        self._app_transport = None
        self._app_transport_created = False
        self._transport = None
        self._ssl_handshake_timeout = ssl_handshake_timeout
        self._ssl_shutdown_timeout = ssl_shutdown_timeout
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
        self._write_backlog.clear()
        self._tls_buff.process_outgoing(-1)
        self._conn_lost += 1

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


class BSSLStreamWriter(asyncio.StreamWriter):
    _loop: asyncio.AbstractEventLoop

    async def _loop_start_tls(
        self,
        transport,
        protocol,
        sslcontext: ClientContext,
        *,
        server_side=False,
        server_hostname=None,
        ssl_handshake_timeout=None,
        ssl_shutdown_timeout=None,
    ):
        waiter = self._loop.create_future()
        ssl_protocol = BSSLProtocol(
            self._loop,
            protocol,
            waiter,
            server_side,
            server_hostname,
            ssl_handshake_timeout=ssl_handshake_timeout,
            ssl_shutdown_timeout=ssl_shutdown_timeout,
            bssl_ctx=sslcontext,
            call_connection_made=False,
        )

        transport.pause_reading()

        transport.set_protocol(ssl_protocol)
        conmade_cb = self._loop.call_soon(ssl_protocol.connection_made, transport)
        resume_cb = self._loop.call_soon(transport.resume_reading)

        try:
            await waiter
        except BaseException:
            transport.close()
            conmade_cb.cancel()
            resume_cb.cancel()
            raise

        return ssl_protocol._app_transport

    async def start_tls(
        self,
        sslcontext: ClientContext,
        *,
        server_hostname=None,
        ssl_handshake_timeout=None,
        ssl_shutdown_timeout=None,
    ):
        protocol = self._protocol
        await self.drain()
        new_transport = await self._loop_start_tls(
            self._transport,
            protocol,
            sslcontext,
            server_hostname=server_hostname,
            ssl_handshake_timeout=ssl_handshake_timeout,
            ssl_shutdown_timeout=ssl_shutdown_timeout,
        )
        self._transport = new_transport
        protocol._replace_writer(self)


class BSSLAsyncProxy(AsyncioProxy):
    def __init__(
        self,
        proxy_type,
        host,
        port,
        username=None,
        password=None,
        rdns=None,
        proxy_ssl: ClientContext = None,
        forward: "BSSLAsyncProxy" = None,
    ):
        self._loop = asyncio.get_event_loop()

        self._proxy_type = proxy_type
        self._proxy_host = host
        self._proxy_port = port
        self._username = username
        self._password = password
        self._rdns = rdns

        self._proxy_ssl = proxy_ssl
        self._forward = forward

        self._resolver = Resolver(loop=self._loop)

    async def _connect(self, dest_host, dest_port, dest_ssl: ClientContext = None, local_addr=None):
        if self._forward is None:
            try:
                # asyncio.streams.open_connection
                reader = asyncio.StreamReader(limit=asyncio.streams._DEFAULT_LIMIT, loop=self._loop)
                protocol = asyncio.StreamReaderProtocol(reader, loop=self._loop)
                transport, _ = await self._loop.create_connection(
                    lambda: protocol,
                    self._proxy_host,
                    self._proxy_port,
                    local_addr=local_addr,
                )
                writer = BSSLStreamWriter(transport, protocol, reader, self._loop)

                # python_socks.async_.asyncio.v2._connect.connect_tcp
                stream = AsyncioSocketStream(
                    loop=self._loop,
                    reader=reader,
                    writer=writer,
                )

            except OSError as e:
                raise ProxyConnectionError(
                    e.errno,
                    "Couldn't connect to proxy" f" {self._proxy_host}:{self._proxy_port} [{e.strerror}]",
                ) from e

        else:
            stream = await self._forward.connect(
                dest_host=self._proxy_host,
                dest_port=self._proxy_port,
            )

        try:
            if self._proxy_ssl is not None:
                stream = await stream.start_tls(hostname=self._proxy_host, ssl_context=self._proxy_ssl)

            connector = create_connector(
                proxy_type=self._proxy_type,
                username=self._username,
                password=self._password,
                rdns=self._rdns,
                resolver=self._resolver,
            )

            await connector.connect(stream=stream, host=dest_host, port=dest_port)

            if dest_ssl is not None:
                stream = await stream.start_tls(hostname=dest_host, ssl_context=dest_ssl)
        except ReplyError as e:
            await stream.close()
            raise ProxyError(e, error_code=e.error_code)
        except (asyncio.CancelledError, Exception):
            await stream.close()
            raise

        return stream


class BSSLProxyConnector(ProxyConnector):
    def __init__(
        self,
        host: str,
        port: int,
        proxy_type: ProxyType = ProxyType.SOCKS5,
        username: str | None = None,
        password: str | None = None,
        rdns: bool | None = None,
        proxy_tls_config: TLSClientConfiguration | None = None,
        dest_tls_config: TLSClientConfiguration | None = None,
        **kwargs,
    ):
        kwargs["resolver"] = NoResolver()
        super(_BaseProxyConnector, self).__init__(**kwargs)

        self._proxy_type = proxy_type
        self._proxy_host = host
        self._proxy_port = port
        self._proxy_username = username
        self._proxy_password = password
        self._rdns = rdns

        self._proxy_ssl = ClientContext(proxy_tls_config) if proxy_tls_config is not None else None
        self._dest_ssl = ClientContext(dest_tls_config) if dest_tls_config is not None else _DEF_BSSL_CONTEXT

    async def _connect_via_proxy(self, host, port, ssl=None, timeout=None):
        proxy = BSSLAsyncProxy(
            proxy_type=self._proxy_type,
            host=self._proxy_host,
            port=self._proxy_port,
            username=self._proxy_username,
            password=self._proxy_password,
            rdns=self._rdns,
            proxy_ssl=self._proxy_ssl,
        )

        stream = await proxy.connect(
            dest_host=host,
            dest_port=port,
            dest_ssl=self._dest_ssl if ssl else None,
            timeout=timeout,
        )

        transport = stream.writer.transport
        protocol = _ResponseHandler(loop=self._loop, writer=stream.writer)

        transport.set_protocol(protocol)
        protocol.connection_made(transport)

        return transport, protocol


async def test(cfg: TLSClientConfiguration):
    from aiohttp import ClientSession

    proxy_url = "socks5://user:pass@host:port"
    connector = BSSLProxyConnector.from_url(proxy_url, dest_tls_config=cfg)
    async with ClientSession(connector=connector) as session:
        resp = await session.get("https://tls.peet.ws/api/tls")
        text = await resp.text()
        print(text)

        resp = await session.get("https://jsonip.com/")
        text = await resp.text()
        print(text)


if __name__ == "__main__":
    config = TLSClientConfiguration(grease=True)  # illustrative example

    asyncio.run(test(config))
