# Connector for aiohttp.ClientSession, separate bssl.ClientContext for each session
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

import aiohappyeyeballs

from aiohttp.connector import (
    ClientRequest,
    ClientConnectorDNSError,
    BaseConnector,
    TCPConnector,
    AddrInfoType,
    ClientConnectorError,
    ceil_timeout,
    cert_errors,
    ClientConnectorCertificateError,
    ClientConnectorSSLError,
    ssl_errors,
    AbstractResolver,
    sentinel,
    _SENTINEL,
    SocketFactoryType,
    DefaultResolver,
    _DNSCacheTable,
    ResolveResult,
    ServerFingerprintMismatch,
    ClientConnectionError,
)

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


def _check_ssl_socket(sock):
    if ssl is not None and isinstance(sock, ssl.SSLSocket):
        raise TypeError("Socket cannot be of type SSLSocket")


def _interleave_addrinfos(addrinfos, first_address_family_count=1):
    # Group addresses by family
    addrinfos_by_family = collections.OrderedDict()
    for addr in addrinfos:
        family = addr[0]
        if family not in addrinfos_by_family:
            addrinfos_by_family[family] = []
        addrinfos_by_family[family].append(addr)
    addrinfos_lists = list(addrinfos_by_family.values())

    reordered = []
    if first_address_family_count > 1:
        reordered.extend(addrinfos_lists[0][: first_address_family_count - 1])
        del addrinfos_lists[0][: first_address_family_count - 1]
    reordered.extend(a for a in itertools.chain.from_iterable(itertools.zip_longest(*addrinfos_lists)) if a is not None)
    return reordered


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


class BSSLConnector(TCPConnector):
    def __init__(
        self,
        *,
        tls_config: TLSClientConfiguration | None = None,
        use_dns_cache: bool = True,
        ttl_dns_cache: int | None = 10,
        family: socket.AddressFamily = socket.AddressFamily.AF_UNSPEC,
        local_addr: tuple[str, int] | None = None,
        resolver: AbstractResolver | None = None,
        keepalive_timeout: None | float | object = sentinel,
        force_close: bool = False,
        limit: int = 100,
        limit_per_host: int = 0,
        enable_cleanup_closed: bool = False,
        loop: asyncio.AbstractEventLoop | None = None,
        timeout_ceil_threshold: float = 5,
        happy_eyeballs_delay: float | None = 0.25,
        interleave: int | None = None,
        socket_factory: SocketFactoryType | None = None,
        ssl_shutdown_timeout: float | None = None,
    ):
        super(TCPConnector, self).__init__(
            keepalive_timeout=keepalive_timeout,
            force_close=force_close,
            limit=limit,
            limit_per_host=limit_per_host,
            enable_cleanup_closed=enable_cleanup_closed,
            loop=loop,
            timeout_ceil_threshold=timeout_ceil_threshold,
        )

        self._ssl = ClientContext(tls_config) if tls_config is not None else _DEF_BSSL_CONTEXT

        self._resolver: AbstractResolver
        if resolver is None:
            self._resolver = DefaultResolver(loop=self._loop)
            self._resolver_owner = True
        else:
            self._resolver = resolver
            self._resolver_owner = False

        self._use_dns_cache = use_dns_cache
        self._cached_hosts = _DNSCacheTable(ttl=ttl_dns_cache)
        self._throttle_dns_futures: dict[tuple[str, int], set["asyncio.Future[None]"]] = {}
        self._family = family
        self._local_addr_infos = aiohappyeyeballs.addr_to_addr_infos(local_addr)
        self._happy_eyeballs_delay = happy_eyeballs_delay
        self._interleave = interleave
        self._resolve_host_tasks: set["asyncio.Task[list[ResolveResult]]"] = set()
        self._socket_factory = socket_factory
        self._ssl_shutdown_timeout = ssl_shutdown_timeout

    def _get_ssl_context(self, req) -> ClientContext | None:
        if not req.is_ssl():
            return None
        else:
            return self._ssl

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
            # call_connection_made=False,  # aiohttp.TCPConnector doesn't call loop.start_tls for non-proxied requests
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

    async def _create_direct_connection(self, req, traces, timeout, *, client_error=ClientConnectorError):
        sslcontext = self._get_ssl_context(req)

        host = req.url.raw_host
        assert host is not None
        if host.endswith(".."):
            host = host.rstrip(".") + "."
        port = req.port
        assert port is not None
        try:
            hosts = await self._resolve_host(host, port, traces=traces)
        except OSError as exc:
            if exc.errno is None and isinstance(exc, asyncio.TimeoutError):
                raise
            raise ClientConnectorDNSError(req.connection_key, exc) from exc

        last_exc = None
        addr_infos = self._convert_hosts_to_addr_infos(hosts)
        while addr_infos:
            server_hostname = (req.server_hostname or host).rstrip(".") if sslcontext else None

            try:
                try:
                    async with ceil_timeout(timeout.sock_connect, ceil_threshold=timeout.ceil_threshold):
                        sock = await aiohappyeyeballs.start_connection(
                            addr_infos=addr_infos,
                            local_addr_infos=self._local_addr_infos,
                            happy_eyeballs_delay=self._happy_eyeballs_delay,
                            interleave=self._interleave,
                            loop=self._loop,
                            socket_factory=self._socket_factory,
                        )

                        transport, protocol = await self._loop.create_connection(self._factory, sock=sock)

                        if sslcontext:
                            transport = await self._loop_start_tls(
                                transport,
                                protocol,
                                sslcontext,
                                ssl_handshake_timeout=timeout.total,
                                server_hostname=server_hostname,
                                ssl_shutdown_timeout=self._ssl_shutdown_timeout,
                            )
                        return transport, protocol

                except cert_errors as exc:
                    raise ClientConnectorCertificateError(req.connection_key, exc) from exc
                except ssl_errors as exc:
                    raise ClientConnectorSSLError(req.connection_key, exc) from exc
                except OSError as exc:
                    if exc.errno is None and isinstance(exc, asyncio.TimeoutError):
                        raise
                    raise client_error(req.connection_key, exc) from exc

            except (ClientConnectorError, asyncio.TimeoutError) as exc:
                last_exc = exc
                aiohappyeyeballs.pop_addr_infos_interleave(addr_infos, self._interleave)
                continue

        else:
            assert last_exc is not None
            raise last_exc

    async def close(self, *, abort_ssl=False) -> None:
        if self._resolver_owner:
            await self._resolver.close()
        await super().close(abort_ssl=abort_ssl or not self._ssl_shutdown_timeout)

    async def _start_tls_connection(
        self,
        underlying_transport,
        req,
        timeout,
        client_error=ClientConnectorError,
    ):
        tls_proto = self._factory()  # Create a brand new proto for TLS
        sslcontext = self._get_ssl_context(req)

        try:
            async with ceil_timeout(timeout.sock_connect, ceil_threshold=timeout.ceil_threshold):
                try:
                    tls_transport = await self._loop_start_tls(
                        underlying_transport,
                        tls_proto,
                        sslcontext,
                        server_hostname=req.server_hostname or req.host,
                        ssl_handshake_timeout=timeout.total,
                        ssl_shutdown_timeout=self._ssl_shutdown_timeout,
                    )

                except BaseException:
                    if not self._ssl_shutdown_timeout:
                        underlying_transport.abort()
                    else:
                        underlying_transport.close()
                    raise

        except cert_errors as exc:
            raise ClientConnectorCertificateError(req.connection_key, exc) from exc
        except ssl_errors as exc:
            raise ClientConnectorSSLError(req.connection_key, exc) from exc
        except OSError as exc:
            if exc.errno is None and isinstance(exc, asyncio.TimeoutError):
                raise
            raise client_error(req.connection_key, exc) from exc
        except TypeError as type_err:
            raise ClientConnectionError(
                "Cannot initialize a TLS-in-TLS connection to host "
                f"{req.host!s}:{req.port:d} through an underlying connection "
                f"to an HTTPS proxy {req.proxy!s} ssl:{req.ssl or 'default'} "
                f"[{type_err!s}]"
            ) from type_err
        else:
            if tls_transport is None:
                msg = "Failed to start TLS (possibly caused by closing transport)"
                raise client_error(req.connection_key, OSError(msg))
            tls_proto.connection_made(tls_transport)  # Kick the state machine of the new TLS protocol

        return tls_transport, tls_proto


async def test(cfg: TLSClientConfiguration):
    from aiohttp import ClientSession

    connector = BSSLConnector(tls_config=cfg)
    async with ClientSession(connector=connector) as session:
        resp = await session.get("https://tls.peet.ws/api/tls")
        text = await resp.text()
        print(text)


if __name__ == "__main__":
    config = TLSClientConfiguration(grease=True)  # illustrative example

    asyncio.run(test(config))
