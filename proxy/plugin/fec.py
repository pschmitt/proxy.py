# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import base64
import re
import logging
import ipaddress
import socket
from typing import Any, Dict, List, Optional, Tuple

from ..http import Url, httpHeaders, httpMethods
from ..core.base import TcpUpstreamConnectionHandler
from ..http.proxy import HttpProxyBasePlugin
from ..common.types import HostPort
from ..http.parser import HttpParser
from ..common.utils import text_, bytes_
from ..http.exception import HttpProtocolException
from ..common.constants import (
    COLON,
    ANY_INTERFACE_HOSTNAMES,
    LOCAL_INTERFACE_HOSTNAMES,
)


logger = logging.getLogger(__name__)

DEFAULT_HTTP_ACCESS_LOG_FORMAT = (
    "{client_ip}:{client_port} - "
    + "{request_method} {server_host}:{server_port}{request_path} -> "
    + "{upstream_proxy_host}:{upstream_proxy_port} - "
    + "{response_code} {response_reason} - {response_bytes} bytes - "
    + "{connection_time_ms} ms"
)

DEFAULT_HTTPS_ACCESS_LOG_FORMAT = (
    "{client_ip}:{client_port} - "
    + "{request_method} {server_host}:{server_port} -> "
    + "{upstream_proxy_host}:{upstream_proxy_port} - "
    + "{response_bytes} bytes - {connection_time_ms} ms"
)

# Run two separate instances of proxy.py
# on port 9000 and 9001 BUT WITHOUT ProxyPool plugin
# to avoid infinite loops.
DEFAULT_PROXY_POOL: List[str] = [
    # Yes you may use the instance running with ProxyPoolPlugin itself.
    # ProxyPool plugin will act as a no-op.
    # 'localhost:8899',
    #
    # Remote proxies
    # 'localhost:9000',
    # 'localhost:9001',
]


class FecPlugin(TcpUpstreamConnectionHandler, HttpProxyBasePlugin):
    """Proxy pool plugin simply acts as a proxy adapter for proxy.py itself.

    Imagine this plugin as setting up proxy settings for proxy.py instance itself.
    All incoming client requests are proxied to configured upstream proxies."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        # self._endpoint: Url = self._select_proxy()
        # Cached attributes to be used during access log override
        self._metadata: List[Any] = [
            None,
            None,
            None,
            None,
        ]

    def handle_upstream_data(self, raw: memoryview) -> None:
        self.client.queue(raw)

    def before_upstream_connection(
        self,
        request: HttpParser,
    ) -> Optional[HttpParser]:
        """Avoids establishing the default connection to upstream server
        by returning None.

        TODO(abhinavsingh): Ideally connection to upstream proxy endpoints
        must be bootstrapped within it's own re-usable and garbage collected pool,
        to avoid establishing a new upstream proxy connection for each client request.

        See :class:`~proxy.core.connection.pool.UpstreamConnectionPool` which is a work
        in progress for SSL cache handling.
        """
        # We don't want to send private IP requests to remote proxies
        try:
            if ipaddress.ip_address(text_(request.host)).is_private:
                return request
        except ValueError:
            pass

        proxy = self._select_proxy(text_(request.host))
        # If chosen proxy is the local instance, bypass upstream proxies
        assert proxy.port and proxy.hostname
        if (
            proxy.port == self.flags.port
            and proxy.hostname in LOCAL_INTERFACE_HOSTNAMES + ANY_INTERFACE_HOSTNAMES
        ):
            return request
        # Establish connection to chosen upstream proxy
        endpoint_tuple = (text_(proxy.hostname), proxy.port)
        logger.info("Using endpoint: {0}:{1}".format(*endpoint_tuple))
        self.initialize_upstream(*endpoint_tuple)
        assert self.upstream
        try:
            self.upstream.connect()
        except TimeoutError:
            raise HttpProtocolException(
                "Timed out connecting to upstream proxy {0}:{1}".format(
                    *endpoint_tuple,
                ),
            )
        except ConnectionRefusedError:
            # TODO(abhinavsingh): Try another choice, when all (or max configured) choices have
            # exhausted, retry for configured number of times before giving up.
            #
            # Failing upstream proxies, must be removed from the pool temporarily.
            # A periodic health check must put them back in the pool.  This can be achieved
            # using a data structure without having to spawn separate thread/process for health
            # check.
            raise HttpProtocolException(
                "Connection refused by upstream proxy {0}:{1}".format(
                    *endpoint_tuple,
                ),
            )
        logger.debug(
            "Established connection to upstream proxy {0}:{1}".format(
                *endpoint_tuple,
            ),
        )
        return None

    def handle_client_request(
        self,
        request: HttpParser,
    ) -> Optional[HttpParser]:
        """Only invoked once after client original proxy request has been received completely."""
        if not self.upstream:
            return request
        assert self.upstream
        # For log sanity (i.e. to avoid None:None), expose upstream host:port from headers
        host, port = None, None
        # Browser or applications may sometime send
        #
        # "CONNECT / HTTP/1.0\r\n\r\n"
        #
        # for proxy keep alive checks.
        if request.has_header(b"host"):
            url = Url.from_bytes(request.header(b"host"))
            assert url.hostname
            host, port = url.hostname.decode("utf-8"), url.port
            port = port if port else (443 if request.is_https_tunnel else 80)
        path = None if not request.path else request.path.decode()
        self._metadata = [
            host,
            port,
            path,
            request.method,
        ]

        proxy = self._select_proxy(text_(host))
        logger.info(f"Selected proxy: {proxy} for {host}")
        # Queue original request optionally with auth headers to upstream proxy
        if proxy.has_credentials:
            assert proxy.username and proxy.password
            request.add_header(
                httpHeaders.PROXY_AUTHORIZATION,
                b"Basic "
                + base64.b64encode(
                    proxy.username + COLON + proxy.password,
                ),
            )

        # Rewrite host
        tld_regex = re.compile(r".(007|aachen|ffb|hhi|iais|iosb)$")
        if re.search(tld_regex, text_(host)):
            new_host = re.sub(
                tld_regex,
                ".svc.cluster.local",
                text_(host)
            ).encode("utf-8")
            logger.info(f"Rewriting host from {request.host} to {new_host}")
            request.host = new_host

            logger.info(f"Setting Host header to {new_host}")
            # Rewrite host header
            if request.has_header(b'Host'):
                request.del_header(b'Host')
            request.add_header(b"Host", new_host)

        self.upstream.queue(memoryview(request.build(for_proxy=True)))
        logging.info(f"Queued request to upstream proxy: {request.build(for_proxy=True)}")
        return request

    def handle_client_data(self, raw: memoryview) -> Optional[memoryview]:
        """Only invoked when before_upstream_connection returns None"""
        # Queue data to the proxy endpoint
        assert self.upstream
        self.upstream.queue(raw)
        return raw

    def handle_upstream_chunk(self, chunk: memoryview) -> Optional[memoryview]:
        """Will never be called since we didn't establish an upstream connection."""
        logger.info(f"Received chunk from upstream proxy: {chunk}")
        if not self.upstream:
            return chunk
        raise Exception("This should have never been called")

    def on_upstream_connection_close(self) -> None:
        """Called when client connection has been closed."""
        if self.upstream and not self.upstream.closed:
            logger.info(f"Closing upstream proxy connection: {self.upstream}")
            self.upstream.close()
            self.upstream = None

    def on_access_log(self, context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not self.upstream:
            return context
        addr, port = (
            (self.upstream.addr[0], self.upstream.addr[1])
            if self.upstream
            else (None, None)
        )
        context.update(
            {
                "upstream_proxy_host": addr,
                "upstream_proxy_port": port,
                "server_host": self._metadata[0],
                "server_port": self._metadata[1],
                "request_path": self._metadata[2],
                "response_bytes": self.total_size,
            }
        )
        self.access_log(context)
        return None

    def access_log(self, log_attrs: Dict[str, Any]) -> None:
        access_log_format = DEFAULT_HTTPS_ACCESS_LOG_FORMAT
        request_method = self._metadata[3]
        if request_method and request_method != httpMethods.CONNECT:
            access_log_format = DEFAULT_HTTP_ACCESS_LOG_FORMAT
        logger.info(access_log_format.format_map(log_attrs))

    def _select_proxy(self, host: Optional[str]) -> Url:
        """Choose a random proxy from the pool.

        TODO: Implement your own logic here e.g. round-robin, least connection etc.
        """
        proxy_default = 'localhost:1086'

        # proxies = {
        #     "oncite-00007": "localhost:1082",
        #     "ipt-aachen": "localhost:1083",
        #     "hhi-berlin-001": "localhost:1084",
        #     "iosb-ast-ilmenau": "localhost:1085",
        #     "ffb-001": "localhost:1086",
        #     "iais-001": "localhost:1087",
        # }
        proxies = {
            "oncite-00007": "172.69.42.2:1080",
            "ipt-aachen": "172.69.42.3:1080",
            "hhi-berlin-001": "172.69.42.4:1080",
            "iosb-ast-ilmenau": "172.69.42.5:1080",
            "ffb-001": "172.69.42.6:1080",
            "iais-001": "172.69.42.7:1080",
        }

        if not isinstance(host, str):
            host = host.decode("utf-8") if host else ""

        logger.info(f"Resolving proxy for host: {host}")

        if not host:
            proxy = proxy_default
        else:
            if host.endswith(".aachen"):
                proxy = proxies["ipt-aachen"]
            elif host.endswith(".hhi"):
                proxy = proxies["hhi-berlin-001"]
            elif host.endswith(".ffb"):
                proxy = proxies["ffb-001"]
            elif host.endswith(".iais"):
                proxy = proxies["iais-001"]
            elif host.endswith(".iosb"):
                proxy = proxies["iosb-ast-ilmenau"]
            else:
                proxy = proxies.get(host, proxy_default)

        logger.info(f"Result: {proxy}")
        return Url.from_bytes(
            proxy.encode("utf-8")
        )

    def resolve_dns(self, host: str, port: int) -> Tuple[Optional[str], Optional[HostPort]]:
        """Here we are using in-built python resolver for demonstration.

        Ideally you would like to query your custom DNS server or even
        use :term:`DoH` to make real sense out of this plugin.

        The second parameter returned is None.  Return a 2-tuple to
        configure underlying interface to use for connection to the
        upstream server.
        """
        try:
            logger.info(f"Resolving DNS for {host}:{port}")
            if host == "horizon.openstack.svc.cluster.local":
                return "100.64.148.129", None

            return socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)[0][4][0], None
        except socket.gaierror:
            # Ideally we can also thrown HttpRequestRejected or HttpProtocolException here
            # Returning None simply fallback to core generated exceptions.
            return None, None
