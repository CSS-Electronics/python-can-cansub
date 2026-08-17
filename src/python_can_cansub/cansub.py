import can
import contextlib
import copy
import ipaddress
import logging
import math
import queue
import requests
import selectors
import socket
import ssl
import struct
import sys
import threading
import warnings
from can import BusABC, LimitedDurationCyclicSendTaskABC, RestartableCyclicTaskABC
from datetime import datetime, timezone
from pathlib import Path
from python_can_cansub.cansub_protocol import cansub_protocol_decode, cansub_protocol_encode
from requests.adapters import HTTPAdapter
from time import monotonic, sleep
from typing import Any, Callable, cast, Optional, Sequence, Tuple, TypedDict, Union
from wsproto import ConnectionType, WSConnection, events
from wsproto.connection import ConnectionState
from zeroconf import InterfaceChoice, IPVersion, ServiceBrowser, ServiceListener, Zeroconf

CANSUB_ROOT_CERT: Path = Path(__file__).with_name("cansub_root_cert.crt")

logger = logging.getLogger("can.cansub")

class CanSubHwFilter(TypedDict):
    is_extended: bool
    is_range: bool
    f1: int
    f2: int

CanSubHwFilters = Sequence[CanSubHwFilter]

class _CanSubHTTPAdapter(HTTPAdapter):
    """
    HTTP adapter binding TLS to a fixed hostname, independent of the host in the request URL.

    The host in the request URL (the pre-resolved IP) is used only to establish the connection. With
    server_hostname None (connection by IP address), certificate hostname verification is disabled.
    Certificate chain verification is always active.
    """

    def __init__(self, server_hostname: Optional[str]):
        self._server_hostname = server_hostname
        super().__init__()

    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        """
        Hook called by HTTPAdapter.__init__ to create the urllib3 pool manager, which opens and reuses the
        underlying TCP/TLS connections. Keywords in pool_kwargs are applied to every connection it opens.

        By default, both SNI and certificate hostname verification use the host from the request URL. The
        two keywords below override this:

        - server_hostname: name sent in the TLS handshake (SNI)
        - assert_hostname: name the server certificate is verified against (False disables the check)
        """
        if self._server_hostname is None:
            pool_kwargs["assert_hostname"] = False
        else:
            pool_kwargs["server_hostname"] = self._server_hostname
            pool_kwargs["assert_hostname"] = self._server_hostname
        super().init_poolmanager(connections, maxsize, block, **pool_kwargs)

class _WakeupQueue(queue.Queue):
    """
    Queue that writes one byte to a wakeup socket when a put makes it non-empty.
    """

    def __init__(self, wakeup_sock: socket.socket, maxsize: int = 0):
        super().__init__(maxsize)
        self._wakeup_sock = wakeup_sock

    def _put(self, item: Any) -> None:
        # Queue holds its mutex across _put, so the emptiness test cannot race a get
        if not self._qsize():
            # Empty -> non-empty transition, signal the consumer.
            try:
                self._wakeup_sock.send(b"\x00")
            except OSError:
                pass
        super()._put(item)

class CanSub(can.BusABC):

    _supported_api_versions = ["04.00"]
    _can_f_clock = 80_000_000
    _can_default_sp = 80.0
    _net_timeout = 3.0

    # Placed in the receive queue when the I/O thread exits, waking recv calls blocked on the
    # queue. Compared by identity; never delivered to the user.
    _RECV_SENTINEL = can.Message()

    # Placed in the TX queue by shutdown(), marking the end of transmission: the I/O thread
    # sends the websocket close once it is reached - all previously accepted messages have then
    # been handed to the device (FIFO). Compared by identity; never sent to the device.
    _TX_CLOSE_SENTINEL = can.Message()

    # Unexpected I/O thread failure; set by the I/O thread, surfaced through send/recv
    _io_error: Optional[BaseException] = None

    def __init__(self,
                 channel: can.typechecking.Channel,
                 can_filters: Optional[can.typechecking.CanFilters] = None,
                 address: Optional[str] = None,
                 timing: Optional[Union[can.BitTiming, can.BitTimingFd]] = None,
                 bitrate: Optional[int] = None,
                 data_bitrate: Optional[int] = None,
                 listen_only: bool = False,
                 auto_reset: bool = True,
                 error_frames: bool = False,
                 receive_own_messages: bool = False,
                 max_device_time_skew: Optional[float] = 1.0,
                 shutdown_timeout: Optional[float] = 3.0,
                 client_cert: Optional[Tuple[Union[str, Path], Union[str, Path]]] = None,
                 **kwargs: object
                 ):
        """
        Python-can compatible interface over a websocket connection. Functions bus.send and bus.recv are made
        thread-safe by using queues.

        :param channel:
            The CAN channel to use. Can be an integer, a string, or a single-element integer
            sequence (can.typechecking.Channel). If a string contains '@', it can specify both
            the device address and the channel (e.g., 'aabbccdd-usb.local@1').

        :param can_filters:
            Optional hardware filters to apply.

        :param address:
            The hostname or IP address of the device. If not provided, it must be part of the `channel` string.
            The TLS server certificate is verified against the built-in CANsub root certificate. With an IP
            address, certificate hostname verification is disabled (chain verification remains active).

        :param timing:
            CAN-bus bit-timing. Takes precedence over bitrate and data_bitrate.

        :param bitrate:
            CAN-bus bit-rate.

        :param data_bitrate:
            CAN-bus data (FD) bit-rate. Optional: when not provided, the bus operates as classic CAN
            and transmission of FD messages is rejected.

        :param listen_only:
            CAN-bus listen-only mode. Enable to monitor a bus without transmitting or acknowledging frames.

        :param auto_reset:
            Automatic recovery from bus-off. Enable to automatically recover from bus-off.

        :param error_frames:
            CAN-bus error frame reporting. Enable to receive error frames.

        :param receive_own_messages:
            Enable to receive messages successfully transmitted by the device.
            Transmission acknowledgements have `is_rx` set to `False`.
            Disable to reduce the network-load.

        :param max_device_time_skew:
            On open, set the device clock to the host time (UTC) if the two differ by more than this many
            seconds. Default: 1.0, always set: 0.0, never set: None

        :param shutdown_timeout:
            On shutdown, time (seconds) to transmit queued messages.
            Default: 3.0, immediately discard: 0.0, never discard: None (waits indefinitely)

        :param client_cert:
            Tuple of paths to the client certificate (.crt file) and the unencrypted private key (.key file)
            (i.e. ('cert', 'key')). Password protection is not supported.
            Required when TLS mutual authentication is enabled.

        :param kwargs:
            Extra arguments passed to the parent `can.BusABC` class.

        """

        # Resources created anywhere in __init__ register their cleanup in _resources right
        # after their creation. On a failed initialization, the except clause at the end
        # releases everything registered so far; on success, shutdown() releases the
        # resources - both in reverse order of registration.
        self._resources = contextlib.ExitStack()
        try:

            # To be able to use python-can command line tool without custom arguments, support that channel can contain
            # both address and channel, format e.g.: aabbccdd-usb.local@1
            if isinstance(channel, str) and "@" in channel:
                address, channel = channel.split("@", 1)

            if address is None:
                raise can.exceptions.CanInitializationError("Address not provided")

            # Parse address and port. This interface is IPv4-only.
            # An IPv6 literal would parse ambiguously, so reject it explicitly.
            if address.count(":") > 1:
                raise can.exceptions.CanInitializationError(f"IPv6 addresses are not supported: {address}")
            if ":" in address:
                host, port_str = address.rsplit(":", 1)
                try:
                    port = int(port_str)
                except ValueError:
                    raise can.exceptions.CanInitializationError(f"Invalid port in address: {address}")
            else:
                host, port = address, 443

            # An IP address carries no name to verify the server certificate against:
            # hostname verification is then disabled (chain verification remains active)
            try:
                ipaddress.ip_address(host)
                tls_hostname = None
                logger.info("Address %s is an IP address: TLS hostname verification disabled", host)
            except ValueError:
                tls_hostname = host

            # Resolve the address to an IPv4 address once for speed (an IP address is passed through unchanged)
            try:
                start = monotonic()
                ip = socket.gethostbyname(host)
                elapsed = monotonic() - start
                logger.debug("Resolved %s to %s in %.3fs", host, ip, elapsed)
            except OSError as e:
                raise can.exceptions.CanInitializationError(f"Failed to resolve address {host} ({e})")

            # Store network details
            self.url = f"https://{ip}:{port}/api"
            self.ip, self.host, self.port, self.tls_hostname = ip, host, port, tls_hostname
            del host, port, ip, address, tls_hostname

            # Channel
            channel_int = None
            if isinstance(channel, can.typechecking.ChannelInt):
                channel_int = channel
            elif isinstance(channel, can.typechecking.ChannelStr):
                channel_int = can.util.channel2int(channel)
            elif isinstance(channel, Sequence) and len(channel) == 1 and isinstance(channel[0], can.typechecking.ChannelInt):
                channel_int = channel[0]
            if not isinstance(channel_int, can.typechecking.ChannelInt):
                raise can.exceptions.CanInitializationError("Invalid channel")
            self.channel = channel_int
            del channel, channel_int

            # Set channel info (required by python-can)
            self.channel_info = f"{self.host}@{self.channel}"

            # The server certificate is always verified against the CANsub root certificate
            self.root_cert = Path(CANSUB_ROOT_CERT)
            if not self.root_cert.is_file():
                raise can.exceptions.CanInitializationError(f"Root certificate not found: {self.root_cert}")

            # Client certificate (mTLS)
            self.client_cert = None
            if client_cert is not None:
                if not (isinstance(client_cert, (tuple, list)) and len(client_cert) == 2
                        and all(isinstance(p, (str, Path)) for p in client_cert)):
                    raise can.exceptions.CanInitializationError("Invalid client_cert")

                client_crt, client_key = Path(client_cert[0]), Path(client_cert[1])

                if not client_crt.is_file():
                    raise can.exceptions.CanInitializationError(f"Client certificate not found: {client_crt}")
                if client_crt.suffix.lower() != ".crt":
                    raise can.exceptions.CanInitializationError(f"Client certificate must be a .crt file: {client_crt}")
                if not client_key.is_file():
                    raise can.exceptions.CanInitializationError(f"Client key not found: {client_key}")
                if client_key.suffix.lower() != ".key":
                    raise can.exceptions.CanInitializationError(f"Client key must be a .key file: {client_key}")

                self.client_cert = (client_crt, client_key)
            del client_cert

            # Bitrate / bit-timing
            if isinstance(timing, can.BitTiming):
                # BitTiming (nominal bit-timing only): classic CAN
                self._can_protocol = can.CanProtocol.CAN_20
                timing = can.util.check_or_adjust_timing_clock(timing, valid_clocks=[self._can_f_clock])

                # Add missing data bit-timing values (device default data timing)
                self.timing = can.BitTimingFd(
                    f_clock=timing.f_clock,
                    nom_brp=timing.brp, nom_tseg1=timing.tseg1, nom_tseg2=timing.tseg2, nom_sjw=timing.sjw,
                    data_brp=4, data_tseg1=15, data_tseg2=4, data_sjw=4)

            elif isinstance(timing, can.BitTimingFd):
                # BitTimingFd (nominal bit-timing + data bit-timing)
                self._can_protocol = can.CanProtocol.CAN_FD
                self.timing = can.util.check_or_adjust_timing_clock(timing, valid_clocks=[self._can_f_clock])

            elif isinstance(bitrate, int) and not isinstance(data_bitrate, int):
                # Nominal bitrate only
                self._can_protocol = can.CanProtocol.CAN_20

                # Construct timing from nominal bitrate and dummy data bitrate
                self.timing = can.BitTimingFd.from_sample_point(
                    f_clock=self._can_f_clock,
                    nom_bitrate=bitrate, nom_sample_point=self._can_default_sp,
                    data_bitrate=1_000_000,
                    data_sample_point=self._can_default_sp)

            elif isinstance(bitrate, int) and isinstance(data_bitrate, int):
                # Nominal bitrate + data bitrate
                self._can_protocol = can.CanProtocol.CAN_FD

                # Construct timing from nominal bitrate and data bitrate
                self.timing = can.BitTimingFd.from_sample_point(
                    f_clock=self._can_f_clock,
                    nom_bitrate=bitrate,
                    nom_sample_point=self._can_default_sp,
                    data_bitrate=data_bitrate,
                    data_sample_point=self._can_default_sp)
            else:
                raise can.exceptions.CanInitializationError("Bitrate / bit-timing not provided")
            del timing, bitrate, data_bitrate

            # listen-only
            if not isinstance(listen_only, bool):
                raise can.exceptions.CanInitializationError("Invalid listen_only type")
            self.listen_only = listen_only
            del listen_only

            # auto-reset
            if not isinstance(auto_reset, bool):
                raise can.exceptions.CanInitializationError("Invalid auto_reset type")
            self.auto_reset = auto_reset
            del auto_reset

            # error_frames
            if not isinstance(error_frames, bool):
                raise can.exceptions.CanInitializationError("Invalid error_frames type")
            self.error_frames = error_frames
            del error_frames

            # receive_own_messages
            if not isinstance(receive_own_messages, bool):
                raise can.exceptions.CanInitializationError("Invalid receive_own_messages type")
            self.receive_own_messages = receive_own_messages
            del receive_own_messages

            # max_device_time_skew: None (never set the time), or a non-negative number of seconds.
            if max_device_time_skew is not None:
                if not isinstance(max_device_time_skew, (int, float)) or max_device_time_skew < 0:
                    raise can.exceptions.CanInitializationError("Invalid max_device_time_skew")

            # shutdown_timeout: None (wait indefinitely) is stored as inf, keeping the deadline
            # arithmetic uniform - and making the validation a plain non-negative number check
            shutdown_timeout = math.inf if shutdown_timeout is None else shutdown_timeout
            if not isinstance(shutdown_timeout, (int, float)) or shutdown_timeout < 0:
                raise can.exceptions.CanInitializationError("Invalid shutdown_timeout")
            self.shutdown_timeout = shutdown_timeout
            del shutdown_timeout

            # Perform REST interaction with the device in a persistent session, always using the pre-resolved IP.
            # NOTE: The session is used from multiple threads (e.g. the state property and cyclic send tasks). This is
            # safe as long as the session is only configured once.
            self._session = requests.Session()
            self._session.mount("https://", _CanSubHTTPAdapter(server_hostname=self.tls_hostname))
            self._session.headers["Host"] = self.host if self.port == 443 else f"{self.host}:{self.port}"
            self._session.verify = str(self.root_cert)
            self._session.cert = (str(self.client_cert[0]), str(self.client_cert[1])) if self.client_cert else None
            self._resources.callback(self._session.close)

            # Get api version (and test connection)
            self.api_version = self._api_request("GET", "/version", "Connection failed",
                                                 error_type=can.exceptions.CanInitializationError)
            if not (isinstance(self.api_version, str) and self.api_version in self._supported_api_versions):
                raise can.exceptions.CanInitializationError(f"API version not supported ({self.api_version})")

            # Get state of the channel
            channel_state = self._api_request("GET", f"/can/{self.channel}", "Failed to get channel state",
                                              error_type=can.exceptions.CanInitializationError)

            state = channel_state.get("state") if isinstance(channel_state, dict) else None
            if state != "stopped":
                raise can.exceptions.CanInitializationError(f"Channel cannot be opened (state: {state})")

            # Set device time to the current host time (UTC), subject to max_device_time_skew
            if max_device_time_skew is not None:

                set_time = True

                # Positive limit: read the device clock and set only if off by more than the limit
                # (0.0 always sets, skipping the round-trip)
                if max_device_time_skew > 0:
                    time_json = self._api_request("GET", "/time", "Failed to get device time",
                                                  error_type=can.exceptions.CanInitializationError)
                    try:
                        device_time = datetime.fromisoformat(time_json.replace("Z", "+00:00"))
                    except Exception as e:
                        raise can.exceptions.CanInitializationError(f"Failed to get device time ({e})")

                    skew = abs((datetime.now(timezone.utc) - device_time).total_seconds())
                    set_time = skew > max_device_time_skew

                if set_time:
                    time_string = datetime.now(timezone.utc).isoformat(timespec="milliseconds")[:-6] + "Z"
                    self._api_request("PUT", "/time", "Failed to set device time", json=time_string,
                                      error_type=can.exceptions.CanInitializationError)

            # Ensure that no hardware filters are set before the channel is opened
            # (Ensures that no messages get through until provided filters are set)
            self.set_hw_filters(None)

            # Ensure that no transmit-sequences are configured before the channel is opened
            transmit_ids = self._api_request("GET", f"/can/{self.channel}/transmit",
                                             "Failed to clear transmit sequences",
                                             error_type=can.exceptions.CanInitializationError)
            if not isinstance(transmit_ids, list):
                raise can.exceptions.CanInitializationError(
                    "Failed to clear transmit sequences (invalid transmit sequence list)")
            for transmit_id in transmit_ids:
                self._api_request("DELETE", f"/can/{self.channel}/transmit/{transmit_id}",
                                  "Failed to clear transmit sequences",
                                  error_type=can.exceptions.CanInitializationError)

            # Set channel configuration
            phy_config = {
                "listen_only": self.listen_only,
                "auto_reset": self.auto_reset,
                "error_frames": self.error_frames,
                "tx_ack_frames": self.receive_own_messages,
                "timing": {
                    "brp": self.timing.nom_brp,
                    "seg1": self.timing.nom_tseg1,
                    "seg2": self.timing.nom_tseg2,
                    "sjw": self.timing.nom_sjw
                },
                "timing_data": {
                    "brp": self.timing.data_brp,
                    "seg1": self.timing.data_tseg1,
                    "seg2": self.timing.data_tseg2,
                    "sjw": self.timing.data_sjw
                }
            }
            self._api_request("PUT", f"/can/{self.channel}/phy", "Failed to configure channel",
                              json=phy_config, error_type=can.exceptions.CanInitializationError)

            # Create a socket to be used as the underlying transport for the websocket.
            ssl_context = ssl.create_default_context(cafile=self.root_cert)
            if self.tls_hostname is None:
                ssl_context.check_hostname = False

            if self.client_cert:
                ssl_context.load_cert_chain(certfile=self.client_cert[0], keyfile=self.client_cert[1])

            # Wrap the TCP socket in TLS. The handshake uses tls_hostname (SNI / certificate
            # hostname verification) while the connection itself uses the pre-resolved IP (below)
            self._ws_sock = ssl_context.wrap_socket(sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM),
                                                   server_hostname=self.tls_hostname)
            # NOTE: Once the I/O thread runs, the thread closes the socket itself (it is stopped
            # first on a failure, see below) - this direct close then becomes a harmless no-op
            self._resources.callback(self._ws_sock.close)

            # Set timeout, and disable Nagles algorithm (lower latency for small writes)
            self._ws_sock.settimeout(self._net_timeout)
            self._ws_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

            # Enable TCP keepalive to detect a lost connection (e.g. unplugged cable)
            self._ws_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            if hasattr(socket, "TCP_KEEPIDLE"):
                # Idle time before probing, probe interval (seconds), and failed probes until
                # the connection is declared dead: detects a loss within ~4 s
                self._ws_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 1)
                self._ws_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 1)
                self._ws_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
            elif hasattr(socket, "SIO_KEEPALIVE_VALS"):
                # Windows: (on, idle ms, interval ms); the probe count is fixed at 10, so a
                # loss is detected within ~11 s
                self._ws_sock.ioctl(socket.SIO_KEEPALIVE_VALS, (1, 1000, 1000))

            # Bound the OS send buffer (platforms may scale the requested value):
            # TX back-pressure then surfaces in the bounded user-space queue instead of
            # megabytes of invisible OS buffering,
            # and a close is not buried behind a frame backlog - while staying far above the
            # bandwidth-delay product of the link, so throughput is unaffected
            self._ws_sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 16 * 1024)

            # Connect to the device using the pre-resolved IP
            try:
                self._ws_sock.connect((self.ip, self.port))
            except Exception as e:
                raise can.exceptions.CanInitializationError(f"Connection failed ({e})")

            # Websocket protocol state machine. Unlike a full websocket client library, wsproto
            # never reads or writes the socket itself: it only translates between websocket
            # events and the bytes to put on / taken from the wire - the socket stays ours.
            # The select() based I/O loop, the TX back-pressure design, and the close sequence
            # all depend on this full control of the socket.
            self._ws_client = WSConnection(ConnectionType.CLIENT)

            # Upgrade to websocket (the default port is omitted from the Host header).
            request = self._ws_client.send(events.Request(
                host=self.host if self.port == 443 else f"{self.host}:{self.port}",
                target=f"/api/can/{self.channel}/ws"))
            try:
                self._ws_sock.sendall(request)
            except (OSError, ssl.SSLError) as e:
                raise can.exceptions.CanInitializationError(f"Upgrade failed ({e})")

            # Wait for the upgrade confirmation; each read is bounded by the socket timeout, and
            # a timeout is a failure (like everywhere else). The loop ends when the device
            # accepts (OPEN) or rejects (REJECTING) the upgrade.
            try:
                while self._ws_client.state == ConnectionState.CONNECTING:
                    # Record-sized reads (TLS records carry at most 16 KiB): a partial read
                    # would strand the rest of the record in the TLS buffer, invisible to the
                    # I/O loop's select()
                    ws_data = self._ws_sock.recv(17 * 1024)
                    if not ws_data:
                        raise ConnectionResetError("connection closed by device")
                    self._ws_client.receive_data(ws_data)
            except Exception as e:
                raise can.exceptions.CanInitializationError(f"Upgrade failed ({e})")

            if self._ws_client.state != ConnectionState.OPEN:
                raise can.exceptions.CanInitializationError("Upgrade failed (rejected by device)")

            # The objects below are shared with the user thread (send/recv/shutdown), so they
            # must exist before the I/O thread is started.

            # I/O thread wakeup signal. The I/O thread blocks in select(), which cannot wait on a queue.
            self._io_wakeup_watch, self._io_wakeup_notify = socket.socketpair()
            if self._io_wakeup_notify.family == socket.AF_INET:
                # Windows: socketpair() is emulated with a loopback TCP connection; disable
                # Nagle such that a wakeup byte is not held back until the previous one is
                # acknowledged (tens of ms with delayed ACK)
                self._io_wakeup_notify.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self._io_wakeup_watch.setblocking(False)
            self._io_wakeup_notify.setblocking(False)
            self._resources.callback(self._io_wakeup_watch.close)
            self._resources.callback(self._io_wakeup_notify.close)

            # Queue from websocket to python-can.recv. Unbounded, a consumer slower than the bus grows memory rather
            # than dropping frames (python-can convention)
            self._can_recv_queue: queue.Queue[can.Message] = queue.Queue()

            # Queue from python-can.send to websocket. Bounded such that a slow bus results in back-pressure in send
            # (blocking / queue.Full) rather than unbounded memory growth. Uses socket (pair) for signaling.
            self._can_send_queue: queue.Queue[can.Message] = _WakeupQueue(self._io_wakeup_notify, maxsize=1024)

            # Set when the I/O loop should (force) close or has closed
            self._close_event = threading.Event()

            # Daemon thread: lets the Python process exit even if the user never calls shutdown()
            self._io_thread = threading.Thread(target=self._io_loop, daemon=True)
            self._io_thread.start()
            # The thread stop signal is registered as a resource: released first (reverse order),
            # it ensures the thread has exited before the sockets it uses are closed
            def stop_io_thread() -> None:
                self._close_event.set()
                try:
                    self._io_wakeup_notify.send(b"\x00")
                except OSError:
                    pass
                self._io_thread.join()
            self._resources.callback(stop_io_thread)

            # Initialize the parent class. Called last, per python-can convention: BusABC.__init__ flips
            # _is_shutdown to False, signaling that the constructor as a whole succeeded (enables cleanup).
            # NOTE: This calls _apply_filters, installing the requested acceptance filters on the device.
            # All acceptance filters were removed above, so the device passes no frames until this point -
            # frames only start flowing once the bus is fully operational.
            super().__init__(channel=self.channel, can_filters=can_filters, **kwargs)

        except BaseException:
            # Initialization failed: release everything registered so far, then re-raise
            # (python-can performs no cleanup of a partially constructed bus)
            self._resources.close()
            raise

    def _io_loop(self):
        """
        The I/O thread: services the websocket connection in both directions, from after the upgrade until the
        connection ends. It owns the socket and the websocket state machine.

        IO loop:
            1. Wait (select) until there is work. Three wakeup sources:
                1.1 The socket has data to read
                1.2 The socket can accept more data (watched only while sending has stalled)
                1.3 The wakeup pipe announces new queued work: the TX queue writes a byte when a put
                makes it non-empty, shutdown() when stopping (select cannot wait on a queue).
            2. Read all available data from the socket into the websocket state machine.
            3. Process the websocket events: decode data frames into the RX queue (recv), and
            handle the close confirmation from the device.
            4. Service TX: batch messages from the TX queue (send) into websocket frames, staged
            and written to the socket one ws frame at a time. The end-of-transmission marker (shutdown()) sends the
            websocket close frame instead.

        Termination:
            - The device confirms the websocket close (the graceful end)
            - The connection ends (EOF): a connection loss without websocket close confirmation
            - The close event is set externally (forced stop, no close handshake)
            - On an error

        Back-pressure: at most one ws frame is staged beyond the bounded TX queue, ensuring back-pressure on send()

        TLS:
            select() watches the encrypted stream while recv() returns decrypted application data.
            This mismatch gives two rules:
            - Rule 1: Never block on the socket. Readable encrypted bytes may decrypt to zero application
              bytes (e.g. TLS handshake records) - recv() then raises SSLWantReadError: return to select().
            - Rule 2: Once select() fires, read until SSLWantReadError. The TLS library consumes whole
              records from the socket, so decrypted data can wait in its buffer, invisible to select().
        """

        # The thread loop requires the ws socket non-blocking
        self._ws_sock.setblocking(False)

        # Selector including the ws socket and the wakeup pipe
        sel = selectors.DefaultSelector()
        sel.register(self._ws_sock, selectors.EVENT_READ)
        sel.register(self._io_wakeup_watch, selectors.EVENT_READ)

        # Encoded-but-unsent websocket bytes (TX) and protocol decode buffer (RX)
        tx_data = bytearray()
        rx_data = bytearray()

        # Deliver a decoded message to recv() (callback for the protocol decoder).
        def msg_cb(msg_in: can.Message):
            msg_in.channel = self.channel
            self._can_recv_queue.put(msg_in)

        try:
            # Prime the first lap: websocket events already parsed during the upgrade are
            # invisible to select(), so make the first select() return immediately
            self._io_wakeup_notify.send(b"\x00")

            while not self._close_event.is_set():

                # Wait for events on the ws socket and the wakeup pipe
                for key, event_mask in sel.select():

                    # Wakeup pipe event
                    if key.fileobj is self._io_wakeup_watch:
                        # Drain wakeup bytes; their only purpose is to unblock select()
                        try:
                            self._io_wakeup_watch.recv(4096)
                        except BlockingIOError:
                            pass

                    # Websocket socket event
                    elif key.fileobj is self._ws_sock:

                        # Readable event
                        if event_mask & selectors.EVENT_READ:

                            # Drain all available application data
                            while True:
                                try:
                                    ws_data = self._ws_sock.recv(2048)
                                except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                                    # No application data - or TLS briefly needs the send
                                    # direction first (required when using TLS)
                                    break

                                if not ws_data:
                                    # Connection ended by the device: exit at the end of this
                                    # lap, once the final events are processed
                                    self._close_event.set()
                                    break

                                # Parse websocket data (the resulting events are processed below)
                                self._ws_client.receive_data(ws_data)

                        # Writeable event
                        if event_mask & selectors.EVENT_WRITE:
                            # Free space now available (used below)
                            pass

                # Process parsed websocket events
                for event in self._ws_client.events():

                    # Data frame: append to the decode buffer and decode all complete messages
                    if isinstance(event, events.BytesMessage):
                        rx_data.extend(event.data)
                        cansub_protocol_decode(rx_data, msg_cb)

                    # Close frame: the device confirming our close - the handshake is complete
                    # and the loop ends. The device never initiates a close of its own, so a
                    # close arriving while OPEN is a fault
                    elif isinstance(event, events.CloseConnection):
                        if self._ws_client.state == ConnectionState.REMOTE_CLOSING:
                            raise can.exceptions.CanOperationError(
                                "Device unexpectedly initiated a websocket close")
                        self._close_event.set()

                # Service TX: stage one websocket frame at a time and send it to the socket
                while True:

                    # Stage the next frame once the previous one is fully sent
                    if not tx_data:

                        # Stage only while the websocket is open
                        if self._ws_client.state != ConnectionState.OPEN:
                            break

                        # Batch queued messages into one websocket frame, up to the end-of-
                        # transmission marker (see shutdown())
                        batch = bytearray()
                        closing = False
                        while len(batch) < 1200:
                            try:
                                # Fetch from the can send queue. Can contain a can.Message or the _TX_CLOSE_SENTINEL
                                msg = self._can_send_queue.get_nowait()
                            except queue.Empty:
                                break
                            if msg is self._TX_CLOSE_SENTINEL:
                                # Marks the end of the transmission queue
                                closing = True
                                break
                            cansub_protocol_encode(msg, batch)

                        if batch:
                            tx_data[:] = self._ws_client.send(events.BytesMessage(batch))
                        if closing:
                            # End of transmission: append the websocket close frame (code 1000,
                            # "normal closure"). The device transmits all messages received
                            # before it, closes the bus, confirms with its own close frame, and
                            # closes the connection
                            tx_data.extend(self._ws_client.send(events.CloseConnection(code=1000)))

                        # Nothing (more) to send?
                        if not tx_data:
                            break

                    # Send as much as the socket accepts
                    try:
                        sent = self._ws_sock.send(tx_data)
                        del tx_data[:sent]
                    except (ssl.SSLWantWriteError, ssl.SSLWantReadError):
                        # Socket cannot take more right now; the write-readiness watch (below)
                        # resumes the flush
                        break

                # Enable EVENT_WRITE (write-readiness) event only when TX data is pending
                # (unblocks select when more data can be sent)
                ws_sock_events = selectors.EVENT_READ | (selectors.EVENT_WRITE if tx_data else 0)
                if sel.get_key(self._ws_sock).events != ws_sock_events:
                    sel.modify(self._ws_sock, ws_sock_events)

        except BaseException as e:
            # Record and log unexpected failures; send/recv report the stored cause
            self._io_error = e
            logger.exception("I/O thread failed")
        finally:

            # Ensure close is set
            self._close_event.set()

            # Drain the send queue: releases senders blocked on a full queue.
            try:
                while True:
                    self._can_send_queue.get_nowait()
            except queue.Empty:
                pass

            # Check how the connection closed. The nested finally guarantees the sentinel is
            # delivered on every exit from this block
            try:
                # Close the selector
                sel.close()

                # Graceful only when the ws close handshake completed
                if self._ws_client.state == ConnectionState.CLOSED:
                    logger.debug("Connection to channel %s closed gracefully", self.channel)
                else:
                    # A close without ws close handshake completed
                    close_error_msg = f"Connection to channel {self.channel} closed with error"
                    logger.warning(close_error_msg)

                    # If no io error set, set one
                    if self._io_error is None:
                        self._io_error = can.exceptions.CanOperationError(close_error_msg)

                    # Request an abort on close (RST): l_onoff=1, l_linger=0
                    if sys.platform == "win32":
                        linger = struct.pack("HH", 1, 0)  # Winsock linger is two u_shorts
                    else:
                        linger = struct.pack("ii", 1, 0)  # POSIX linger is two ints
                    try:
                        self._ws_sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, linger)
                    except OSError:
                        # Socket already dead; close() below releases the resources
                        pass

                # Close socket and release resources (sends the RST if linger-0 was set)
                try:
                    self._ws_sock.close()
                except OSError:
                    pass
            finally:
                # Wake receivers blocked on recv()
                self._can_recv_queue.put(self._RECV_SENTINEL)

    def shutdown(self):

        # Already shut down?
        if self._is_shutdown:
            return

        # Invoke super().shutdown() first: it flips _is_shutdown (send() rejects new messages
        # from here) and stops the periodic tasks, which needs the still-open session
        try:
            super().shutdown()
        except Exception as e:
            logger.warning("Shutdown failed on channel %s (%s)", self.channel, e)

        # Configure escalation timers:
        # 1. Ask the device to discard the queued messages if it cannot transmit them within shutdown_timeout
        # 2. Force close by setting _close_event
        timers = []
        if self.shutdown_timeout != math.inf:

            # 1. After shutdown_timeout, ask the device to discard the messages queued on it
            def ws_delete() -> None:
                logger.warning("Requesting discard of queued messages on channel %s (DELETE)", self.channel)
                try:
                    self._session.delete(f"{self.url}/can/{self.channel}/ws", timeout=self._net_timeout)
                except requests.RequestException as err:
                    logger.warning("Discard request failed on channel %s (%s)", self.channel, err)
            timers.append(threading.Timer(self.shutdown_timeout, ws_delete))

            # 2. Five seconds after the discard request, force the I/O loop to exit
            # (the join below is the wait)
            def force_close() -> None:
                self._close_event.set()
                try:
                    self._io_wakeup_notify.send(b"\x00")
                except OSError:
                    pass
            timers.append(threading.Timer(self.shutdown_timeout + 5.0, force_close))

        # Add end-of-transmission marker to the end of the send queue.
        try:
            # Start the shutdown escalation timers (inside the try to ensure they are cancelled on error)
            for timer in timers:
                timer.start()

            # Try to place end-of-transmission marker in queue
            # Note: if the queue is full, it will likely clear once ws delete triggers
            while not self._close_event.is_set():
                try:
                    self._can_send_queue.put(self._TX_CLOSE_SENTINEL, timeout=0.5)
                    break
                except queue.Full:
                    pass

            # Wait for the I/O thread to exit (bounded by the force-close timer; unbounded
            # for shutdown_timeout None - never discard)
            self._io_thread.join()
        finally:
            for timer in timers:
                timer.cancel()

            # Release the registered resources (in reverse order of registration)
            self._resources.close()

    def _api_request(self, method: str, path: str, error_msg: str, json=None,
                     error_type: type = can.exceptions.CanOperationError) -> Any:
        """
        Perform a device REST API request (path relative to the API root), raising error_type on
        any failure: transport error, non-2xx status, or an unparsable body.

        Returns the parsed JSON response body, or None when the response has no body (the device
        API returns JSON or nothing).
        """
        try:
            response = self._session.request(method, f"{self.url}{path}", json=json,
                                            timeout=self._net_timeout)
            response.raise_for_status()
            return response.json() if response.content else None
        except Exception as e:
            raise error_type(f"{error_msg} ({e})")

    def send(self, msg: can.Message, timeout: Optional[float] = None):
        """
        See "send" in can.BusABC. Note, waits for a slot in the queue to be available (not for messages to be ACK'ed).

        The message is enqueued as a copy: the caller may mutate/reuse the message object as soon
        as this method returns.

        :raises can.exceptions.CanOperationError:
            If the bus is not operational (shut down, or the connection to the device is lost),
            the timeout is invalid, or the message is an FD message on a classic CAN bus.
        :raises can.exceptions.CanTimeoutError:
            If no TX queue space became available within the timeout (backpressure).
        """

        # Rejected after shutdown (_is_shutdown) and once the I/O thread has stopped
        # (error or connection loss)
        if self._is_shutdown or self._close_event.is_set():
            raise can.exceptions.CanOperationError(
                f"Bus is not operational ({self._io_error or 'shut down or connection lost'})")

        if timeout is not None and timeout < 0:
            raise can.exceptions.CanOperationError("Invalid timeout value")

        if msg.is_fd and self._can_protocol == can.CanProtocol.CAN_20:
            raise can.exceptions.CanOperationError(
                "Cannot send FD message on a classic CAN bus (no data_bitrate / FD bit-timing configured)")

        # Enqueue a private copy
        # NOTE: The explicit payload copy is essential - Message.__copy__ (and __init__) store a
        # passed bytearray by reference, so copy.copy alone would still share the payload buffer.
        # (copy.deepcopy would copy it, but is ~4x slower on this per-frame path.)
        msg_copy = copy.copy(msg)
        msg_copy.data = bytearray(msg.data or b"")
        msg = msg_copy

        try:
            if timeout is None:
                # Wait indefinitely for queue space
                self._can_send_queue.put(msg, block=True, timeout=None)
            elif timeout == 0:
                # Return immediately
                self._can_send_queue.put(msg, block=False)
            else:
                # Wait for timeout seconds for queue space
                self._can_send_queue.put(msg, block=True, timeout=timeout)
        except queue.Full:
            raise can.exceptions.CanTimeoutError("Send queue full")

    def _recv_internal(self, timeout: Optional[float] = None) -> Tuple[Optional[can.Message], bool]:
        """
        See "recv" and "_recv_internal" in can.BusABC

        Always return that the message has already been filtered.
        """
        if timeout is not None and timeout < 0:
            raise can.exceptions.CanOperationError("Invalid timeout value")

        start_time = monotonic()
        msg = None
        try:
            if timeout is None:
                # Wait indefinitely
                msg = self._can_recv_queue.get(block=True, timeout=None)
            elif timeout == 0:
                # Return immediately
                msg = self._can_recv_queue.get(block=False)
            else:
                # Wait for timeout seconds
                msg = self._can_recv_queue.get(block=True, timeout=timeout)
        except queue.Empty:
            # Queue empty. Surface an I/O failure; a normally closed bus keeps returning None
            if self._io_error is not None:
                raise can.exceptions.CanOperationError(f"Bus is not operational ({self._io_error})")

        if msg is self._RECV_SENTINEL:
            # The I/O thread has exited. Re-insert the sentinel to wake other blocked receivers.
            self._can_recv_queue.put(self._RECV_SENTINEL)

            if self._io_error is not None:
                raise can.exceptions.CanOperationError(f"Bus is not operational ({self._io_error})")

            if timeout is None:
                # None cannot wake a recv without timeout (python-can retries indefinitely on
                # None), so raising is the only way to unblock the caller
                raise can.exceptions.CanOperationError("Bus is not operational (shut down or connection lost)")

            # Bounded timeout on a normally closed bus: behave like a silent bus - wait out the
            # remaining timeout and report no message
            remaining = timeout - (monotonic() - start_time)
            if remaining > 0:
                sleep(remaining)
            msg = None

        return msg, True

    @property
    def state(self) -> can.BusState:
        """
        Return the current state of the hardware
        """

        # Rejected after shutdown, like send()
        if self._is_shutdown:
            raise can.exceptions.CanOperationError("Bus is not operational (shut down)")

        # Get channel state
        response_dict = self._api_request("GET", f"/can/{self.channel}",
                                          f"Failed to get state of channel {self.channel}")

        # Parse response
        response_state = response_dict.get("state") if isinstance(response_dict, dict) else None
        if response_state is None:
            raise can.exceptions.CanOperationError(f"Failed to get state of channel {self.channel}")

        if response_state in ("error_active", "error_warning"):
            state = can.BusState.ACTIVE
        elif response_state == "error_passive":
            state = can.BusState.PASSIVE
        elif response_state == "bus_off":
            state = can.BusState.ERROR
        elif response_state == "stopped":
            # Not a python-can BusState: the channel is not running (bus closed, or the device
            # stopped the channel after a connection loss)
            raise can.exceptions.CanOperationError(f"Channel {self.channel} is stopped")
        else:
            raise can.exceptions.CanOperationError(f"Unknown channel state {response_state}")
        return state

    @state.setter
    def state(self, new_state: can.BusState) -> None:
        # Overriding the getter replaces the whole BusABC property: without this setter,
        # assignment (e.g. can_logger --active) would raise AttributeError instead of the
        # NotImplementedError that python-can specifies
        raise NotImplementedError("Setting the CANsub bus state is not supported")

    @property
    def session(self) -> requests.Session:
        """
        Return the requests session used for the REST interaction with the device.

        The session can be used for custom API calls. It is read-only. The session is shared across threads and must
        not be replaced or reconfigured.
        """
        return self._session

    def flush_tx_buffer(self):
        """
        Discard all messages waiting in the send queue.

        NOTE: Messages already delivered (or being delivered) to the device are not discarded.
        """
        # Drain item by item: each get also releases send() calls blocked on a full queue
        closing = False
        try:
            while True:
                if self._can_send_queue.get_nowait() is self._TX_CLOSE_SENTINEL:
                    closing = True
        except queue.Empty:
            pass

        # Preserve an in-progress shutdown: re-add the end-of-transmission marker
        if closing:
            self._can_send_queue.put(self._TX_CLOSE_SENTINEL)

    def _apply_filters(self, filters: Optional[can.typechecking.CanFilters]) -> None:

        # Python-can specify that all messages should be accepted if filters are None or empty list
        if filters is None or len(filters) == 0:
            filters = [can.typechecking.CanFilter(can_id=0, can_mask=0)]  # Accept all messages

        # Change to CanSubHwFilter type. A filter without the "extended" field matches both
        # standard and extended ids (python-can semantics, also used by the command line tools):
        # it becomes two device filters, one per id type.
        can_hw_filters = []
        for can_filter in filters:
            for is_extended in ([can_filter["extended"]] if "extended" in can_filter else [False, True]):
                can_hw_filters.append(CanSubHwFilter(is_extended=is_extended,
                                                     is_range=False,
                                                     f1=can_filter["can_id"],
                                                     f2=can_filter["can_mask"]))

        # Apply hardware filter
        self.set_hw_filters(can_hw_filters)

    def set_hw_filters(self, can_hw_filters: Optional[CanSubHwFilters]) -> None:
        """
        Sets device hardware filters

        NOTE: Contrary to the set_filters method, this method does not set any filters if can_hw_filters is None or empty.

        NOTE: The filters are replaced by deleting the existing ones before creating the new ones.
        The device passes no frames while no filters are installed, so frames arriving in the
        transition window are dropped.
        """

        # Failures are initialization errors while the bus is being constructed (_is_shutdown flips
        # once __init__ succeeds) and operation errors afterwards (e.g. set_filters at runtime)
        error_type = (can.exceptions.CanInitializationError if self._is_shutdown
                      else can.exceptions.CanOperationError)

        # Get existing filters for channel
        filter_ids = self._api_request("GET", f"/can/{self.channel}/filter",
                                       "Failed to get existing filters",
                                       error_type=error_type)
        if not isinstance(filter_ids, list):
            raise error_type("Invalid filter list response")

        # Any existing filters?
        if len(filter_ids) > 0:

            # Yes, delete filters one by one
            for filter_id in filter_ids:
                self._api_request("DELETE", f"/can/{self.channel}/filter/{filter_id}",
                                  "Failed to delete existing filter", error_type=error_type)

            # Confirm all filters deleted
            remaining_filter_ids = self._api_request("GET", f"/can/{self.channel}/filter",
                                                     "Failed to get existing filters",
                                                     error_type=error_type)
            if not isinstance(remaining_filter_ids, list):
                raise error_type("Invalid filter list response")

            if len(remaining_filter_ids) > 0:
                raise error_type("Failed to delete all existing filters")

        # Any new filters provide?
        if can_hw_filters is None or len(can_hw_filters) == 0:
            # No, nothing to do
            return

        # Create new filters
        for hw_filter in can_hw_filters:

            if not isinstance(hw_filter, dict):
                raise error_type("Invalid filter type")

            self._api_request("POST", f"/can/{self.channel}/filter", "Failed to create new filter",
                              json=hw_filter, error_type=error_type)

        # Confirm all filters created
        new_filter_ids = self._api_request("GET", f"/can/{self.channel}/filter",
                                           "Failed to get new filters",
                                           error_type=error_type)
        if not isinstance(new_filter_ids, list):
            raise error_type("Invalid filter list response")

        if len(new_filter_ids) != len(can_hw_filters):
            raise error_type("Failed to create new filters")

    def _send_periodic_internal(
            self,
            msgs: Union[Sequence[can.Message], can.Message],
            period: float,
            duration: Optional[float] = None,
            autostart: bool = True,
            modifier_callback: Optional[Callable[[can.Message], None]] = None,
    ) -> can.broadcastmanager.CyclicSendTaskABC:

        messages = [msgs] if isinstance(msgs, can.Message) else msgs
        if self._can_protocol == can.CanProtocol.CAN_20 and any(m.is_fd for m in messages):
            raise can.exceptions.CanOperationError(
                "Cannot send FD messages on a classic CAN bus (no data_bitrate / FD bit-timing configured)")

        if modifier_callback is None:
            return CyclicSendTask(session=self._session,
                                  transmit_api_url=f"{self.url}/can/{self.channel}/transmit",
                                  net_timeout=self._net_timeout,
                                  messages=msgs, period=period, duration=duration, autostart=autostart)
        else:
            # modifier_callback not supported by hw, fallback to thread-based cyclic task
            warnings.warn(
                f"{self.__class__.__name__} falls back to a thread-based cyclic task, "
                "when the `modifier_callback` argument is given.",
                stacklevel=3,
            )
            return BusABC._send_periodic_internal(
                self,
                msgs=msgs,
                period=period,
                duration=duration,
                autostart=autostart,
                modifier_callback=modifier_callback,
            )

    @staticmethod
    def _detect_available_configs() -> Sequence[can.typechecking.AutoDetectedConfig]:
        return CanSub.mdns_discover(interfaces=InterfaceChoice.All)

    @staticmethod
    def mdns_discover(interfaces: Union[Sequence[str], InterfaceChoice] = InterfaceChoice.All,
                      discovery_time: float = 2.0) -> Sequence[can.typechecking.AutoDetectedConfig]:
        """Discover available CANsub devices by performing a mDNS lookup.

        :param interfaces: The interfaces to listen on. These must be either interface addresses
            or one of the zeroconf InterfaceChoice enum values.
        :param discovery_time: Time (seconds) to listen for mDNS responses.
        :return: A sequence of auto-detected CANbus configurations.
        """
        # Collect DNS-SD service info objects keyed by service name.
        # The device firmware advertises _cansub._tcp with TXT records:
        #   api=<version>   - must match _supported_api_versions
        #   channels=<n>    - number of CAN channels (channels are numbered 1..n)
        # The SRV hostname encodes the serial number and connection type,
        # e.g. 1b5b9343-usb.local (USB) or 1b5b9343-eth.local (Ethernet).
        discovered = {}

        class _Listener(ServiceListener):
            def add_service(self, zconf, type_, name):
                service_info = zconf.get_service_info(type_, name)
                if service_info:
                    discovered[name] = service_info
            def remove_service(self, zconf, type_, name): pass
            def update_service(self, zconf, type_, name): pass

        # Listen on all specified interfaces.
        zc = Zeroconf(interfaces=interfaces, ip_version=IPVersion.V4Only, use_asyncio=False)
        try:
            ServiceBrowser(zc, "_cansub._tcp.local.", _Listener())
            sleep(discovery_time)
        finally:
            zc.close()

        configs = []
        for info in discovered.values():
            # The SRV hostname is required to build the channel string (zeroconf types it Optional)
            if not info.server:
                continue

            # TXT record keys/values arrive as bytes; decode to str for easy lookup.
            txt = {
                (k.decode() if isinstance(k, bytes) else k):
                (v.decode() if isinstance(v, bytes) else v)
                for k, v in info.properties.items()
            }

            # Skip devices running an unsupported API version.
            api_version = txt.get("api")
            if api_version not in CanSub._supported_api_versions:
                warnings.warn(
                    f"Detected CANsub device {info.server.rstrip('.')} has an unsupported API version ({api_version}). "
                    f"Supported versions: [{', '.join(CanSub._supported_api_versions)}]",
                    UserWarning
                )
                continue

            # info.server has a trailing dot (DNS convention); strip it.
            hostname = info.server.rstrip(".")

            try:
                num_channels = int(txt.get("channels", 1))
            except (TypeError, ValueError):
                # Missing, empty (None), or non-numeric TXT value
                num_channels = 1

            # Channel is encoded in the address string understood by __init__,
            # e.g. "1b5b9343-usb.local@1". Channels are 1-based.
            for channel in range(1, num_channels + 1):
                configs.append({"interface": "cansub", "channel": f"{hostname}@{channel}"})

        return configs

class CyclicSendTask(LimitedDurationCyclicSendTaskABC, RestartableCyclicTaskABC):

    def __init__(
        self,
        session: requests.Session,
        transmit_api_url: str,
        net_timeout: float,
        messages: Union[Sequence[can.Message], can.Message],
        period: float,
        duration: Optional[float] = None,
        autostart: bool = True
    ) -> None:

        # Super classes perform various checks and place the parameters to use in self;
        # messages is normalized to a tuple
        super().__init__(messages, period, duration)
        messages = cast(Tuple[can.Message, ...], self.messages)

        self.transmit_api_url = transmit_api_url
        self._net_timeout = net_timeout
        self.session = session

        # The device API has millisecond resolution: the frame spacing is rounded to the nearest
        # millisecond, and the sequence period follows from it (python-can cyclic tasks have
        # uniform frame spacing). Sub-millisecond periods cannot be represented.
        spacing_ms = round(self.period_ns / 1_000_000)
        if spacing_ms < 1:
            raise ValueError(f"period must be at least 0.001 s (got {self.period} s)")
        period_ms = len(messages) * spacing_ms

        if self.duration is None:
            # Use max value (0xFFFFFFFF - 1) when duration is not provided.
            limit = 0xFFFFFFFE
        else:
            # limit counts sequence repetitions; per python-can, the task transmits at the given
            # rate for at least the requested duration - hence rounding up
            limit = max(1, math.ceil(self.duration * 1000 / period_ms))

        # Sent to the device by start(): the device-side transmit sequence is created on start()
        # and deleted on stop(), so the task holds no device resources before its first start
        # (autostart=False) or after a stop.
        self.transmit_sequence = {
            "limit": limit,
            "period_ms": period_ms,
            "spacing_ms": spacing_ms,
            "frames": [
                {
                    "is_extended": message.is_extended_id,
                    "is_fd": message.is_fd,
                    "is_rtr_brs": message.bitrate_switch if message.is_fd else message.is_remote_frame,
                    "id": message.arbitration_id,
                    "data": "".join([f"{x:02X}" for x in cast(bytearray, message.data)])
                } for message in messages
            ]
        }

        # ID of the device-side transmit sequence; None while none exists
        self.transmit_id: Optional[int] = None

        if autostart:
            self.start()

    def start(self) -> None:
        """Start the task, or restart a stopped or completed task."""

        # Create a device-side transmit sequence if none exists (first start, or restart after
        # stop). A sequence that still exists (e.g. completed by reaching its limit) is reused.
        if self.transmit_id is None:
            try:
                response = self.session.post(url=self.transmit_api_url, timeout=self._net_timeout,
                                        json=self.transmit_sequence)
            except requests.RequestException as e:
                raise can.exceptions.CanOperationError(f"Failed to create transmit sequence ({e})")
            if response.status_code != 201:
                raise can.exceptions.CanOperationError(f"Failed to create transmit sequence ({response.status_code})")

            id_str = response.headers.get("Location", "").rstrip("/").split("/")[-1]
            if not id_str.isdigit():
                raise can.exceptions.CanOperationError("Failed to get transmit sequence ID")
            self.transmit_id = int(id_str)

        # Reset the transmitted-count; the device (re)starts transmission from the first frame
        try:
            response = self.session.put(url=f"{self.transmit_api_url}/{self.transmit_id}/count", timeout=self._net_timeout,
                                    json=0)
        except requests.RequestException as e:
            raise can.exceptions.CanOperationError(f"Failed to (re)start transmit sequence ({e})")
        if response.status_code != 200:
            raise can.exceptions.CanOperationError(f"Failed to (re)start transmit sequence ({response.status_code})")

    def stop(self) -> None:
        """Stop the task by deleting the device-side transmit sequence. Repeated stops are no-ops."""

        # Already stopped?
        if self.transmit_id is None:
            return

        try:
            response = self.session.delete(url=f"{self.transmit_api_url}/{self.transmit_id}",
                                           timeout=self._net_timeout)
        except requests.RequestException as e:
            raise can.exceptions.CanOperationError(f"Failed to stop transmit sequence ({e})")

        # 404: the sequence no longer exists on the device (e.g. the channel was closed after a
        # connection loss) - the goal state of stop(), so treated as stopped
        if response.status_code not in (200, 404):
            raise can.exceptions.CanOperationError(f"Failed to stop transmit sequence ({response.status_code})")
        self.transmit_id = None
