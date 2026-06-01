import socket
import ssl
import warnings
import can
import queue
import requests
import threading
from pathlib import Path
from datetime import datetime, timezone
from time import time, sleep
from typing import Optional, Sequence, TypedDict, Union, Callable, Generator, Any
from can import LimitedDurationCyclicSendTaskABC, BusABC, RestartableCyclicTaskABC
from can.io.generic import TextIOMessageWriter, TextIOMessageReader
from wsproto import ConnectionType, WSConnection, ConnectionState, events
from python_can_cansub.cansub_protocol import cansub_protocol_decode, cansub_protocol_encode

CANSUB_ROOT_CERT: Path = Path(__file__).with_name("cansub_root_cert.crt")

class CanSubHwFilter(TypedDict):
    is_extended: bool
    is_range: bool
    f1: int
    f2: int

CanSubHwFilters = Sequence[CanSubHwFilter]

class CanSub(can.BusABC):

    _supported_api_versions = ["02.00"]
    _can_protocol = can.CanProtocol.CAN_FD_NON_ISO
    _can_f_clock = 80_000_000

    def __init__(self,
                 channel: can.typechecking.Channel,
                 can_filters: Optional[can.typechecking.CanFilters] = None,
                 address: str | None = None,
                 timing: Optional[can.BitTimingFd] = None,
                 bitrate: Optional[int] = None,
                 data_bitrate: Optional[int] = None,
                 listen_only: Optional[bool] = False,
                 auto_reset: Optional[bool] = True,
                 error_frames: Optional[bool] = False,
                 **kwargs: object
                 ):
        """
        Python-can compatible interface over a websocket connection. Functions bus.send and bus.recv are made
        thread-safe by using queues.

        :param timing:
            CAN-bus bit-timing. Takes precedence over bitrate and data_bitrate.

        :param int bitrate:
            CAN-bus bit-rate.

        :param int data_bitrate:
            CAN-bus data (FD) bit-rate.

        :param listen_only:
            CAN-bus listen-only mode.

        :param auto_reset:
            Automatic recovery from bus-off.

        :param error_frames:
            CAN-bus error frame reporting.

        """

        # To be able to use python-can command line tool without custom arguments, support that channel can contain
        # both address and channel, format e.g.: aabbccdd-usb.local@1
        if isinstance(channel, str) and "@" in channel:
            address, channel = channel.split("@", 1)

        if address is None:
            raise can.exceptions.CanInitializationError("Address not provided")

        # Parse address and port
        if ':' in address:
            host, port_str = address.rsplit(':', 1)
            try:
                port = int(port_str)
            except ValueError:
                raise can.exceptions.CanInitializationError(f"Invalid port in address: {address}")
        else:
            host = address
            port = 443

        # Channel
        self.channel = None
        if isinstance(channel, can.typechecking.ChannelInt):
            self.channel = channel
        elif isinstance(channel, can.typechecking.ChannelStr):
            self.channel = can.util.channel2int(channel)
        elif isinstance(channel, Sequence) and len(channel) == 1:
            self.channel = channel[0]

        del channel

        if not isinstance(self.channel, can.typechecking.ChannelInt):
            raise can.exceptions.CanInitializationError("Invalid channel")

        # Bitrate / bit-timing
        if isinstance(timing, can.BitTimingFd):
            # Bit-timing takes precedence over bitrate and data_bitrate
            self.timing = timing
        elif isinstance(bitrate, int) and isinstance(data_bitrate, int):
            # Construct timing from bitrate/data_bitrate (using 80% sample point)
            self.timing = can.BitTimingFd.from_sample_point(
                f_clock=self._can_f_clock,
                nom_bitrate=bitrate,
                nom_sample_point=80.0,
                data_bitrate=data_bitrate,
                data_sample_point=80.0)
        else:
            raise can.exceptions.CanInitializationError("Bitrate / bit-timing not provided")
        del timing, bitrate, data_bitrate

        # listen-only
        self.listen_only = listen_only
        if not isinstance(self.listen_only, bool):
            raise can.exceptions.CanInitializationError("Invalid listen_only type")
        del listen_only

        # auto-reset
        self.auto_reset = auto_reset
        if not isinstance(self.auto_reset, bool):
            raise can.exceptions.CanInitializationError("Invalid auto_reset type")
        del auto_reset

        # error_frames
        self.error_frames = error_frames
        if not isinstance(self.error_frames, bool):
            raise can.exceptions.CanInitializationError("Invalid error_frames type")
        del error_frames

        # Set channel info (required by python-can)
        self.channel_info = f"{address}@{self.channel}"

        # Path to device root certificate
        self.cansub_cert = str(CANSUB_ROOT_CERT)

        # Perform REST interaction with the device in a persistent session
        self.api_url = f"https://{host}:{port}/api"
        self._net_timeout = 3.0

        # Create persistent session for REST API calls
        self.session = requests.Session()
        self.session.verify = self.cansub_cert

        # Get api version (and test connection)
        try:
            response = self.session.get(f"{self.api_url}/version", timeout=self._net_timeout)
            response.raise_for_status()
        except Exception as e:
            raise can.exceptions.CanInitializationError(f"Connection failed ({e})")

        self.api_version = response.json()
        if not (isinstance(self.api_version, str) and self.api_version in self._supported_api_versions):
            raise can.exceptions.CanInitializationError(f"API version not supported ({self.api_version})")

        # Get state of the channel
        try:
            response = self.session.get(f"{self.api_url}/can/{self.channel}", timeout=self._net_timeout)
            response.raise_for_status()
        except Exception as e:
            raise can.exceptions.CanInitializationError(f"Failed to get channel state ({e})")

        channel_state = response.json()
        if not ("state" in channel_state and channel_state["state"] == "stopped"):
            raise can.exceptions.CanInitializationError(f"Channel connect be opened (state: {channel_state['state']})")

        # Set device time
        time_string = datetime.now(timezone.utc).isoformat(timespec="milliseconds")[:-6] + "Z"
        try:
            response = self.session.put(url=f"{self.api_url}/time", json=time_string, timeout=self._net_timeout)
            response.raise_for_status()
        except Exception as e:
            raise can.exceptions.CanInitializationError(f"Failed to set device time ({e})")

        # Ensure that no hardware filters are set before the channel is opened
        # (Ensures that no messages get through until provided filters are set)
        self.set_hw_filters(None)

        # Ensure that no transmit-sequences are configured before the channel is opened
        try:
            response = self.session.get(f"{self.api_url}/can/{self.channel}/transmit", timeout=self._net_timeout)
            response.raise_for_status()
            for transmit_id in response.json():
                response = self.session.delete(f"{self.api_url}/can/{self.channel}/transmit/{transmit_id}", timeout=self._net_timeout)
                response.raise_for_status()
        except Exception as e:
            raise can.exceptions.CanInitializationError(f"Failed to clear transmit sequences ({e})")

        # Set channel configuration
        phy_config = {
            "listen_only": self.listen_only,
            "auto_reset": self.auto_reset,
            "error_frames": self.error_frames,
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
        try:
            response = self.session.put(f"{self.api_url}/can/{self.channel}/phy", json=phy_config,
                                    timeout=self._net_timeout)
            response.raise_for_status()
        except Exception as e:
            raise can.exceptions.CanInitializationError(f"Failed to configure channel ({e})")

        # Socket TLS configuration
        ssl_context = ssl.create_default_context(cafile=self.cansub_cert)

        # Socket
        self.ws_sock = ssl_context.wrap_socket(sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM), server_hostname=host)
        self.ws_sock.settimeout(self._net_timeout)

        # Disable Nagles algorithm (lower latency for small writes)
        self.ws_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        # Websocket client
        self.ws_client = WSConnection(ConnectionType.CLIENT)

        # Queue from websocket to python-can.recv
        self.can_recv_queue: queue.Queue[can.Message] = queue.Queue()

        # Queue from python-can.send to websocket
        self.can_send_queue: queue.Queue[can.Message] = queue.Queue()

        # Thread stop event
        self.stop_event = threading.Event()

        # ws close event. Stored here to allow the client (us) to correctly confirm the close
        self.ws_close_event = None

        # Connect to the regular socket with retry.
        socket_connected = False
        for i in range(5):
            try:
                self.ws_sock.connect((host, port))
                socket_connected = True
                break
            except ConnectionRefusedError:
                # Server is likely busy, wait a bit and try again
                sleep(0.25 * (i + 1))
                continue
            except Exception:
                break

        if socket_connected is False:
            raise can.exceptions.CanInitializationError("Connection failed")

        # Upgrade to websocket
        request = self.ws_client.send(events.Request(host=f"{host}:{port}", target=f"/api/can/{self.channel}/ws"))
        self.ws_sock.sendall(request)

        # Wait for upgrade confirmation with timeout
        start_time = time()
        while (self.ws_client.state != ConnectionState.OPEN) and (time() - start_time) < 5:
            try:
                self.ws_client.receive_data(self.ws_sock.recv(2048))
            except socket.timeout:
                continue
            except Exception:
                break

        # Check that the upgrade was successful
        if self.ws_client.state != ConnectionState.OPEN:
            raise can.exceptions.CanInitializationError("Upgrade failed")

        # Call init for parent class
        # NOTE: This calls _apply_filters ensuring that can_filters are set
        super().__init__(channel=self.channel, can_filters=can_filters)

        def _ws_recv_loop():
            """
            Receives data from (web)socket and adds parsed messages to python-can recv queue.
            Warning: this thread is only allowed to receive from ws
            """

            data = bytearray()

            # Receive data from the socket in loop. Ensure to periodically check if the stop event is set
            while not self.stop_event.is_set():

                try:
                    ws_data = self.ws_sock.recv(2048)
                except socket.timeout:
                    # Timeout to be able to check if the stop event is set
                    continue
                except socket.error as e:
                    raise can.exceptions.CanOperationError(f"Socket receive error: {e}")
                except Exception as e:
                    raise can.exceptions.CanOperationError(f"Socket receive error: {e}")

                # Data received?
                if not ws_data:
                    # No, socket closed by peer (NOTE, the regular socket was closed directly, not the websocket)
                    self.stop_event.set()
                    continue
                else:
                    # Yes, parse websocket data
                    self.ws_client.receive_data(ws_data)

                    # Process websocket events
                    for event in self.ws_client.events():

                        # Websocket event type
                        if isinstance(event, events.BytesMessage):

                            # Append to data buffer
                            data.extend(event.data)

                            def msg_cb(msg: can.Message):
                                msg.channel = self.channel
                                self.can_recv_queue.put(msg)

                            cansub_protocol_decode(data, msg_cb)

                        # Websocket close event. NOTE: We need to store this event to allow the client (us) to
                        # correctly confirm the close later (we cannot send in this thread)
                        elif isinstance(event, events.CloseConnection):
                            self.ws_close_event = event
                            self.stop_event.set()

        def _ws_send_loop():
            """Warning: this thread is only allowed to transmit to ws"""

            # Send buffer
            data = bytearray()

            while not self.stop_event.is_set():

                # Wait for a CAN TX frame in queue with timeout to allow checking stop_event
                msg = None
                try:
                    msg = self.can_send_queue.get(block=True, timeout=self.ws_sock.gettimeout())
                except queue.Empty:
                    continue

                # Encode the message in the buffer
                cansub_protocol_encode(msg, data)

                # Transmit if buffer "full" or no more messages in the queue
                if len(data) >= 1200 or self.can_send_queue.qsize() == 0:

                    # Send network frame
                    if self.ws_sock:
                        self.ws_sock.sendall(self.ws_client.send(events.BytesMessage(data)))
                    else:
                        break

                    # Reset buffer
                    data.clear()

        def _shutdown():
            """Thread to handle correct shutdown of the websocket connection, regardless of shutdown triggered by
            used or due to error"""

            # Wait ws threads to finish (on error or on shutdown event)
            self._pythoncan_send_to_ws_send_thread.join()
            self._ws_recv_to_python_can_recv_thread.join()

            # Close websocket connection
            if self.ws_client.state == ConnectionState.REMOTE_CLOSING and self.ws_close_event:

                # Websocket already closed by peer, confirm close
                self.ws_sock.sendall(self.ws_client.send(self.ws_close_event.response()))

            #elif self.ws_client.state == ConnectionState.OPEN:
            #
            #    # Websocket still open, send close request
            #    self.ws_sock.sendall(self.ws_client.send(CloseConnection(CloseReason.NORMAL_CLOSURE)))
            #
            #    # Wait for peer to confirm close with timeout
            #    # TODO: Use below once cansub supports confirmation of close
            #    if False:
            #        start_time = time()
            #        while (self.ws_client.state != ConnectionState.CLOSED) and (time() - start_time) < 1:
            #            try:
            #                self.ws_client.receive_data(self.ws_sock.recv(2048))
            #            except socket.timeout:
            #                continue
            #            except Exception:
            #                break
            #
            ## Confirm websocket close
            ## TODO: CANsub does currently not confirm to websocket close
            #if self.ws_client.state != ConnectionState.CLOSED:
            #    #raise can.exceptions.CanOperationError("Websocket close failed")
            #    print("Websocket close failed")
            #    pass

            # Gracefully close the TCP connection
            try:
                self.ws_sock.shutdown(socket.SHUT_WR)
            except socket.error:
                print("Socket shutdown failed")
                # Socket already closed or other error
                pass

            # Wait for peer to confirm close of socket with timeout
            try:
                data = self.ws_sock.recv(1024)
                if data:
                    print("Socket confirm close failed")
            except socket.timeout:
                # Peer dit not confirm in time
                print("Socket shutdown timeout")
                pass
            except socket.error:
                # Socket already closed or other error
                print("Socket shutdown failed")
                pass
            finally:
                # Close socket and release resources
                self.ws_sock.close()

        # ws thread, ws to python-can recv
        self._ws_recv_to_python_can_recv_thread = threading.Thread(target=_ws_recv_loop)

        # ws thread, python-can send to ws
        self._pythoncan_send_to_ws_send_thread = threading.Thread(target=_ws_send_loop)

        self._ws_recv_to_python_can_recv_thread.start()
        self._pythoncan_send_to_ws_send_thread.start()

        sleep(0.1)

        # Create a thread to handle correct shutdown of the websocket connection, regardless of shutdown due to error
        # or normal shutdown (by used calling bus.shutdown)
        self.ws_shutdown_thread = threading.Thread(target=_shutdown)
        self.ws_shutdown_thread.start()

        # Initialize the parent class
        super().__init__(channel=self.channel, can_filters=can_filters, **kwargs)

    def shutdown(self):

        # Signal websocket threads to stop
        self.stop_event.set()

        # Wait for shutdown thread to complete
        self.ws_shutdown_thread.join()

        # Close the persistent session
        if hasattr(self, 'session'):
            self.session.close()

        super().shutdown()

    def send(self, msg: can.Message, timeout: float = None):
        """
        See "send" in can.BusABC. Note, waits for a slot in the queue to be available (not for messages to be ACK'ed)
        """

        if timeout is not None and timeout < 0:
            raise can.exceptions.CanOperationError("Invalid timeout value")

        try:
            if timeout is None:
                # Wait indefinitely for queue space
                self.can_send_queue.put(msg, block=True, timeout=None)
            elif timeout == 0:
                # Return immediately
                self.can_send_queue.put(msg, block=False)
            else:
                # Wait for timeout seconds for queue space
                self.can_send_queue.put(msg, block=True, timeout=timeout)
        except queue.Full:
            # Queue full
            can.exceptions.CanOperationError("TX queue full")

    def _recv_internal(self, timeout: float = None) -> tuple[Optional[can.Message], bool]:
        """
        See "recv" and "_recv_internal" in can.BusABC

        Always return that the message has already been filtered.
        """
        if timeout is not None and timeout < 0:
            raise can.exceptions.CanOperationError("Invalid timeout value")

        msg = None
        try:
            if timeout is None:
                # Wait indefinitely
                msg = self.can_recv_queue.get(block=True, timeout=None)
            elif timeout == 0:
                # Return immediately
                msg = self.can_recv_queue.get(block=False)
            else:
                # Wait for timeout seconds
                msg = self.can_recv_queue.get(block=True, timeout=timeout)
        except queue.Empty:
            # Queue empty
            pass
        return msg, True

    @property
    def state(self) -> can.BusState:
        """
        Return the current state of the hardware
        """

        # Get channel state
        try:
            response = self.session.get(f"{self.api_url}/can/{self.channel}", timeout=self._net_timeout)
            response.raise_for_status()
        except Exception as e:
            raise can.exceptions.CanOperationError(f"Failed to get state of channel {self.channel}")

        # Parse response
        response_dict = response.json()
        if not (isinstance(response_dict, dict) and "state" in response_dict):
            raise can.exceptions.CanOperationError(f"Failed to get state of channel {self.channel}")

        response_state = response_dict["state"]
        if response_state == "error_active" or response_state == "error_warning":
            state = can.BusState.ACTIVE
        elif response_state == "error_passive":
            state = can.BusState.PASSIVE
        elif response_state == "bus_off":
            state = can.BusState.ERROR
        else:
            raise can.exceptions.CanOperationError(f"Unknown channel state {response_state}")
        return state

    def flush_tx_buffer(self):
        """
        Flush to send queue
        """
        self.can_send_queue.queue.clear()

    def _apply_filters(self, filters: Optional[can.typechecking.CanFilters]) -> None:

        # Python-can specify that all messages should be accepted if filters are None or empty list
        if filters is None or len(filters) == 0:
            filters = [
                can.typechecking.CanFilter(extended=False, can_id=0, can_mask=0),  # Accept all std messages
                can.typechecking.CanFilter(extended=True,  can_id=0, can_mask=0)   # Accept all ext messages
            ]

        # Change to CanSubHwFilter type. When "extended" field not provided, default to False (required by cmd-tools)
        can_hw_filters = [CanSubHwFilter(is_extended=x.get("extended", False),
                                         is_range=False,
                                         f1=x["can_id"],
                                         f2=x["can_mask"]) for x in filters]

        # Apply hardware filter
        self.set_hw_filters(can_hw_filters)

    def set_hw_filters(self, can_hw_filters: Optional[CanSubHwFilters]) -> None:
        """
        Sets device hardware filters

        NOTE: Contrary to the set_filters method, this method does not set any filters if can_hw_filters is None or empty.
        """

        # Get existing filters for channel
        try:
            response = self.session.get(f"{self.api_url}/can/{self.channel}/filter", timeout=self._net_timeout)
            response.raise_for_status()
        except Exception as e:
            raise can.exceptions.CanInitializationError(f"Failed to get existing filters ({e})")

        filter_ids = response.json()

        # Any existing filters?
        if len(filter_ids) > 0:

            # Yes, delete filters one by one
            for filter_id in filter_ids:
                try:
                    response = self.session.delete(f"{self.api_url}/can/{self.channel}/filter/{filter_id}",
                                               timeout=self._net_timeout)
                    response.raise_for_status()
                except Exception as e:
                    raise can.exceptions.CanInitializationError(f"Failed to delete existing filter ({e})")

            # Confirm all filters deleted
            try:
                response = self.session.get(f"{self.api_url}/can/{self.channel}/filter",
                                        timeout=self._net_timeout)
                response.raise_for_status()
            except Exception as e:
                raise can.exceptions.CanInitializationError(f"Failed to get existing filters ({e})")

            if len(response.json()) > 0:
                raise can.exceptions.CanInitializationError("Failed to delete all existing filters")

        # Any new filters provide?
        if can_hw_filters is None or len(can_hw_filters) == 0:
            # No, nothing to do
            return

        # Create new filters
        for hw_filter in can_hw_filters:

            if not isinstance(hw_filter, dict):
                raise can.exceptions.CanOperationError("Invalid filter type")

            try:
                response = self.session.post(f"{self.api_url}/can/{self.channel}/filter", json=hw_filter,
                                         timeout=self._net_timeout)
                response.raise_for_status()
            except Exception as e:
                raise can.exceptions.CanOperationError(f"Failed to create new filter ({e})")

        # Confirm all filters created
        try:
            response = self.session.get(f"{self.api_url}/can/{self.channel}/filter",
                                    timeout=self._net_timeout)
            response.raise_for_status()
        except Exception as e:
            raise can.exceptions.CanOperationError(f"Failed to get new filters ({e})")

        if len(response.json()) != len(can_hw_filters):
            raise can.exceptions.CanOperationError("Failed to create new filters")

    def _send_periodic_internal(
            self,
            msgs: Union[Sequence[can.Message], can.Message],
            period: float,
            duration: Optional[float] = None,
            autostart: bool = True,
            modifier_callback: Optional[Callable[[can.Message], None]] = None,
    ) -> can.broadcastmanager.CyclicSendTaskABC:

        if modifier_callback is None:
            return CyclicSendTask(self, channel=self.channel, messages=msgs, period=period, duration=duration,
                                  autostart=autostart)
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
        from zeroconf import InterfaceChoice, ServiceBrowser, Zeroconf

        # Collect DNS-SD service info objects keyed by service name.
        # The device firmware advertises _cansub._tcp with TXT records:
        #   api=<version>   - must match _supported_api_versions
        #   channels=<n>    - number of CAN channels (0-based indices)
        # The SRV hostname encodes the serial number and connection type,
        # e.g. 1b5b9343-usb.local (USB) or 1b5b9343-eth.local (Ethernet).
        discovered = {}

        class _Listener:
            def add_service(self, zc, type_, name):
                info = zc.get_service_info(type_, name)
                if info:
                    discovered[name] = info
            def remove_service(self, zc, type_, name): pass
            def update_service(self, zc, type_, name): pass

        # Listen on all interfaces so devices on multiple USB/Ethernet links
        # are all discovered (each CDC-NCM or Ethernet link is a separate interface).
        zc = Zeroconf(interfaces=InterfaceChoice.All)
        try:
            ServiceBrowser(zc, "_cansub._tcp.local.", _Listener())
            sleep(2.0)
        finally:
            zc.close()

        configs = []
        for info in discovered.values():
            # TXT record keys/values arrive as bytes; decode to str for easy lookup.
            txt = {
                (k.decode() if isinstance(k, bytes) else k):
                (v.decode() if isinstance(v, bytes) else v)
                for k, v in info.properties.items()
            }

            # Skip devices running an unsupported API version.
            if txt.get("api") not in CanSub._supported_api_versions:
                continue

            # info.server has a trailing dot (DNS convention); strip it.
            hostname = info.server.rstrip(".")

            try:
                num_channels = int(txt.get("channels", 1))
            except ValueError:
                num_channels = 1

            # Channel is encoded in the address string understood by __init__,
            # e.g. "1b5b9343-usb.local@1". Channels are 1-based.
            for channel in range(1, num_channels + 1):
                configs.append({"interface": "cansub", "channel": f"{hostname}@{channel}"})

        return configs

class CyclicSendTask(LimitedDurationCyclicSendTaskABC, RestartableCyclicTaskABC):

    def __init__(
        self,
        cansub: CanSub,
        channel: can.typechecking.ChannelInt,
        messages: Union[Sequence[can.Message], can.Message],
        period: float,
        duration: Optional[float] = None,
        autostart: bool = True
    ) -> None:

        # Super classes perform various checks and place the parameters to use in self.
        super().__init__(messages, period, duration)

        self.transmit_api_url = f"{cansub.api_url}/can/{channel}/transmit"
        self._net_timeout = cansub._net_timeout
        self.cansub_cert = cansub.cansub_cert
        self.session = cansub.session

        period_ms = int(len(self.messages) * self.period_ns / 1_000_000)
        spacing_ms = int(self.period_ns / 1_000_000)

        if self.duration is None:
            # Use max value (0xFFFFFFFF - 1) when duration is not provided.
            limit = 0xFFFFFFFE
        else:
            limit = int(duration * 1000 / period_ms)
            limit = max(1, limit)

        transmit_sequence = {
            "limit": limit,
            "period_ms": period_ms,
            "spacing_ms": spacing_ms,
            "frames": [
                {
                    "is_extended": message.is_extended_id,
                    "is_fd": message.is_fd,
                    "is_rtr_brs": message.bitrate_switch if message.is_fd else message.is_remote_frame,
                    "id": message.arbitration_id,
                    "data": "".join([f"{x:02X}" for x in message.data])
                } for message in self.messages
            ]
        }

        # Set up new transmit sequence
        response = self.session.post(url=self.transmit_api_url, timeout=self._net_timeout, verify=self.cansub_cert,
                                json=transmit_sequence)

        if response.status_code != 201:
            raise can.exceptions.CanOperationError(f"Failed to create transmit sequence ({response.status_code})")
        if "Location" not in response.headers or not isinstance(response.headers["Location"], str):
            raise can.exceptions.CanOperationError(f"Failed get transmit sequence ID")

        id_str = response.headers["Location"].rstrip('/').split('/')[-1]
        if id_str.isdigit() is False:
            raise can.exceptions.CanOperationError(f"Failed get transmit sequence ID")
        self.transmit_id = int(id_str)

        if autostart is True:
            self.start()

    def start(self) -> None:
        """Restart a stopped periodic task."""
        response = self.session.put(url=f"{self.transmit_api_url}/{self.transmit_id}/count", timeout=self._net_timeout,
                                verify=self.cansub_cert, json=0)
        if response.status_code != 200:
            raise can.exceptions.CanOperationError(f"Failed to (re)start transmit sequence ({response.status_code})")

    def stop(self) -> None:
        """Stop periodic task."""
        response = self.session.delete(url=f"{self.transmit_api_url}/{self.transmit_id}", timeout=self._net_timeout,
                                   verify=self.cansub_cert)
        if response.status_code != 200:
            raise can.exceptions.CanOperationError(f"Failed to stop transmit sequence ({response.status_code})")
        return

class CanSubCSVWriter(TextIOMessageWriter):
    """
    CanSub CSV writer.
    """

    def __init__(self, file, append=False, **kwargs):
        super().__init__(file, mode="a" if append else "w")
        if not append:
            self.file.write("TimestampEpoch;BusChannel;ID;IDE;DLC;DataLength;Dir;EDL;BRS;ESI;RTR;DataBytes\n")

    def on_message_received(self, msg: can.Message) -> None:

        # Determine BusChannel from msg.channel
        bus_channel = str(msg.channel) if msg.channel is not None else ""

        # ID formatting: 3 hex chars for standard ID, 8 for extended ID
        id_fmt = f"{msg.arbitration_id:03X}" if not msg.is_extended_id else f"{msg.arbitration_id:08X}"

        row = ";".join(
            [
                f"{msg.timestamp:10.6f}",                   #  0: TimestampEpoch
                str(bus_channel),                           #  1: BusChannel
                id_fmt,                                     #  2: ID
                "1" if msg.is_extended_id else "0",         #  3: IDE
                str(can.util.len2dlc(msg.dlc)),             #  4: DLC (NOTE: python-can stores LEN in DLC)
                str(msg.dlc),                               #  5: DataLength (NOTE: python-can stores LEN in DLC)
                "0" if msg.is_rx else "1",                  #  6: Dir
                "1" if msg.is_fd else "0",                  #  7: EDL
                "1" if msg.bitrate_switch else "0",         #  8: BRS
                "1" if msg.error_state_indicator else "0",  #  9: ESI
                "1" if msg.is_remote_frame else "0",        # 10: RTR
                msg.data.hex().upper(),                     # 11: DataBytes
            ]
        )
        self.file.write(row + "\n")

class CanSubCSVReader(TextIOMessageReader):
    """
    CanSub CSV reader.
    """

    def __init__(self, file: Union[can.typechecking.StringPathLike, Any], channel_filter=None, **kwargs: Any) -> None:
        """
        :param channel_filter: Only frames recorded on this channel are yielded (channel field is first set to None)
        """
        super().__init__(file, mode="r", **kwargs)
        self.channel_filter = str(channel_filter) if channel_filter is not None else None

    def __iter__(self) -> Generator[can.Message, None, None]:

        # Expected header
        expected_header = "TimestampEpoch;BusChannel;ID;IDE;DLC;DataLength;Dir;EDL;BRS;ESI;RTR;DataBytes"

        # Verify the header line
        try:
            header = next(self.file).strip()
            if header.lower() != expected_header.lower():
                warnings.warn(
                    f"CSV header mismatch. Expected: {expected_header}, Found: {header}",
                    UserWarning
                )
        except StopIteration:
            return

        for line in self.file:
            line = line.strip()
            if not line:
                continue

            columns = line.split(";")
            if len(columns) < 12:
                continue

            try:
                channel = int(columns[1]) if columns[1] else None
                # Perform channel filtering if enabled
                if channel is not None and self.channel_filter is not None:
                    if str(channel) != self.channel_filter:
                        continue
                    # Clear channel field (better compatibility with python-can commandline tools)
                    channel = None
                yield can.Message(
                    timestamp=float(columns[0]),                        #  0: TimestampEpoch
                    channel=channel,                                    #  1: BusChannel (None when channel_filter is set)
                    arbitration_id=int(columns[2], 16),                 #  2: ID
                    is_extended_id=columns[3] == "1",                   #  3: IDE
                    dlc=can.util.dlc2len(int(columns[4])),              #  4: DLC (NOTE: python-can stores LEN in DLC)
                                                                        #  5: DataLength not mapped
                    is_rx=columns[6] == "0",                            #  6: Dir
                    is_fd=columns[7] == "1",                            #  7: EDL
                    bitrate_switch=columns[8] == "1",                   #  8: BRS
                    error_state_indicator=columns[9] == "1",            #  9: ESI
                    is_remote_frame=columns[10] == "1",                 # 10: RTR
                    data=bytes.fromhex(columns[11])                     # 11: DataBytes
                )
            except (ValueError, IndexError):
                continue

        self.stop()

def register_cansub_csv_writer():
    """
    Registers the CanSubCSVWriter and CanSubCSVReader for .csv files in python-can.
    """
    from can.io.logger import MESSAGE_WRITERS
    from can.io.player import MESSAGE_READERS
    MESSAGE_WRITERS[".csv"] = CanSubCSVWriter
    MESSAGE_READERS[".csv"] = CanSubCSVReader
