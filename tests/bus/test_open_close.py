import can
import pytest
import socket
from time import monotonic, sleep


class TestOpenClose:

    def test_open(self, bus_config):
        """Open and close a bus and measure the time it takes."""
        start = monotonic()
        with can.Bus(channel=1, **bus_config) as bus:
            open_time = monotonic() - start
            assert bus.state is can.BusState.ACTIVE

            # Opened with a data bitrate: the bus operates as (ISO) CAN FD
            assert bus.protocol is can.CanProtocol.CAN_FD

            # A freshly opened, quiet bus delivers nothing
            assert bus.recv(timeout=0.2) is None, "unexpected message on an idle bus"

            start = monotonic()
        close_time = monotonic() - start

        print(f"open: {open_time:.3f} s, close: {close_time:.3f} s")
        assert open_time < 0.5, f"open took {open_time:.3f} s"
        assert close_time < 0.1, f"close took {close_time:.3f} s"

    def test_open_no_data_bitrate(self, bus_config):
        """Open a bus with no data bitrate, and check that it operates as (ISO) CAN 2.0."""
        classic_config = {key: value for key, value in bus_config.items() if key != "data_bitrate"}

        with can.Bus(channel=1, **classic_config) as bus:
            assert bus.protocol is can.CanProtocol.CAN_20

            # Test that sending an FD message fails
            with pytest.raises(can.CanOperationError):
                bus.send(can.Message(arbitration_id=0x123, is_extended_id=False, is_fd=True,
                                     bitrate_switch=True, data=bytes(64)))

    def test_open_no_data_bit_timing(self, bus_config):
        """Open a bus with a nominal bit-timing only (can.BitTiming), and check that it operates
        as (ISO) CAN 2.0."""
        timing = can.BitTiming.from_sample_point(f_clock=80_000_000,
                                                 bitrate=bus_config["bitrate"], sample_point=80.0)
        timing_config = {key: value for key, value in bus_config.items()
                         if key not in ("bitrate", "data_bitrate")}

        with can.Bus(channel=1, timing=timing, **timing_config) as bus:
            assert bus.protocol is can.CanProtocol.CAN_20

            # Test that sending an FD message fails
            with pytest.raises(can.CanOperationError):
                bus.send(can.Message(arbitration_id=0x123, is_extended_id=False, is_fd=True,
                                     bitrate_switch=True, data=bytes(64)))

    def test_open_via_ip(self, bus_config):
        """Open a bus via the device IP address instead of the hostname. An IP address carries
        no name to verify the server certificate against, so hostname verification is disabled
        (chain verification remains active)."""
        ip = socket.gethostbyname(bus_config["address"])
        ip_config = {**bus_config, "address": ip}

        with can.Bus(channel=1, **ip_config) as bus:
            assert bus.state is can.BusState.ACTIVE

    def test_reopen(self, bus_config):
        """Test that a channel can be closed and reopened (resources are released on both sides)."""
        for _ in range(3):
            with can.Bus(channel=1, **bus_config) as bus:
                assert bus.state in [can.BusState.ACTIVE, can.BusState.PASSIVE]

    def test_channel_info(self, bus_config):
        """Test that channel_info (required by the python-can API) is "<address>@<channel>",
        both when connected via the hostname and via the ip address."""
        with can.Bus(channel=1, **bus_config) as bus:
            assert bus.channel_info == f"{bus_config['address']}@1"

        # Connect via the resolved ip address instead of the hostname
        ip = socket.gethostbyname(bus_config["address"])
        ip_config = {**bus_config, "address": ip}
        with can.Bus(channel=2, **ip_config) as bus:
            assert bus.channel_info == f"{ip}@2"

    def test_address_argument_forms(self, bus_config):
        """Test the two ways of providing the device address: the dedicated address argument,
        and combined with the channel ("<address>@<channel>", used by the command line tools)."""
        address = bus_config["address"]

        # Dedicated address argument, numeric channel
        with can.Bus(channel=1, **bus_config) as bus:
            assert bus.channel_info == f"{address}@1"

        # Address combined into the channel string
        combined_config = {key: value for key, value in bus_config.items() if key != "address"}
        with can.Bus(channel=f"{address}@1", **combined_config) as bus:
            assert bus.channel_info == f"{address}@1"

    def test_close_with_queue(self, bus_config):
        """Test that the bus can be closed while the tx queue is full. Ensures shutdown of a non-functional bus"""
        shutdown_timeout = 2.0

        # Open only the transmitting bus: nothing acknowledges on the wire, so the first
        # transmission never completes
        with can.Bus(channel=1, shutdown_timeout=shutdown_timeout, **bus_config) as bus_tx:

            # Transmit full blast until backpressure blocks the send (queues full)
            sent_nof = 0
            full = False
            try:
                for i in range(9999):
                    bus_tx.send(can.Message(arbitration_id=i, is_extended_id=True,
                                            data=[1, 2, 3, 4, 5, 6, 7, 8]), timeout=1.0)
                    sent_nof += 1
            except can.CanTimeoutError:
                full = True
            assert full is True

            # Immediately leave the scope; the close waits shutdown_timeout, then discards
            start = monotonic()
        close_time = monotonic() - start

        print(f"queued {sent_nof} messages, closed in {close_time:.3f} s")
        assert shutdown_timeout < close_time < shutdown_timeout + 5.0, \
            f"close took {close_time:.3f} s, expected just above {shutdown_timeout} s"

    def test_connection_loss(self, bus_config, capsys):
        """Test that the I/O thread terminates when the physical connection to the device is
        lost, and that the bus reports the loss and can still be shut down.

        MANUAL: an operator must disconnect the device when prompted, and reconnect it at the
        second prompt (the test waits for the reconnection).
        """
        try:
            with can.Bus(channel=1, **bus_config) as bus:
                # Prompt outside the output capturing, such that the operator sees it immediately
                with capsys.disabled():
                    print("\n*** DISCONNECT THE DEVICE NOW (within 5 s) ***", flush=True)

                # A quiet bus returns None until the loss surfaces as an exception. Budget:
                # 5 s for the operator plus the TCP keepalive detection time of ~4 s
                # (~11 s on Windows)
                for _ in range(20):
                    bus.recv(timeout=1.0)
        except can.CanOperationError as e:
            # Expected: the loss surfaced through recv, and shutdown (the context exit,
            # unwinding through the raise) completed on the dead connection
            print(f"connection loss detected ({e})")
        else:
            pytest.fail("Connection loss not detected: this test needs an operator to "
                        "disconnect the device when prompted, within 5 s")

        # Wait for the operator to reconnect the device: the following tests need it
        with capsys.disabled():
            print("*** RECONNECT THE DEVICE NOW (within 60 s) ***", flush=True)
        deadline = monotonic() + 60.0
        while monotonic() < deadline:
            try:
                socket.create_connection((bus_config["address"], 443), timeout=1.0).close()
                break
            except OSError:
                sleep(1.0)
        else:
            pytest.fail("Device not reconnected: reconnect the device within 60 s of the "
                        "reconnect prompt")
        with capsys.disabled():
            print("device reconnected", flush=True)