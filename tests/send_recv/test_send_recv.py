import can
import pytest
from time import monotonic, time


class TestSendRecv:
    """Send and receive"""

    @pytest.mark.parametrize("msg", [
        can.Message(arbitration_id=0x123, is_extended_id=False, data=bytes(0)),
        can.Message(arbitration_id=0x12345678, is_extended_id=True, data=bytes(8)),
        can.Message(arbitration_id=0x789, is_extended_id=False, is_remote_frame=True, dlc=4),
        can.Message(arbitration_id=0x456, is_extended_id=False, is_fd=True, bitrate_switch=True, data=bytes(64)),
    ], ids=["classical", "extended", "remote", "fd_brs"])
    def test_roundtrip(self, bus_config, msg):
        """
        Test that a message arrives intact at the receiving channel.
        Enable receive_own_messages to also test tx acks on the transmitting channel.
        """
        with (can.Bus(channel=1, **bus_config) as bus_rx,
              can.Bus(channel=2, receive_own_messages=True, **bus_config) as bus_tx):

            # Update timestamp to system time
            msg.timestamp = time()

            # Send message
            bus_tx.send(msg)
            print(msg)

            # Read message (tx ack) on the transmitting channel
            tx_ack = bus_tx.recv(timeout=2.0)
            print(tx_ack)
            assert tx_ack is not None, "tx ack not received"

            # Read message on the receiving channel
            rx = bus_rx.recv(timeout=2.0)
            print(rx)
            assert rx is not None, "message not received"

            # Check that tx_ack matches test message with a timestamp delta of 0.5 s
            assert tx_ack.equals(msg, timestamp_delta=0.5, check_channel=False, check_direction=False)

            # Check that rx matches tx_ack
            assert tx_ack.equals(rx, timestamp_delta=1.5e-6, check_channel=False, check_direction=False)

            # Check the direction flags: the tx ack is a transmitted message, not a received one
            assert tx_ack.is_rx is False, "tx ack has is_rx True"
            assert rx.is_rx is True, "received message has is_rx False"


    def test_no_own_messages_by_default(self, bus_config):
        """Test that a bus does not receive its own transmitted messages by default"""
        with can.Bus(channel=1, **bus_config) as bus_rx, can.Bus(channel=2, **bus_config) as bus_tx:

            bus_tx.send(can.Message(arbitration_id=0x123, is_extended_id=False, data=[1, 2]))

            # Test that message arrives at the other channel
            assert bus_rx.recv(timeout=2.0) is not None, "message not received"

            # Test that no message arrives at the transmitting channel
            assert bus_tx.recv(timeout=0.5) is None, "unexpected own message (tx ack) received"

    def test_high_load(self, bus_config):
        """Test that messages sent at full blast arrive exactly once, in order - including the messages still queued
        when the transmitting exits to open-scope.
        The transmitting bus is opened with receive_own_messages=True to include the tx acks in the load."""
        test_message_count = 100_000

        rx_buffer = can.BufferedReader()
        tx_buffer = can.BufferedReader()

        # Open both buses with listeners
        with (can.Bus(channel=1, shutdown_timeout=None, error_frames=True, **bus_config) as bus_rx,
              can.Bus(channel=2, shutdown_timeout=None, error_frames=True, receive_own_messages=True,
                      **bus_config) as bus_tx,
              can.Notifier([bus_rx], listeners=[rx_buffer]),
              can.Notifier([bus_tx], listeners=[tx_buffer])):

            start = monotonic()

            # Transmit full blast - backpressure ensures that no frames are lost
            for i in range(test_message_count):
                bus_tx.send(can.Message(arbitration_id=i, is_extended_id=True,
                                        data=[1, 2, 3, 4, 5, 6, 7, 8]), timeout=10)

            transmit_time_actual = monotonic() - start

            # An extended-id classical frame with 8 data bytes is 131 bits nominal (incl. 3-bit interframe space)
            transmit_time_expected = test_message_count * 131 / bus_config["bitrate"]

            print(f"transmitted {test_message_count} messages in {transmit_time_actual:.3f} s "
                  f"({test_message_count / transmit_time_actual:.0f} msg/s, wire minimum {transmit_time_expected:.1f} s)")
            assert transmit_time_expected < transmit_time_actual < transmit_time_expected * 1.2, \
                f"transmit took {transmit_time_actual:.3f} s, expected just above {transmit_time_expected:.1f} s"

            # Collect until the wire goes quiet (2 s without a message)
            rx_msgs = list(iter(lambda: rx_buffer.get_message(timeout=2.0), None))
            tx_msgs = list(iter(lambda: tx_buffer.get_message(timeout=2.0), None))
            print(f"received {len(rx_msgs)} messages ({len(tx_msgs)} tx acks)")

        # Test that the transfer was error free on both channels
        rx_errors = [msg for msg in rx_msgs if msg.is_error_frame]
        tx_errors = [msg for msg in tx_msgs if msg.is_error_frame]
        assert not tx_errors, f"{len(tx_errors)} error frames on the transmitting channel"
        assert not rx_errors, f"{len(rx_errors)} error frames on the receiving channel"

        # Test that every message was received exactly once, in order
        rx_ids = [msg.arbitration_id for msg in rx_msgs]
        assert rx_ids == list(range(test_message_count)), \
            f"sent {test_message_count} messages, received {len(rx_ids)}"
