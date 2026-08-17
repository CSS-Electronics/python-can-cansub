import can
from python_can_cansub import CanSubErrorFrameType


class TestErrorFrames:
    """Error frame reporting: bus errors are received as error frame messages."""

    def test_error_frame_on_unacknowledged_tx(self, bus_config):
        """
        With the peer channel closed, nothing acknowledges on the wire: a transmission produces
        (ACK) error frames, received as messages with is_error_frame set.
        """
        with can.Bus(channel=1, error_frames=True, **bus_config) as bus:
            bus.send(can.Message(arbitration_id=0x111, is_extended_id=False, data=[1]))

            msg = bus.recv(timeout=2.0)
            assert msg is not None, "no error frame received"
            assert msg.is_error_frame

            # The arbitration ID encodes the error type
            error_type = CanSubErrorFrameType(msg.arbitration_id)
            assert error_type == CanSubErrorFrameType.ACK, f"unexpected error type {error_type.name}"

            # The failed retransmissions (+8 on the TX error counter each) quickly drive the
            # counter past 127: the bus state must report error-passive
            assert bus.state is can.BusState.PASSIVE, f"unexpected state {bus.state}"
