import can


class TestPeriodic:
    """Periodic transmission (broadcast manager): device-side transmit sequences."""

    def test_send_periodic(self, bus_config):
        """Test that a periodic task with a duration transmits its frame sequence the expected
        number of times in order, and then stops by itself."""
        period = 0.1
        duration = 1.0

        messages = [
            can.Message(arbitration_id=0x321, is_extended_id=False, data=[1, 2]),
            can.Message(arbitration_id=0x321, is_extended_id=False, data=[3, 4]),
        ]

        with can.Bus(channel=1, **bus_config) as bus_rx, can.Bus(channel=2, **bus_config) as bus_tx:

            # Enable periodic transmission job (on the hardware device)
            bus_tx.send_periodic(messages, period=period, duration=duration)

            # Collect until the bus goes quiet (0.5 s without a message >> period)
            rx_msgs = list(iter(lambda: bus_rx.recv(timeout=0.5), None))

        # "period" is the frame spacing: duration / period frames in total - then the task stops
        print(f"received {len(rx_msgs)} messages")
        assert len(rx_msgs) == round(duration / period), f"received {len(rx_msgs)} messages"

        # The task cycles through the sequence in order
        for i, rx_msg in enumerate(rx_msgs):
            assert rx_msg.data == messages[i % len(messages)].data, f"unexpected payload at frame {i}"

        # The frames must be spaced "period" apart (device timestamps; ms scheduling resolution)
        spacings = [b.timestamp - a.timestamp for a, b in zip(rx_msgs, rx_msgs[1:])]
        print(f"frame spacing: min {min(spacings) * 1000:.3f} ms, max {max(spacings) * 1000:.3f} ms")
        assert all(abs(spacing - period) < 0.01 for spacing in spacings), \
            f"unexpected frame spacing: min {min(spacings):.6f} s, max {max(spacings):.6f} s"

    def test_restart(self, bus_config):
        """Test that a periodic task can be stopped and restarted."""
        with can.Bus(channel=1, **bus_config) as bus_rx, can.Bus(channel=2, **bus_config) as bus_tx:

            # Enable periodic transmission job (on the hardware device)
            task = bus_tx.send_periodic(
                can.Message(arbitration_id=0x321, is_extended_id=False, data=[1, 2]), period=0.1)
            assert isinstance(task, can.RestartableCyclicTaskABC)

            # Ensure the task is transmitting
            assert bus_rx.recv(timeout=1.0) is not None, "task not transmitting"

            # Stop the task and expect it to stop transmitting
            task.stop()
            quiet = False
            for _ in range(5):
                if bus_rx.recv(timeout=0.5) is None:
                    quiet = True
                    break
            assert quiet, "task still transmitting after stop"

            # After a restart, the messages must flow again
            task.start()
            assert bus_rx.recv(timeout=1.0) is not None, "task not transmitting after restart"

            task.stop()
