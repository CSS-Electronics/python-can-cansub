import can


class TestFilters:
    """Hardware acceptance filters"""

    def test_filter(self, bus_config):
        """Test of message acceptance filters

        1. Set up a filter when opening the bus
        2. Read back the filter
        3. Send a message that should be rejected
        4. Send a message that should be accepted
        5. Receive the accepted message
        6. Change the filters on the open bus
        7. Read back the filters
        8. Send a message that should be rejected
        9. Send a message that should be accepted
        10. Receive the accepted message

        that only messages matching a filter are received, and that the other message
        is rejected - both for filters set when opening the bus (can_filters) and for filters
        changed on the open bus (the bus.filters property). The applied filters must also read
        back through bus.filters."""

        can_filters = [{"can_id": 0x100, "can_mask": 0x7FF, "extended": False}]

        # 1. Open bus with filters
        with (can.Bus(channel=1, can_filters=can_filters, **bus_config) as bus_rx,
              can.Bus(channel=2, **bus_config) as bus_tx):

            # 2. Read back the filters
            assert bus_rx.filters == can_filters

            # 3. Send a message that should be rejected
            bus_tx.send(can.Message(arbitration_id=0x200, is_extended_id=False, data=[1]))

            # 4. Send a message that should be accepted
            bus_tx.send(can.Message(arbitration_id=0x100, is_extended_id=False, data=[2]))

            # 5. Receive the accepted message
            rx = bus_rx.recv(timeout=2.0)
            assert rx is not None, "matching message not received"
            assert rx.arbitration_id == 0x100
            assert bus_rx.recv(timeout=0.5) is None, "unexpected extra message received"

            # 6. Change the filters on the open bus
            new_filters = [{"can_id": 0x200, "can_mask": 0x7FF, "extended": False}]
            bus_rx.filters = new_filters

            # 7. Read back the (changed) filters
            assert bus_rx.filters == new_filters

            # 8. Send a message that should be rejected
            bus_tx.send(can.Message(arbitration_id=0x100, is_extended_id=False, data=[3]))

            # 9. Send a message that should be accepted
            bus_tx.send(can.Message(arbitration_id=0x200, is_extended_id=False, data=[4]))

            # 10. Receive the accepted message
            rx = bus_rx.recv(timeout=2.0)
            assert rx is not None, "matching message not received after filter change"
            assert rx.arbitration_id == 0x200
            assert bus_rx.recv(timeout=0.5) is None, "unexpected extra message received after filter change"
