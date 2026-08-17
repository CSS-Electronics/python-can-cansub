import can
import subprocess
import sys
from datetime import datetime
from python_can_cansub import CanSubCSVReader, CanSubCSVWriter

# Static reference CSV and the messages it represents (format reference: cCsvConverter.c)
REFERENCE_CSV = (
    "TimestampEpoch;BusChannel;ID;IDE;DLC;DataLength;Dir;EDL;BRS;ESI;RTR;DataBytes\n"
    "1670926807.419500;1;000;0;1;1;0;0;0;0;0;AA\n"
    "1670926807.419700;1;7FF;0;8;8;0;0;0;0;0;AAAAAAAAAAAAAAAA\n"
    "1670926807.419900;1;00000000;1;9;12;0;1;1;0;0;AAAAAAAAAAAAAAAAAAAAAAAA\n"
    "1670926807.420100;1;1FFFFFFF;1;15;64;0;1;1;0;0;"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
)
REFERENCE_MESSAGES = [
    can.Message(timestamp=1670926807.419500, channel=1, arbitration_id=0x000,
                is_extended_id=False, data=bytes([0xAA] * 1), is_rx=True),
    can.Message(timestamp=1670926807.419700, channel=1, arbitration_id=0x7FF,
                is_extended_id=False, data=bytes([0xAA] * 8), is_rx=True),
    can.Message(timestamp=1670926807.419900, channel=1, arbitration_id=0x00000000,
                is_extended_id=True, data=bytes([0xAA] * 12), is_rx=True, is_fd=True, bitrate_switch=True),
    can.Message(timestamp=1670926807.420100, channel=1, arbitration_id=0x1FFFFFFF,
                is_extended_id=True, data=bytes([0xAA] * 64), is_rx=True, is_fd=True, bitrate_switch=True),
]


class TestCsvLogger:
    """pyton-can-cansub CSV logger"""

    def test_csv_plugin_selection(self, tmp_path):
        """Test that can.Logger / can.LogReader automatically select the CanSub CSV writer and
        reader for .csv files.

        Run in a fresh interpreter that never imports python_can_cansub: python-can's entry-point
        loading must import the package, whose init overrides the builtin csv handler.
        """
        log_path = tmp_path / "log.csv"
        code = (
            "import can\n"
            f"with can.Logger({str(log_path)!r}) as logger:\n"
            "    print(type(logger).__name__)\n"
            f"with can.LogReader({str(log_path)!r}) as reader:\n"
            "    print(type(reader).__name__)\n"
        )

        result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
        assert result.returncode == 0, f"subprocess failed: {result.stderr}"
        print(result.stdout)
        assert result.stdout.split() == ["CanSubCSVWriter", "CanSubCSVReader"]

    def test_csv_read_reference(self, tmp_path):
        """Test that the reader parses the static reference CSV to the expected messages."""
        log_path = tmp_path / "reference.csv"
        log_path.write_text(REFERENCE_CSV)

        with can.LogReader(str(log_path)) as reader:
            msgs = list(reader)

        assert len(msgs) == len(REFERENCE_MESSAGES), f"parsed {len(msgs)} messages"
        for msg, reference in zip(msgs, REFERENCE_MESSAGES):
            assert msg.equals(reference, timestamp_delta=None), f"mismatch: {msg} != {reference}"

    def test_csv_read_rtr(self, tmp_path):
        """Test that RTR rows map correctly to can.Message.
        - CSV format: "DLC" is the raw DLC. "DataLength" is the interpreted raw DLC (e.g. 8->8, 9->12) - also for RTR.
        - can.Message: "DLC" is the interpreted raw DLC (e.g. 8->8, 9->12).

        NOTE: RTR frames are well suited for testing if the mapping between CSV and can.Message is correct.
        """
        log_path = tmp_path / "rtr.csv"
        log_path.write_text(
            "TimestampEpoch;BusChannel;ID;IDE;DLC;DataLength;Dir;EDL;BRS;ESI;RTR;DataBytes\n"
            "1670926807.419500;1;722;0;4;4;0;0;0;0;1;\n"
        )

        with can.LogReader(str(log_path)) as reader:
            msgs = list(reader)

        assert len(msgs) == 1, f"parsed {len(msgs)} messages"
        for msg in msgs:
            assert msg.is_remote_frame is True
            assert msg.dlc == 4
            assert msg.data == b""

    def test_csv_write_reference(self, tmp_path):
        """Test that the writer reproduces the static reference CSV exactly."""
        log_path = tmp_path / "log.csv"

        with can.Logger(str(log_path)) as logger:
            for msg in REFERENCE_MESSAGES:
                logger(msg)

        assert log_path.read_text() == REFERENCE_CSV

    def test_csv_roundtrip(self, tmp_path):
        """Test that messages written to CSV read back identically."""
        log_path = tmp_path / "log.csv"

        # Values exactly representable at the 6-decimal CSV timestamp resolution
        timestamp = datetime(2026, 1, 1, 12, 00, 00, microsecond=500000).timestamp()

        messages = [
            can.Message(timestamp=timestamp,        channel=2, arbitration_id=0x123, is_extended_id=False, data=[1, 2, 3], is_rx=False),
            can.Message(timestamp=timestamp + 0.1,  channel=2, arbitration_id=0x456, is_extended_id=False, is_remote_frame=True, dlc=4, is_rx=True),
            can.Message(timestamp=timestamp + 0.2,  channel=2, arbitration_id=0x789, is_extended_id=False, data=bytes(5), is_rx=True, is_fd=True, error_state_indicator=True),
        ]

        # Write messages to CSV
        with can.Logger(str(log_path)) as logger:
            assert isinstance(logger, CanSubCSVWriter)
            for msg in messages:
                logger(msg)

        # Print CSV for debugging
        with open(log_path, "r") as f:
            print(f.read())

        # Read messages back from CSV
        with can.LogReader(str(log_path)) as reader:
            assert isinstance(reader, CanSubCSVReader)
            read_back = list(reader)

        assert len(read_back) == len(messages), f"read {len(read_back)} messages"
        for actual, expected in zip(read_back, messages):
            assert actual.equals(expected, timestamp_delta=None), f"mismatch: {actual} != {expected}"
