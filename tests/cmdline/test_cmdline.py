import can
import pytest
import signal
import subprocess
import sys
from pathlib import Path
from python_can_cansub import CanSubCSVReader, CanSubCSVWriter
from time import sleep


def tool_command(name: str) -> str:
    """Path to a python-can console script (installed next to the interpreter)."""
    return str(Path(sys.executable).with_name(name))


@pytest.fixture()
def bus_arguments(bus_config) -> list:
    """Command line equivalent of bus_config (the channel is appended per test)."""
    return ["--interface", bus_config["interface"],
            "--bitrate", str(bus_config["bitrate"]),
            "--data-bitrate", str(bus_config["data_bitrate"])]


@pytest.mark.skipif(sys.platform == "win32", reason="cmdline tests are not Windows compatible")
@pytest.mark.skipif("config.getoption('--server-cert')",
                    reason="Command line tool tests do not support the --server-cert option")
class TestCmdline:
    """python-can command line tools (see "python-can tools" in the package README)."""

    def test_can_logger(self, bus_config, bus_arguments, tmp_path):
        """
        Test that can_logger logs received frames to a CSV file.
        """
        log_path = tmp_path / "log.csv"
        msg_nof = 10

        logger_process = subprocess.Popen(
            [tool_command("can_logger"),
             "--channel", f"{bus_config['address']}@1",
             *bus_arguments,
             "--file_name", str(log_path)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            # Allow the tool to start up and open the bus (the startup time varies)
            sleep(5.0)
            assert logger_process.poll() is None, \
                f"can_logger exited early: {logger_process.communicate()[1]}"

            # Transmit; the bus close flushes, so everything is on the wire afterwards
            with can.Bus(channel=2, **bus_config) as bus_tx:
                for i in range(msg_nof):
                    bus_tx.send(can.Message(arbitration_id=i, is_extended_id=False, data=[1, 2]), timeout=5)

            # Allow the frames to reach the logger process
            sleep(1.0)
        finally:
            # Ctrl-C: the tool closes the bus and the log file
            logger_process.send_signal(signal.SIGINT)
            try:
                logger_process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                logger_process.kill()

        # Read back with the CanSub CSV reader explicitly: verifies that the command line tool
        # wrote the CanSub CSV format (any other format parses to no messages)
        with CanSubCSVReader(str(log_path)) as reader:
            logged_ids = [msg.arbitration_id for msg in reader]
        assert logged_ids == list(range(msg_nof))

    def test_can_logger_filter(self, bus_config, bus_arguments, tmp_path):
        """
        Test the can_logger --filter argument: the filter carries no id type, so a matching id
        is accepted as both standard and extended - other ids are blocked.
        """
        log_path = tmp_path / "log.csv"

        logger_process = subprocess.Popen(
            [tool_command("can_logger"),
             "--channel", f"{bus_config['address']}@1",
             *bus_arguments,
             "--filter", "100:7FF",
             "--file_name", str(log_path)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            # Allow the tool to start up and open the bus (the startup time varies)
            sleep(5.0)
            assert logger_process.poll() is None, \
                f"can_logger exited early: {logger_process.communicate()[1]}"

            with can.Bus(channel=2, **bus_config) as bus_tx:
                bus_tx.send(can.Message(arbitration_id=0x200, is_extended_id=False, data=[1]), timeout=5)
                bus_tx.send(can.Message(arbitration_id=0x100, is_extended_id=False, data=[2]), timeout=5)
                bus_tx.send(can.Message(arbitration_id=0x100, is_extended_id=True, data=[3]), timeout=5)

            # Allow the frames to reach the logger process
            sleep(1.0)
        finally:
            # Ctrl-C: the tool closes the bus and the log file
            logger_process.send_signal(signal.SIGINT)
            try:
                logger_process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                logger_process.kill()

        # Only the matching id must be logged, once per id type, in transmit order
        with CanSubCSVReader(str(log_path)) as reader:
            logged = [(msg.arbitration_id, msg.is_extended_id) for msg in reader]
        assert logged == [(0x100, False), (0x100, True)], f"unexpected filter result: {logged}"

    def test_can_player(self, bus_config, bus_arguments, tmp_path):
        """
        Test that can_player replays a CSV log file onto the bus.

        --channel-filter selects the recorded channel to replay, independently of the channel played back on.
        """
        log_path = tmp_path / "log.csv"
        msg_nof = 10
        channel_filter = 1

        # Simulate log-file. Even ids recorded on channel 1, odd ids on channel 2.
        messages = [can.Message(timestamp=i * 0.01, channel=1 + (i % 2), arbitration_id=i,
                                is_extended_id=False, data=[i], is_rx=True)
                    for i in range(msg_nof)]
        with CanSubCSVWriter(str(log_path)) as logger:
            for msg in messages:
                logger(msg)

        # Open bus 1 to receive the replayed frames
        with can.Bus(channel=1, **bus_config) as bus_rx:

            # Start the player on channel 2, filtering on channel 1
            result = subprocess.run(
                [tool_command("can_player"),
                 "--channel", f"{bus_config['address']}@2",
                 *bus_arguments,
                 f"--channel-filter={channel_filter}",
                 str(log_path)],
                capture_output=True, text=True, timeout=60)
            assert result.returncode == 0, f"can_player failed: {result.stderr}"

            # Read replayed frames
            rx_ids = [msg.arbitration_id for msg in iter(lambda: bus_rx.recv(timeout=1.0), None)]

        # Only the frames recorded on the filtered channel are replayed (on channel 2)
        expected_ids = [msg.arbitration_id for msg in messages if msg.channel == channel_filter]
        assert rx_ids == expected_ids
