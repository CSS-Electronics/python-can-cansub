import logging
import warnings
import can
from typing import Union, Any, Generator
from can.io.generic import TextIOMessageWriter, TextIOMessageReader

logger = logging.getLogger("can.cansub")

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
                bus_channel,                                #  1: BusChannel
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
                # Channel: int when numeric (native CanSub logs), otherwise kept as a string
                # (logs written from other python-can buses, e.g. "vcan0")
                channel = columns[1] or None
                if channel is not None:
                    try:
                        channel = int(channel)
                    except ValueError:
                        pass
                # Perform channel filtering if enabled
                if channel is not None and self.channel_filter is not None:
                    if str(channel) != self.channel_filter:
                        continue
                    # Clear channel field (better compatibility with python-can commandline tools)
                    channel = None
                data_length = int(columns[5])
                is_remote_frame = columns[10] == "1"
                data = bytes.fromhex(columns[11])

                # Validate the explicit byte count against the payload (RTR frames carry none)
                if not is_remote_frame and data_length != len(data):
                    logger.warning("Skipping CSV row with inconsistent DataLength (%d != %d payload bytes)",
                                   data_length, len(data))
                    continue

                yield can.Message(
                    timestamp=float(columns[0]),                        #  0: TimestampEpoch
                    channel=channel,                                    #  1: BusChannel (None when channel_filter is set)
                    arbitration_id=int(columns[2], 16),                 #  2: ID
                    is_extended_id=columns[3] == "1",                   #  3: IDE
                                                                        #  4: DLC not mapped (derived: len2dlc(DataLength))
                    dlc=data_length,                                    #  5: DataLength (NOTE: python-can stores LEN in DLC)
                    is_rx=columns[6] == "0",                            #  6: Dir
                    is_fd=columns[7] == "1",                            #  7: EDL
                    bitrate_switch=columns[8] == "1",                   #  8: BRS
                    error_state_indicator=columns[9] == "1",            #  9: ESI
                    is_remote_frame=is_remote_frame,                    # 10: RTR
                    data=data                                           # 11: DataBytes
                )
            except (ValueError, IndexError):
                logger.warning("Skipping unparsable CSV row: %r", line)
                continue

        self.stop()