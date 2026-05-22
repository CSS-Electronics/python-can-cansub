import binascii
import can
from enum import IntEnum
from typing import Callable
from can.util import len2dlc, dlc2len

HDLC_BOUNDARY_BYTE = 0x7E
HDLC_ESCAPE_BYTE = 0x7D

MSG_ENCODE_ERR_HEADER_SIZE = 7
MSG_ENCODE_STD_HEADER_SIZE = 9   # 7 + 2
MSG_ENCODE_EXT_HEADER_SIZE = 11  # 7 + 4
MSG_ENCODE_HEADER_MIN_SIZE = MSG_ENCODE_ERR_HEADER_SIZE
MSG_ENCODE_HEADER_MAX_SIZE = MSG_ENCODE_EXT_HEADER_SIZE

# The encoded timestamp is offset by date 2025/01/01 00:00:00 UTC.
MSG_ENCODE_TIME_MIN = 1735689600
MSG_ENCODE_TIME_MAX = MSG_ENCODE_TIME_MIN + (0xFF_FF_FF_FF_FF_FF / 1_000_000)

class CanSubErrorFrameType(IntEnum):
    BIT = 0
    ACK = 1
    FORM = 2
    STUFF = 3
    CRC = 4
    OTHER = 0xFF

def cansub_protocol_encode(msg: can.Message, data: bytearray) -> bytes:
    """
    Encodes msg into data. Can be called multiple times to encode multiple messages in the same data buffer. The
    boundary bytes (start/stop), byte stuffing and, CRC32 will be updated to ensure that the frame in the data buffer
    is always valid.
    """

    # Encode the new message into message buffer
    msg_buf = message_encode(msg)

    # Default crc32 value
    crc32 = 0

    # Check if output buffer already contains a start boundary flag */
    if len(data) == 0:
        # No, add flag
        data.append(HDLC_BOUNDARY_BYTE)
    else:
        # Remove the current end boundary flag (such that more data can be added)
        boundary_flag_end = data.pop()
        if boundary_flag_end != HDLC_BOUNDARY_BYTE:
            raise ValueError("Unexpected boundary end flag")

        # Get current CRC (and remove from the end of buffer)
        # WARNING: The CRC bytes can be byte-stuffed and take up more than 4 bytes!
        for i in range(0, 4):

            if len(data) < 1:
                raise ValueError("Missing CRC32 bytes")

            # Get byte and check if byte before is escape byte
            byte = data.pop()
            if len(data) > 0 and (data[-1] == HDLC_ESCAPE_BYTE):
                # Yes, byte before is escape byte, de-stuff crc byte and remove escape byte
                byte ^= 0x20
                data.pop()

            # NOTE: Be aware that the CRC32 bytes are read from the end of the buffer!
            crc32 |= byte << (i * 8)

    # Update crc32 with new data
    crc32 = binascii.crc32(msg_buf, crc32)

    # Append CRC32 bytes to message buffer
    msg_buf.extend(crc32.to_bytes(4, "big"))

    # Add the new message to the persistent buffer while applying HDLC byte stuffing */
    for byte in msg_buf:

        # Check if bytestuffing in required
        if byte == HDLC_BOUNDARY_BYTE or byte == HDLC_ESCAPE_BYTE:
            # Insert escape byte
            data.append(HDLC_ESCAPE_BYTE)

            # Modify data byte with XOR 0x20
            byte ^= 0x20

        # Insert data byte
        data.append(byte)

    # Insert the boundary end flag
    data.append(HDLC_BOUNDARY_BYTE)

    return data

def cansub_protocol_decode(data: bytearray, msg_cb: Callable[[can.Message], None]) -> None:
    frames_decode(data, msg_cb)

def frames_decode(data: bytearray, msg_cb: Callable[[can.Message], None]) -> None:

    # Decode all frames in buffer
    while len(data) > 0:

        # Pre-decode length of buffer
        data_len_pre = len(data)

        # Decode single frame
        try:
            frame_decode(data, msg_cb)

            # Check if bytes consumed
            if len(data) == data_len_pre:
                # No, this is not an error. Just that we need more bytes to parse frame.
                break
        except Exception as e:
            # Some error. Bytes consumed?
            print(f"Error decoding frame {e}")
            if data_len_pre == len(data):
                # No, likely deadlock, reset buffer
                data = bytearray()
                break

def frame_decode(data: bytearray, msg_cb: Callable[[can.Message], None]) -> None:

    # Find boundary start
    frame_start = data.find(HDLC_BOUNDARY_BYTE)
    if frame_start < 0:
        # Boundary start byte should during normal operation always be present. However, this is not a hard fault.
        return

    # Find boundary end (starting from boundary_start + 1)
    frame_end = data.find(HDLC_BOUNDARY_BYTE, frame_start + 1)
    if frame_end < 0:
        # No boundary end, wait for more data. Zero bytes consumed
        return

    # Create frame containing byte-stuffed bytes without boundary flags
    frame = data[frame_start + 1:frame_end]

    # Consume frame bytes (including boundary flags)
    del data[:frame_end + 1]

    # Perform byte de-stuffing
    i_in = 0
    i_out = 0
    while i_in < len(frame):

        # Read one byte
        byte = frame[i_in]
        i_in += 1

        # Check if de-stuffing is required
        if byte == HDLC_ESCAPE_BYTE:
            # Yes, check that we have one more byte
            if i_in < len(frame):
                # Yes, de-stuff next byte
                byte = frame[i_in] ^ 0x20
                i_in += 1
            else:
                # No, this is an error
                raise ValueError("Frame stuffed byte missing")

        # Add de-stuffed byte to the output
        frame[i_out] = byte
        i_out += 1

    del frame[i_out:]

    # Check frame crc32
    if len(frame) < 4:
        raise ValueError("Frame CRC32 missing")

    crc32_expected = int.from_bytes(frame[-4:], "big")
    del frame[-4:]
    crc32_actual = binascii.crc32(frame)

    if crc32_expected != crc32_actual:
        raise ValueError("Frame CRC32 mismatch")

    # Decode message(s) in frame
    messages_decode(frame, msg_cb)

def messages_decode(data: bytearray, msg_cb: Callable[[can.Message], None]) -> None:

    # Decode all messages in buffer
    while len(data) > 0:
        # Pre-decode length of buffer
        data_len_pre = len(data)

        # Decode a single message
        try:
            message_decode(data, msg_cb)
            result = True
        except Exception as e:
            print(f"Error decoding message {e}")
            result = False
            break

        # If decode error or if zero bytes consumed, break
        if not result or data_len_pre == len(data):
            raise ValueError("Message decode error")

def message_decode(data: bytearray, msg_cb: Callable[[can.Message], None]) -> None:

    # Backup of len before bytes are removed
    data_len_orig = len(data)

    # Check minimum header
    if data_len_orig < MSG_ENCODE_HEADER_MIN_SIZE:
        raise ValueError("Not enough data to parse header")

    # Microseconds (48 bit)
    timestamp_us = int.from_bytes(data[:6], byteorder='big')
    timestamp = float(timestamp_us) / 1_000_000.0 + MSG_ENCODE_TIME_MIN
    del data[:6]

    # Flags
    flags = data[0]
    del data[0]

    # Error frame ?
    if (flags & 0xE0) != 0x20:

        # No, is data frame
        if data_len_orig < MSG_ENCODE_STD_HEADER_SIZE:
            raise ValueError("Not enough data to parse header")

        # Frame format
        is_fdf = bool(flags & 0x80)

        if not is_fdf:
            is_rtr = bool(flags & 0x40)
            is_brs = False
            is_esi = False
        else:
            is_rtr = False
            is_brs = bool(flags & 0x40)
            is_esi = bool(flags & 0x20)

        # Get TX (note, logic reversed)
        is_rx = not bool(flags & 0x10)

        # DLC
        dlc = flags & 0x0F

        # Is extended ID?
        is_extended_id = bool(data[0] & 0x80)

        # Arbitration ID
        if not is_extended_id:
            # Regular ID
            if len(data) < 2:
                raise ValueError("Not enough data to parse STD ID")
            arbitration_id = int.from_bytes(bytes(data[:2]), byteorder='big') & 0x7FF
            del data[:2]
        else:
            # Extended ID
            if len(data) < 4:
                raise ValueError("Not enough data to parse EXT ID")
            arbitration_id = int.from_bytes(bytes(data[:4]), byteorder='big') & 0x1FFFFFFF
            del data[:4]

        # Payload
        payload = b""
        if not is_rtr:
            payload_len = dlc2len(dlc)
            if len(data) >= payload_len:
                payload = data[:payload_len]
                del data[:payload_len]
            else:
                raise ValueError("Not enough data bytes for payload")

        msg = can.Message(timestamp=timestamp,
                          channel=None,
                          is_rx=is_rx,
                          arbitration_id=arbitration_id,
                          is_extended_id=is_extended_id,
                          is_remote_frame=is_rtr,
                          is_fd=is_fdf,
                          bitrate_switch=is_brs,
                          error_state_indicator=is_esi,
                          # Note: python-can stores actual byte length in Message.dlc
                          dlc=dlc2len(dlc) if is_rtr else len(payload),
                          data=payload,
                          check=True,
        )
        # Invoke callback
        msg_cb(msg)

    else:
        # Yes, is error frame. Store the error code in the arbitration ID (like the python-can socketcan implementation)
        error_type_val = flags & 0x1F

        # Map error type to enum value, default to OTHER if unknown
        try:
            error_type = CanSubErrorFrameType(error_type_val)
        except ValueError:
            error_type = CanSubErrorFrameType.OTHER

        msg = can.Message(timestamp=timestamp,
                          channel=None,
                          arbitration_id=int(error_type),
                          is_error_frame=True,
                          check=True,
        )
        # Invoke callback
        msg_cb(msg)


def message_encode(message: can.Message) -> bytearray:

    if message.is_error_frame:
        raise ValueError("Encoding of error frames not supported")

    buffer = bytearray()

    # Microseconds since 00:00:00 01/01/2025 UTC (48 bit)
    timestamp_us = 0
    if (message.timestamp is not None ) and (MSG_ENCODE_TIME_MAX >= message.timestamp >= MSG_ENCODE_TIME_MIN):
        timestamp_us = int((message.timestamp - MSG_ENCODE_TIME_MIN) * 1_000_000)
    buffer.extend(timestamp_us.to_bytes(6, byteorder='big'))

    # Note: python-can stores actual byte length in Message.dlc
    dlc = len2dlc(len(message.data)) if not message.is_remote_frame else len2dlc(message.dlc)

    # fd (1 bit), rtr/brs (1 bit), 0/esi (1 bit), tx (1 bit), dlc (4 bit)
    flags = 0
    flags |= 0x80 if message.is_fd else 0x00
    if not message.is_fd:
        flags |= 0x40 if message.is_remote_frame else 0x00
    else:
        flags |= 0x40 if message.bitrate_switch else 0x00
        flags |= 0x20 if message.error_state_indicator else 0x00
    flags |= 0x10 if not message.is_rx else 0x00
    flags |= dlc & 0x0F
    buffer.append(flags)

    # ID (11 or 29 bit). Note: MSb set if extended ID.
    if not message.is_extended_id:
        arbitration_id = bytearray((message.arbitration_id & 0x7FF).to_bytes(2, byteorder='big'))
    else:
        arbitration_id = bytearray(((message.arbitration_id & 0x1FFFFFFF) | 0x80000000).to_bytes(4, byteorder='big'))
    buffer.extend(arbitration_id)

    # Payload (omit for RTR)
    if not message.is_remote_frame:
        buffer.extend(message.data)

    return buffer
