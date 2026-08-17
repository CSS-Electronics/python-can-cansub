from can.io.logger import MESSAGE_WRITERS
from can.io.player import MESSAGE_READERS

from .cansub_protocol import CanSubErrorFrameType
from .cansub import CANSUB_ROOT_CERT, CanSub, CanSubHwFilter
from .cansub_csv import CanSubCSVWriter, CanSubCSVReader

# Override the default python-can CSV writer/reader with the webCAN-compatible ones.
# NOTE: The forced assignment is required: the python-can entry-point plugin loading skips
# suffixes that already have a builtin handler (".csv" has), so the entry points declared in
# pyproject.toml cannot override it themselves. They still matter - loading them makes
# python-can import this package (running this override) even when the user never does.
MESSAGE_WRITERS[".csv"] = CanSubCSVWriter
MESSAGE_READERS[".csv"] = CanSubCSVReader