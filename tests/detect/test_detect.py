import can
from time import monotonic


class TestDetect:
    """Device detection: mDNS discovery via python-can detect_available_configs.

    Note: mDNS discovery relies on inbound UDP port 5353. If a host firewall blocks it,
    no devices are detected and these tests fail.
    """

    def test_detect_available_configs(self, device_address):
        """The device under test is discovered, with (at least) channels 1 and 2."""

        start = monotonic()
        configs = can.detect_available_configs(interfaces=["cansub"])
        detect_time = monotonic() - start

        print(f"detect: {detect_time:.3f} s")
        assert detect_time < 3.0, f"detect took {detect_time:.3f} s"

        assert all(config["interface"] == "cansub" for config in configs)

        channels = [str(config["channel"]) for config in configs]
        assert f"{device_address}@1" in channels, f"channel 1 not detected ({channels})"
        assert f"{device_address}@2" in channels, f"channel 2 not detected ({channels})"
