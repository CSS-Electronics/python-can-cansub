"""
Hardware test fixtures. The tests run against a real CANsub device (see README.md).
"""
import pytest
import python_can_cansub.cansub
import requests
import urllib3
from pathlib import Path
from time import monotonic, sleep


def pytest_addoption(parser):
    parser.addoption("--address", action="store", default=None,
                     help="CANsub device address (hostname), e.g. 1b5b9343-usb.local. Required.")
    parser.addoption("--server-cert", action="store", default=None,
                     help="Path to a server root certificate (.crt), replacing the built-in "
                          "CANsub root certificate.")

@pytest.fixture(scope="session")
def device_address(request) -> str:
    """The address (hostname) of the device under test."""
    address = request.config.getoption("--address")
    if not address:
        pytest.fail("--address is required, e.g.: pytest --address 1b5b9343-usb.local", pytrace=False)
    return address

@pytest.fixture(scope="session", autouse=True)
def server_certificate(request):
    """Replace the built-in root certificate when --server-cert is given."""
    server_cert = request.config.getoption("--server-cert")
    if server_cert is None:
        yield
        return

    server_cert = Path(server_cert).resolve()
    if not server_cert.is_file():
        pytest.fail(f"Server certificate not found: {server_cert}", pytrace=False)

    # Patch the module
    original = python_can_cansub.cansub.CANSUB_ROOT_CERT
    python_can_cansub.cansub.CANSUB_ROOT_CERT = server_cert
    yield
    python_can_cansub.cansub.CANSUB_ROOT_CERT = original

@pytest.fixture(scope="session")
def bus_config(device_address) -> dict:
    """Common can.Bus keyword arguments for the device under test (override per call)."""
    return {
        "interface": "cansub",
        "address": device_address,
        "bitrate": 1_000_000,
        "data_bitrate": 1_000_000,
    }

@pytest.fixture(autouse=True)
def device_reset(device_address):
    """Reboot the device before each test, such that every test starts from a known device state."""

    # Disable TLS verification warning
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # Request the reboot
    response = requests.post(f"https://{device_address}/api/reboot", verify=False, timeout=5.0)
    assert response.status_code == 202

    # Wait a bit for the device to reboot
    sleep(1.0)

    # Poll until the device is up and ready
    deadline = monotonic() + 30.0
    while monotonic() < deadline:
        try:
            if requests.get(f"https://{device_address}/api/version", verify=False, timeout=2.0).status_code == 200:
                break
        except requests.exceptions.RequestException:
            pass
        sleep(0.5)
    else:
        pytest.fail("Device did not come back up after reboot.")
