# Tests

Smoke tests of python-can-cansub.

## Requirements

- A CANsub device connected (USB or ethernet)
- All channels are wired together on the same physical bus (CAN-H/CAN-L, terminated)

## Running

```bash
pytest --address aabbccdd-usb.local
```
