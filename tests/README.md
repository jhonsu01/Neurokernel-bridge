# Testing

This directory contains the automated tests for the NeuroKernel Bridge project.

## Structure

The tests are organized into three main categories:

*   `unit/`: These are unit tests that verify the functionality of individual components in isolation. They do not require root privileges to run. They are further broken down by the component they test (e.g., `test_rules.py`, `test_executor.py`).

*   `integration/`: These tests verify the interaction between multiple components of the system.

*   `ebpf/`: This contains tests specifically for the eBPF sensor code. `test_sensor_compile.py` ensures that the `sensor.c` code compiles successfully using the BCC toolchain. These tests require root privileges to run.

## Running Tests

You can run all tests using `pytest`:

```bash
# Run all unit tests
pytest tests/unit/

# Run the eBPF compilation test (requires root)
sudo pytest tests/ebpf/
```
