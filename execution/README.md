# Execution Layer

This directory contains the core logic for the NeuroKernel Bridge. It is responsible for the "Execution" layer (Layer 3) in the system's 4-layer architecture. This involves all deterministic, heavy-lifting work.

## Components

*   `sensor.c`: This is the eBPF sensor code written in C. It contains the kernel probes (`kprobes`) that are attached to various syscalls to monitor system activity in real-time. The probes are compiled Just-In-Time (JIT) by the BCC library.

*   `orchestrator/`: This Python package is the heart of the user-space application. It orchestrates the entire process from receiving events from the kernel to making decisions and taking actions.
    *   `main.py`: The main entry point for the application. It initializes all components and starts the event loop.
    *   `sensors/`: Handles loading the eBPF program (`sensor.c`) and managing the perf buffer that receives data from the kernel.
    *   `decision/`: Contains the 3-tier decision engine (Rules, Cache, LLM).
    *   `actions/`: Responsible for executing actions based on decisions (e.g., terminating or renicing a process).
    *   `batching/`: Collects and batches events from the kernel for more efficient processing.
    *   `config.py`: Manages configuration loaded from `.env` files.
    *   `models.py`: Defines the Pydantic data models for events and decisions.
