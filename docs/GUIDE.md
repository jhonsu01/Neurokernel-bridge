# NeuroKernel Bridge - User and Technical Guide

A practical guide with instructions for installation, configuration, execution, and examples for the kernel security monitor.

---

## Table of Contents

1.  [System Architecture](#1-system-architecture)
2.  [System Requirements](#2-system-requirements)
3.  [Installation](#3-installation)
4.  [Configuration](#4-configuration)
5.  [Telegram Integration](#5-telegram-integration)
6.  [Execution](#6-execution)
7.  [Operating Modes](#7-operating-modes)
8.  [Reading Logs](#8-reading-logs)
9.  [Troubleshooting](#9-troubleshooting)

---

## 1. System Architecture

The system is a HIDS/HIPS-type security monitor that combines kernel-level eBPF probes with a 3-tier decision engine (deterministic rules, vector cache, and AI via an LLM API) to detect and respond to threats in real-time.

```
                    ┌──────────────────────────────────────────┐
                    │           LINUX KERNEL (eBPF)            │
                    │                                          │
                    │  Probes → Dimensions → Perf Buffers      │
                    └────────────────┬─────────────────────────┘
                                     │ perf_buffer_poll (100ms)
                                     ▼
                    ┌──────────────────────────────────────────┐
                    │         BATCH COLLECTOR (Python)         │
                    │    window: 1s | max: 50 events/batch     │
                    └────────────────┬─────────────────────────┘
                                     │
                                     ▼
              ┌─────────────────────────────────────────────────────┐
              │              DECISION ENGINE (3 tiers)              │
              │                                                     │
              │  Tier 1: RULES ──→ ~0ms, deterministic              │
              │     │                                               │
              │     └─ miss ──→ Tier 2: CACHE ──→ ~1-5ms, SQLite    │
              │                    │                                │
              │                    └─ miss ──→ Tier 3: LLM ──→      │
              │                                  500-2000ms, API    │
              └────────────────────┬────────────────────────────────┘
                                   │
                                   ▼
              ┌─────────────────────────────────────────────────────┐
              │              ACTION EXECUTOR                       │
              │                                                     │
              │  SAFE       → log debug                             │
              │  LIMIT      → renice +15                            │
              │  MALICIOUS  → SIGTERM (if not protected)            │
              │                                                     │
              │  Guards: dry_run | protected_procs | confidence<0.8  │
              └─────────────────────────────────────────────────────┘
```

### Monitoring Dimensions

The eBPF sensor (`execution/sensor.c`) intercepts multiple dimensions of kernel activity:

| Dimension | Probe | What it Detects |
|---|---|---|
| **Exec** | `trace_execve` | Execution of new processes |
| **File** | `trace_openat2` | File openings (rate-limited) |
| **Network** | `trace_tcp_connect`, `trace_tcp_accept`, etc. | Network connections |
| **Suspicious** | `trace_mmap_exec`, `trace_module_load`, etc. | Potentially malicious syscalls |

### 3-Tier Decision Engine

*   **Tier 1: Deterministic Rules (~0ms):** Pure Python pattern matching for immediate classification of known safe or malicious events (e.g., accessing `/etc/shadow`).
*   **Tier 2: Vector Cache (~1-5ms):** An SQLite database with n-gram embeddings that stores previous Tier 3 decisions for fast lookups based on cosine similarity.
*   **Tier 3: LLM Inference (500-2000ms):** For ambiguous events, it consults a Large Language Model for contextual analysis.

---

## 2. System Requirements

### Hardware

-   x86_64 Architecture
-   Minimum RAM: 512MB available

### Software

| Requirement | Minimum Version | Check with |
|---|---|---|
| Linux kernel | 4.15+ (5.x+ recommended) | `uname -r` |
| Python | 3.10+ | `python3 --version` |
| BCC (BPF Compiler Collection) | 0.25+ | `dpkg -l \| grep bpfcc` |
| Kernel headers | Same as kernel | `ls /usr/src/linux-headers-$(uname -r)` |
| Root privileges | Required | `sudo whoami` |

---

## 3. Installation

### Step 1: Install System Dependencies (Ubuntu/Debian)
```bash
sudo apt update
sudo apt install -y bpfcc-tools linux-headers-$(uname -r) python3-bpfcc
```

### Step 2: Install Python Dependencies
```bash
# It is recommended to use a virtual environment
python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
```

### Step 3: Configure the Environment
```bash
cp .env.example .env
```
Edit the `.env` file and set the `ANTHROPIC_API_KEY` for full functionality.

### Step 4: Verify Installation
```bash
# Run unit tests (do not require root)
pytest tests/unit/ -v

# Verify that the sensor compiles (requires root)
sudo pytest tests/ebpf/ -v
```

---
## 4. Configuration

All environment variables in the `.env` file use the `LIAK_` prefix (except `ANTHROPIC_API_KEY`).

| Variable | Default | Description |
|---|---|---|
| `ANTHROPIC_API_KEY` | — | API key for Tier 3 decisions. |
| `LIAK_DRY_RUN` | `true` | If `true`, runs in observation-only mode. |
| `LIAK_ANTHROPIC_MODEL` | `claude-3-sonnet-20240229` | The LLM used for Tier 3. |
| `LIAK_MAX_API_CALLS_PER_MINUTE`| `20` | Rate limit for the API to control costs. |
| `LIAK_SIMILARITY_THRESHOLD` | `0.85` | Similarity score needed for a Tier 2 cache hit. |
| `LIAK_LOG_LEVEL` | `INFO` | Logging verbosity (e.g., DEBUG, INFO, WARNING). |


You can override any variable from the command line:
```bash
LIAK_LOG_LEVEL=DEBUG sudo -E python3 execution/orchestrator/main.py
```

---

## 5. Telegram Integration

NeuroKernel Bridge can integrate with a Telegram bot to send real-time security alerts and allow for remote administration via chat commands.

### Configuration

To enable the bot, you need to provide a bot token and your chat ID in the `.env` file.

1.  **Create a Bot**: Talk to `@BotFather` on Telegram and follow the instructions to create a new bot. You will receive a unique token.
2.  **Get your Chat ID**: After starting your bot, send it a message. Then, open your browser and go to `https://api.telegram.org/bot<YOUR_TOKEN>/getUpdates`. Look for the `result.message.chat.id` field in the JSON response.
3.  **Set Environment Variables**: Add the following variables to your `.env` file:
    ```env
    TELEGRAM_BOT_TOKEN=your-token-from-botfather
    TELEGRAM_CHAT_ID=your-chat-id
    ```

The bot will connect automatically when you start the main orchestrator.

### Available Commands

All commands are restricted to the configured `TELEGRAM_CHAT_ID`.

*   `/help` or `/start`: Displays the list of available commands.
*   `/status`: Shows the current monitor status, including uptime, processed events, and decision statistics.
*   `/home`: Lists the contents of the home directory of the user running the script.
*   `/ls <path>`: Lists the contents of the specified directory path.
*   `/cat <path>`: Reads the first 50 lines of a specified file.
*   `/mkdir <path>`: Creates a new directory.
*   `/touch <path>`: Creates a new empty file.
*   `/cmd <command>`: Executes a shell command. **Use with extreme caution.** For example, to shut down the computer, you could use: `/cmd shutdown now`. Any other shell command can be executed in the same way.

For security reasons, direct commands like `/shutdown`, `/reboot`, and `/logout` are disabled. However, the same functionality can be achieved using the `/cmd` command (e.g., `/cmd shutdown now`).

---

## 6. Execution

### Start the Monitor
```bash
sudo -E python3 execution/orchestrator/main.py
```
You should see a startup banner confirming the monitor is active.

### Stop the Monitor
Press `Ctrl+C` once for a graceful shutdown.

---
## 7. Operating Modes

### DRY-RUN (Default)
The monitor observes and classifies all events but **takes no action**. It is ideal for initial setup and verifying for false positives. Logs will show what the monitor *would have* done (e.g., `dry_run_would_block`).

### ACTIVE (Enforcement)
The monitor takes real actions:
-   **MALICIOUS** (confidence >= 0.8) → Sends `SIGTERM` to the process.
-   **LIMIT** → Lowers the process priority using `renice`.
-   **SAFE** → Logs the event only.

Enable this mode by setting `LIAK_DRY_RUN=false` in your `.env` file or on the command line.

---
## 8. Reading Logs

Logs are written in JSONL format to `logs/orchestrator.jsonl`. Each line is a JSON object representing an event.

### Log Event Structure
```json
{
  "dimension": "FILE",
  "decision": "SAFE",
  "confidence": 0.95,
  "comm": "konsole",
  "pid": 46990,
  "event": "tier1_decision",
  "level": "info",
  "timestamp": "2026-02-05T22:38:16.482702Z"
}
```

### Analysis
You can use standard command-line tools like `grep`, `sort`, `uniq -c`, and `jq` to analyze the logs.

**Key events to look for:**
-   `"decision": "MALICIOUS"`: An event classified as a threat.
-   `"event": "process_blocked"`: A process that was terminated by the monitor.
-   `"event": "dry_run_would_block"`: A process that would have been terminated if `DRY_RUN` was `false`.
-   `"event": "tier3_decision"`: An event that required an API call, indicating a novel or ambiguous event.

A healthy system should have very few `MALICIOUS` or `process_blocked` events in the logs.

---

## 9. Troubleshooting

### Error: "This program requires root privileges"
The eBPF probes require root access. Run the command with `sudo`.

### Error: "Cannot attach BPF probe"
This usually means the kernel headers do not match the running kernel. Ensure you have the correct headers installed.

### High API Usage
If you see too many `tier3_decision` events, it means many events are novel. You can:
-   Lower the `LIAK_SIMILARITY_THRESHOLD` to get more cache hits.
-   Reduce the `LIAK_MAX_API_CALLS_PER_MINUTE` to control costs (ambiguous events will default to SAFE).

### Legitimate Process Flagged
If a safe process is being flagged, you can add it to the `whitelisted_procs` list in the configuration (`execution/orchestrator/config.py`).
