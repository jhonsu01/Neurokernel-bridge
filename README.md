# NeuroKernel Bridge: A RAG-driven Orchestrator for Linux

## Abstract

NeuroKernel Bridge is an advanced infrastructure framework that implements a "User-Space Governance over Kernel-Space Events" paradigm. By integrating eBPF (Extended Berkeley Packet Filter) dynamic probes with a RAG (Retrieval-Augmented Generation) architecture, the system provides the Linux kernel with a persistent "immunological memory." Unlike traditional security systems based on static signatures, NeuroKernel Bridge utilizes a three-tier inference engine to evaluate the semantics of system calls in real-time, enabling autonomous responses such as resource throttling (renice) or process termination (SIGKILL) based on historical context and probabilistic reasoning.

---

## Core Philosophy

LLMs are probabilistic; business logic is deterministic. This architecture addresses this mismatch by delegating execution to reliable code, allowing the AI agent to focus on **intelligent decision-making**.

The core problem with multi-step AI operations is probabilistic degradation:
`Accuracy per step: 90% × 90% × 90% × 90% × 90% = 59% success rate`

The solution is to push complexity towards deterministic code and leverage a persistent, semantic memory system to retain context across sessions.

---

## 4-Layer Architecture

| Layer | Name | Responsibility | Location |
|---|---|---|---|
| 1 | **Directive** | What to do (High-level goals in natural language) | `directives/` |
| 2 | **Orchestration** | Decision-making (The AI Agent) | - |
| 3 | **Execution** | Deterministic, heavy-lifting work | `execution/` |
| 4 | **Memory** | Cross-session context persistence (RAG) | `system_memory/` & `claude-mem-main/` |

**Fundamental Principle:** The agent never executes business logic directly. It delegates heavy work to Python scripts (`execution/`) and uses the memory system to maintain context.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           4-LAYER ARCHITECTURE                          │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  LAYER 1: DIRECTIVES (directives/)                                      │
│  ├─ Goals and operating procedures in Markdown                          │
│  └─ Learning history and constraints                                    │
│                                                                         │
│  LAYER 2: ORCHESTRATION (LLM Agent)                                     │
│  ├─ Stochastic/Deterministic/Hybrid architecture evaluation             │
│  ├─ Decision-making and tool coordination                               │
│  └─ Queries to the persistent memory system                             │
│                                                                         │
│  LAYER 3: EXECUTION (execution/)                                        │
│  ├─ Deterministic Python scripts (e.g., eBPF loader, actions)           │
│  ├─ Kernel probes in C (sensor.c)                                       │
│  └─ External integrations                                               │
│                                                                         │
│  LAYER 4: MEMORY (system_memory/ & claude-mem-main/)                    │
│  ├─ Observation capture (tool use, file changes, decisions)             │
│  ├─ Semantic compression of events                                      │
│  ├─ Hybrid search (Full-Text Search + Vector)                           │
│  └─ Context injection for subsequent sessions                           │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Persistent Memory System (RAG)

The memory system allows the agent to **remember** work from previous sessions. It automatically captures observations (tools used, syscalls, file access) and compresses them into semantic summaries for future use, forming the core of the Retrieval-Augmented Generation (RAG) capability.

### Memory Flow
```
┌─────────────────────────────────────────────────────────────────────────┐
│                              MEMORY FLOW                                │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  CURRENT SESSION                                                        │
│  ─────────────                                                          │
│  1. [START] Inject context from previous sessions.                      │
│       ↓                                                                 │
│  2. [WORK] Capture observations (tool use, syscalls, file access).      │
│       ↓                                                                 │
│  3. [END] Compress observations into a semantic summary.                │
│       ↓                                                                 │
│  4. [PERSIST] Store in the database for future sessions.                │
│                                                                         │
│  NEXT SESSION                                                           │
│  ──────────────                                                         │
│  1. Search for relevant context (keyword + semantic).                   │
│  2. Inject compressed summaries.                                        │
│  3. The agent "remembers" previous work.                                │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 🏗️ System Architecture

The system is deployed as a hybrid HIDS/HIPS monitor that operates in a a closed loop of telemetry, memory retrieval, and executive action:

*   **Telemetry Layer (Kernel Space):** Multi-dimensional eBPF probes intercept `execve`, `openat2`, and other syscalls to monitor process execution and sensitive file access in real-time.
*   **Memory Layer (RAG):** A persistent vector database (ChromaDB) stores event-action pairs. This allows for semantic cache "hits," enabling the system to remember previous threats or optimizations without redundant API calls.
*   **Inference Layer (Tier-3 Logic):** For novel or ambiguous events, the orchestrator consults a Large Language Model (LLM) to perform heuristic analysis on process intent.

---

## 🔬 Academic and Technical References

This project is grounded in contemporary systems engineering and cybersecurity research:

*   **Dynamic Observability:** Based on the methodology proposed by Brendan Gregg regarding BPF-based performance and security analysis.
*   **eBPF-based Security:** Leverages the Kprobe mechanism for deep visibility into the kernel's execution path without modifying the source code, ensuring system stability.
*   **Semantic Vector Memory:** Utilizes cosine similarity search over system event embeddings to maintain persistent situational awareness, a concept emerging in "Self-Healing Systems" research.
*   **Zero Trust Enforcement:** Implements a behavior-based security model that protects critical paths (e.g., `/etc/shadow`, `/etc/sudoers`, `.ssh/`) by validating them against the binary's historical profile.

---

## 🛠️ Implementation Specifications
### Core Components

*   `sensor.c`: C-based eBPF programs JIT-compiled and loaded into the kernel for high-performance telemetry.
*   `orchestrator.py`: The asynchronous decision engine that bridges the kernel's perf-buffer with the Vector DB and the AI API.
*   `system_memory/`: Persistent storage for the "immunological" memory of the OS.

### Operational Tiering

*   **Tier 1 (Deterministic):** Immediate filtering of whitelisted or known-malicious PIDs based on hardcoded rules.
*   **Tier 2 (Memory RAG):** Decision-making based on historical similarity in the vector database.
*   **Tier 3 (AI Inference):** Contextual reasoning for unknown behaviors via LLM API.

---

## 🚀 Quick Start

### 1. Install Dependencies
```bash
# Install kernel headers and BCC tools
sudo apt update && sudo apt install -y python3-bcc bpfcc-tools linux-headers-$(uname -r)

# Install Python requirements
pip install -r requirements.txt
```

### 2. Configure Environment
```bash
# Copy the example environment file
cp .env.example .env

# Edit the .env file and add your AI Agent API Key
# nano .env
# ANTHROPIC_API_KEY="your_api_key_here"
```

### 3. Run the Orchestrator
Execute with root privileges, which are required for eBPF. The `-E` flag preserves the environment variables.
```bash
sudo -E python3 execution/orchestrator/main.py
```
By default, the system runs in **DRY-RUN** mode, where it will only log actions but not execute them. To enable active enforcement, set `LIAK_DRY_RUN=false` in your `.env` file.

---

## 🤖 AI Co-construction Statement

NeuroKernel Bridge was developed using a Human-AI Co-construction methodology.

*   **Architectural Vision:** Defined by the human author.
*   **Technical Synthesis:** AI was utilized as a high-velocity engine for generating eBPF boilerplate, Python integration, and complex C-structures.
*   **Verification:** All kernel probes and security enforcement logic were manually audited, debugged, and validated by the author to ensure system-critical stability and prevent kernel panics.

---

## ⚖️ License

This project is licensed under the GNU General Public License v3.0 (GPL-3.0). Given its deep interaction with the Linux Kernel, this license ensures the project remains part of the free software ecosystem, requiring any derivative works to be transparent and open-source.