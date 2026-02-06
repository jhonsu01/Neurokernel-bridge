---
name: False Positive Report
about: Report a false positive detection by NeuroKernel Bridge
title: '[FALSE POSITIVE] '
labels: false-positive, triage
assignees: ''
---

## 🚨 False Positive Description

NeuroKernel Bridge incorrectly flagged a legitimate process or system call as malicious.

## 📋 Event Details

### Process Information

- **Process Name**: [e.g., nginx, dockerd, custom_app]
- **PID**: [if available]
- **Command Line**: [full command executed]
- **User**: [user who executed the process]
- **Working Directory**: [path if relevant]

### System Call Details

- **Syscall Type**: [e.g., execve, openat2, read, write]
- **Target Path**: [file or directory accessed]
- **Timestamp**: [when the event occurred]
- **Detection Tier**: [Tier 1: Rules, Tier 2: Memory/RAG, Tier 3: AI Inference]

### Detection Reason

What was the reason provided by the orchestrator for flagging this event?

```
# Include the detection reason from logs
```

## 🎯 Why This Is Legitimate

Explain why this process or system call should be considered legitimate:

- **Purpose**: [What is this process doing?]
- **Frequency**: [How often does this happen?]
- **Context**: [Is this part of normal operations?]

## 📊 Logs

Include relevant logs from the orchestrator:

```bash
# Include the full event log
```

## 🔧 Environment

- **OS**: [e.g., Ubuntu 22.04, Debian 11, etc.]
- **Kernel Version**: [e.g., 5.15.0-91-generic]
- **NeuroKernel Bridge Version**: [e.g., latest commit hash or version]

## 💡 Suggested Resolution

How should this be handled? Select one or provide additional context:

- [ ] Add to whitelist (hardcoded rules)
- [ ] Add to memory database (positive example for RAG)
- [ ] Improve AI prompt/context
- [ ] Other: [explain]

### If Whitelist Suggested

Provide the rule criteria:

```python
# Example whitelist rule
{
    "process_name": "nginx",
    "path": "/usr/sbin/nginx",
    "user": "root",
    "reason": "Legitimate web server process"
}
```

### If Memory/RAG Suggested

Provide context for the positive example:

```python
# Example positive memory entry
{
    "process": "nginx",
    "syscall": "openat2",
    "target": "/var/log/nginx/access.log",
    "context": "Web server log file access during normal operations",
    "action": "allow"
}
```

## 🧪 Verification Steps

How can this be verified as a false positive?

1. [ ]
2. [ ]
3. [ ]

## 📚 Additional Context

Add any other relevant information:

- Is this a known legitimate application?
- Has this happened before?
- Any specific configuration or deployment details?

## ✅ Checklist

- [ ] I have confirmed this is a false positive (not actual malicious activity)
- [ ] I have provided complete event details
- [ ] I have included relevant logs
- [ ] I have suggested a resolution approach
- [ ] I have read the [CONTRIBUTING.md](../../CONTRIBUTING.md) guidelines

## 🔒 Security Note

Please ensure you are not reporting actual malicious activity as a false positive. If you are unsure about the legitimacy of an event, please consult with your security team first.
