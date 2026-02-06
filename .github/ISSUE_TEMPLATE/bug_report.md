---
name: Bug Report
about: Report a technical issue or bug in NeuroKernel Bridge
title: '[BUG] '
labels: bug
assignees: ''
---

## 🐛 Bug Description

A clear and concise description of what the bug is.

## 📋 Steps to Reproduce

Provide a minimal, reproducible example:

1. Go to '...'
2. Click on '....'
3. Scroll down to '....'
4. See error

```bash
# Include relevant commands or code snippets
```

## 🎯 Expected Behavior

A clear and concise description of what you expected to happen.

## 📸 Actual Behavior

What actually happened? Include screenshots if applicable.

## 🔧 Environment

- **OS**: [e.g., Ubuntu 22.04, Debian 11, etc.]
- **Kernel Version**: [e.g., 5.15.0-91-generic]
- **Python Version**: [e.g., 3.10.12]
- **NeuroKernel Bridge Version**: [e.g., latest commit hash or version]

```bash
# Run these commands and paste the output:
uname -a
python3 --version
pip list | grep -i "bcc\|chromadb\|anthropic"
```

## 📝 Configuration

Please share relevant configuration settings (remove sensitive data):

```env
# From your .env file (remove API keys and secrets)
LIAK_DRY_RUN=true/false
# Other relevant settings...
```

## 📊 Logs

Include relevant logs from the orchestrator output:

```bash
# Example logs or error messages
```

## 💻 System Information

```bash
# BCC tools version
bcc --version

# eBPF support check
bpftool feature

# Kernel headers
dpkg -l | grep linux-headers-$(uname -r)
```

## 🧪 Test Cases

If you have written test cases that demonstrate the bug, please provide them:

```python
# Include test code here
```

## 📚 Additional Context

Add any other context about the problem here:

- Is this a regression? (Did it work before?)
- Are you running in DRY-RUN mode or active enforcement mode?
- Any specific system calls or processes being monitored?
- Relevant eBPF probe information

## ✅ Checklist

- [ ] I have searched for existing issues
- [ ] I have provided a minimal, reproducible example
- [ ] I have included relevant logs and environment information
- [ ] I have checked the documentation
- [ ] I have read the [CONTRIBUTING.md](../../CONTRIBUTING.md) guidelines
