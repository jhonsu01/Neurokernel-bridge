# Contributing to NeuroKernel Bridge

Thank you for your interest in contributing to NeuroKernel Bridge! This document provides guidelines and instructions for contributing to the project.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Branching Strategy](#branching-strategy)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)
- [Submitting Changes](#submitting-changes)
- [Reporting Issues](#reporting-issues)

## 🤝 Code of Conduct

Be respectful, inclusive, and constructive in all interactions. We welcome contributors from all backgrounds and experience levels.

## 🚀 Getting Started

### Prerequisites

- Linux system with kernel 4.15+ (eBPF support)
- Python 3.8+
- Root/sudo access for eBPF operations
- Git

### Setup Development Environment

```bash
# 1. Fork the repository on GitHub
# 2. Clone your fork
git clone https://github.com/YOUR_USERNAME/NeuroKernel-Bridge.git
cd NeuroKernel-Bridge

# 3. Install dependencies
sudo apt update
sudo apt install -y python3-bcc bpfcc-tools linux-headers-$(uname -r)
pip install -r requirements.txt

# 4. Copy environment configuration
cp .env.example .env
# Edit .env and add your API keys

# 5. Install development dependencies
pip install pytest pytest-cov flake8 pylint mypy
```

### Verify Setup

```bash
# Run tests to verify your environment
pytest tests/ -v

# Check eBPF support
bpftool feature
```

## 🔄 Development Workflow

### 1. Create a Branch

```bash
# Ensure you're on the latest dev branch
git checkout dev
git pull upstream dev

# Create a feature branch
git checkout -b feature/your-feature-name
# or
git checkout -b fix/issue-123
```

### 2. Make Your Changes

- Write clean, well-documented code
- Follow the coding standards (see below)
- Add tests for new functionality
- Update documentation as needed

### 3. Test Your Changes

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=execution/orchestrator --cov-report=html

# Run linting
flake8 execution/orchestrator/
pylint execution/orchestrator/

# Type checking (if using type hints)
mypy execution/orchestrator/
```

### 4. Commit Your Changes

```bash
# Stage your changes
git add .

# Commit with a descriptive message (follow conventional commits)
git commit -m "feat: add new syscall monitoring capability"

# Common commit types:
# feat:     New feature
# fix:      Bug fix
# docs:     Documentation changes
# style:    Code style changes (formatting)
# refactor: Code refactoring
# perf:     Performance improvements
# test:     Adding or updating tests
# chore:    Maintenance tasks
```

### 5. Push and Create Pull Request

```bash
# Push to your fork
git push origin feature/your-feature-name

# Create a pull request on GitHub
# Target branch: dev (for development) or main (for production-ready changes)
```

## 🌳 Branching Strategy

```
main
  ↑ Production-ready code
  │
dev
  ↑ Development branch
  │
feature/*, fix/*, docs/*
  ↑ Feature and bugfix branches
```

### Branch Rules

- **`main`**: Production-ready code only. Merged from `dev` after thorough testing
- **`dev`**: Active development branch. All feature branches merge here
- **`feature/*`**: New features and enhancements
- **`fix/*`**: Bug fixes
- **`docs/*`**: Documentation updates

### Merge Requirements

To merge from `dev` to `main`:

- [ ] All tests passing
- [ ] Code review approved
- [ ] No breaking changes without documentation
- [ ] Release notes updated
- [ ] Version number incremented

## 📝 Coding Standards

### Python

- Follow PEP 8 style guide
- Use type hints where appropriate
- Maximum line length: 100 characters
- Docstrings follow Google style

```python
def example_function(param1: str, param2: int) -> bool:
    """Brief description of the function.

    Longer description if needed.

    Args:
        param1: Description of param1
        param2: Description of param2

    Returns:
        Description of return value

    Raises:
        ValueError: When invalid input is provided
    """
    # Implementation
    pass
```

### C (eBPF Programs)

- Follow Linux kernel coding style
- Use `clang-format` with kernel style
- Add comments for complex logic
- Ensure kernel compatibility

```c
// Example eBPF probe
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx) {
    // Implementation
    return 0;
}
```

### General Guidelines

- Write self-documenting code
- Keep functions focused and small
- Use meaningful variable names
- Add comments for non-obvious logic
- Avoid premature optimization

## 🧪 Testing Guidelines

### Test Structure

```
tests/
├── unit/           # Unit tests
├── integration/    # Integration tests
└── ebpf/          # eBPF compilation tests
```

### Writing Tests

```python
import pytest

class TestExample:
    """Example test class."""

    def test_example_function(self):
        """Test that example_function works correctly."""
        result = example_function("test", 42)
        assert result is True
```

### Test Coverage

- Aim for >80% code coverage
- Test edge cases and error conditions
- Mock external dependencies (API calls, database)
- Test eBPF probes separately from orchestration logic

### Running Tests

```bash
# All tests
pytest tests/ -v

# Specific test file
pytest tests/unit/test_executor.py -v

# With coverage
pytest tests/ --cov=execution/orchestrator --cov-report=term-missing

# Specific test
pytest tests/unit/test_executor.py::TestExecutor::test_execute -v
```

## 📤 Submitting Changes

### Pull Request Checklist

Before submitting a PR:

- [ ] Code follows project style guidelines
- [ ] All tests pass
- [ ] New tests added for new features
- [ ] Documentation updated
- [ ] Commit messages are clear and descriptive
- [ ] PR description explains the "why" not just "what"
- [ ] No merge conflicts with target branch

### PR Review Process

1. Automated checks (CI/CD) must pass
2. Code review by maintainers
3. Address review feedback
4. Approval from at least one maintainer
5. Merge into target branch

### Getting Your PR Merged

- Be responsive to review feedback
- Keep the PR focused on one issue/feature
- Update the PR as needed based on feedback
- Mark conversations as resolved when addressed

## 🐛 Reporting Issues

### Bug Reports

Use the [Bug Report](.github/ISSUE_TEMPLATE/bug_report.md) template and include:

- Clear description of the bug
- Steps to reproduce
- Expected vs actual behavior
- Environment details (OS, kernel, Python version)
- Relevant logs and configuration

### False Positives

Use the [False Positive Report](.github/ISSUE_TEMPLATE/false_positive.md) template and include:

- Event details (process, syscall, detection tier)
- Why it's a false positive
- Suggested resolution
- Relevant logs

### Feature Requests

Open an issue with:

- Clear description of the feature
- Use case and motivation
- Proposed implementation approach
- Alternatives considered

## 📚 Documentation

### Updating Documentation

- Keep README.md up to date with setup instructions
- Update GUIDE.md for new features
- Add inline docstrings for new functions
- Update CHANGELOG.md for user-facing changes

### Documentation Style

- Use clear, concise language
- Include code examples
- Provide context and motivation
- Link to related documentation

## 🔒 Security

### Reporting Security Vulnerabilities

For security issues, **do not** use public issues. Instead:

1. Email security@neurokernel-bridge.org
2. Include details of the vulnerability
3. Wait for response before disclosing publicly

### Security Best Practices

- Never commit API keys or secrets
- Validate all inputs
- Follow principle of least privilege
- Review eBPF code for kernel safety
- Test in DRY-RUN mode first

## 🎯 Areas for Contribution

We welcome contributions in these areas:

- **eBPF Probes**: New syscall monitoring capabilities
- **Detection Logic**: Improved rules and heuristics
- **AI Integration**: Better LLM prompts and context
- **Performance**: Optimization of probes and orchestrator
- **Testing**: Additional test coverage
- **Documentation**: Guides, tutorials, examples
- **Integrations**: New notification channels, databases

## 💬 Getting Help

- **GitHub Issues**: For bugs and feature requests
- **Discussions**: For questions and general discussion
- **Documentation**: Check GUIDE.md and inline docs

## 📜 License

By contributing, you agree that your contributions will be licensed under the GNU General Public License v3.0 (GPL-3.0).

## 🙏 Thank You

We appreciate all contributions, no matter how small. Every bug fix, documentation improvement, or feature enhancement helps make NeuroKernel Bridge better for everyone!

---

For questions not covered here, please open a GitHub Discussion or contact the maintainers.
