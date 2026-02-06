## 📋 Description

Briefly describe the changes in this pull request.

## 🎯 Type of Change

- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update
- [ ] Performance improvement
- [ ] Code refactoring

## 🧪 Testing

### Manual Testing

Describe the manual testing performed:

- [ ] Tested on Ubuntu 22.04
- [ ] Tested on Debian 11
- [ ] Tested on other OS: [specify]

### Automated Testing

- [ ] All existing tests pass
- [ ] New tests added for the changes
- [ ] Tests cover edge cases

```bash
# Include test results
pytest tests/
```

## 📚 Documentation

- [ ] Code is documented with docstrings
- [ ] README.md updated (if needed)
- [ ] GUIDE.md updated (if needed)
- [ ] Inline comments added for complex logic

## 🔒 Security Considerations

- [ ] No security vulnerabilities introduced
- [ ] eBPF code reviewed for kernel safety
- [ ] No sensitive data exposed in logs
- [ ] API keys/secrets properly handled

## 🚀 Deployment Checklist

### Pre-Merge Requirements

- [ ] Code follows project style guidelines
- [ ] No linting errors (flake8, pylint, etc.)
- [ ] No type checking errors (mypy, if applicable)
- [ ] Changes are based on latest `dev` branch
- [ ] Commit messages follow conventional commits

### Code Review

- [ ] Self-review completed
- [ ] Code is clear and maintainable
- [ ] No unnecessary complexity added
- [ ] Dependencies are minimal and justified

## 📊 Performance Impact

- [ ] No performance regression
- [ ] eBPF probe overhead measured (if applicable)
- [ ] Memory usage reviewed

## 🔄 Branching

This PR is targeting: `main` branch

### Required for merging to `main`

- [ ] All CI/CD checks pass
- [ ] At least one maintainer approval
- [ ] No merge conflicts
- [ ] All PR template requirements completed

## 🔗 Related Issues

Closes #(issue_number)
Related to #(issue_number)

## 📝 Additional Notes

Any additional context, screenshots, or information that helps reviewers understand the changes.

---

## ✅ Final Checklist

Before requesting review, ensure:

- [ ] I have read the [CONTRIBUTING.md](../CONTRIBUTING.md) guidelines
- [ ] My code follows the project's coding standards
- [ ] I have performed a self-review of my code
- [ ] I have commented my code where necessary
- [ ] I have updated the documentation accordingly
- [ ] My changes generate no new warnings
- [ ] I have tested my changes thoroughly
- [ ] I understand that this PR may be rejected if it doesn't meet quality standards

## 🏗️ Technical Details

### Files Changed

List the files modified in this PR:

- `path/to/file1.py` - Description of changes
- `path/to/file2.c` - Description of changes
- ...

### Breaking Changes

If this PR introduces breaking changes, describe them here and provide migration instructions:

```python
# Example migration guide
# Old way:
result = old_function()

# New way:
result = new_function(param1, param2)
```

### Dependencies

- [ ] No new dependencies added
- [ ] New dependencies: [list and justify]

---

Thank you for contributing to NeuroKernel Bridge! 🙏
