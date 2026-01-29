# Logging
logger.debug("Detailed information for debugging")
logger.info("General information")
logger.warning("Warning: potential issue")
logger.error("Error occurred, but handled")
logger.critical("Critical error, system may be compromised")
```

## Testing

### Test Requirements

All contributions must include appropriate tests:

1. **Unit Tests**: Test individual functions/methods
2. **Integration Tests**: Test module interactions
3. **Security Tests**: Verify no security regressions
4. **Performance Tests**: Ensure no performance degradation

### Writing Tests

```python
# Python example using pytest
import pytest
from lackadaisical.modules.network import TorController

class TestTorController:
    @pytest.fixture
    def controller(self):
        return TorController()
    
    def test_connection(self, controller):
        """Test Tor connection establishment"""
        controller.connect()
        assert controller.is_connected()
    
    def test_new_identity(self, controller):
        """Test identity rotation"""
        controller.connect()
        old_ip = controller.get_ip()
        controller.new_identity()
        new_ip = controller.get_ip()
        assert old_ip != new_ip
    
    def test_security_leak(self, controller):
        """Test for DNS leaks"""
        controller.connect()
        assert not controller.has_dns_leak()
```

### Running Tests

```bash
# Run all tests
pytest

# Run specific module tests
pytest tests/test_network.py

# Run with coverage
pytest --cov=lackadaisical --cov-report=html

# Run security tests
pytest tests/security/

# Run performance benchmarks
pytest tests/performance/ --benchmark-only
```

### Test Coverage

- Minimum 80% code coverage required
- Critical security functions require 100% coverage
- Include edge cases and error conditions

## Documentation

### Documentation Requirements

All contributions must include:

1. **Code Documentation**: Docstrings, comments
2. **API Documentation**: If adding/changing APIs
3. **Usage Examples**: Show how to use new features
4. **Update Guides**: Update relevant guides

### Documentation Style

```python
def secure_communication(sender: str, receiver: str, 
                        message: str, encryption: str = 'aes256') -> bytes:
    """
    Establish secure communication between parties.
    
    This function creates an encrypted channel between sender and receiver
    using the specified encryption algorithm. It handles key exchange,
    message encryption, and integrity verification.
    
    Args:
        sender: Identifier of the message sender
        receiver: Identifier of the message receiver  
        message: Plain text message to send
        encryption: Encryption algorithm to use. Options:
                   - 'aes256': AES-256-GCM (default)
                   - 'chacha20': ChaCha20-Poly1305
                   - 'rsa4096': RSA-4096 with OAEP
    
    Returns:
        Encrypted message bytes with authentication tag
        
    Raises:
        EncryptionError: If encryption fails
        InvalidRecipientError: If receiver key not found
        
    Example:
        >>> encrypted = secure_communication(
        ...     'alice', 'bob', 'Secret message', 'aes256'
        ... )
        >>> print(f"Encrypted: {encrypted.hex()}")
        
    Note:
        This function requires prior key exchange between parties.
        Use `exchange_keys()` before first communication.
        
    Security:
        - Uses authenticated encryption (AEAD)
        - Includes replay protection
        - Forward secrecy with ephemeral keys
    """
    # Implementation
```

### Updating Documentation

When adding features, update:

1. `README.md` - If adding major features
2. `docs/USAGE_GUIDE.md` - Add usage instructions
3. `docs/API_REFERENCE.md` - API changes
4. `docs/SECURITY_GUIDE.md` - Security implications
5. Module-specific docs in `docs/modules/`

## Security

### Security Requirements

All code must:

1. **Avoid Vulnerabilities**: No SQL injection, XSS, etc.
2. **Validate Input**: Never trust user input
3. **Secure Defaults**: Default to secure settings
4. **Minimize Privileges**: Request only needed permissions
5. **Clear Sensitive Data**: Wipe memory after use

### Security Checklist

- [ ] Input validation implemented
- [ ] Error messages don't leak sensitive info
- [ ] Secrets properly managed (no hardcoding)
- [ ] Secure random number generation used
- [ ] Memory cleared after handling sensitive data
- [ ] Timing attacks considered and mitigated
- [ ] Dependencies checked for vulnerabilities
- [ ] Security tests written

### Reporting Security Issues

**DO NOT** create public issues for security vulnerabilities.

Instead:
1. Email security@lackadaisical-security.com
2. Use PGP encryption (key in repo)
3. Include:
   - Description of vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

## Review Process

### Review Criteria

PRs are reviewed for:

1. **Functionality**: Does it work as intended?
2. **Security**: No vulnerabilities introduced?
3. **Performance**: No significant degradation?
4. **Code Quality**: Follows standards?
5. **Tests**: Adequate test coverage?
6. **Documentation**: Properly documented?

### Review Timeline

- Small changes: 1-3 days
- Medium changes: 3-7 days  
- Large changes: 7-14 days
- Security fixes: ASAP

### Getting Reviews

To get timely reviews:

1. Keep PRs focused and small
2. Write clear descriptions
3. Include test results
4. Respond promptly to feedback
5. Be patient and respectful

## Release Process

### Version Numbering

We use semantic versioning (MAJOR.MINOR.PATCH):

- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes

### Release Checklist

- [ ] All tests passing
- [ ] Documentation updated
- [ ] CHANGELOG updated
- [ ] Security scan completed
- [ ] Performance benchmarks run
- [ ] Release notes prepared

## Recognition

Contributors are recognized in:

- `CONTRIBUTORS.md` file
- Release notes
- Project website
- Annual security report

### Contributor Levels

1. **Contributor**: 1+ merged PRs
2. **Regular Contributor**: 5+ merged PRs
3. **Core Contributor**: 20+ merged PRs + ongoing involvement
4. **Maintainer**: Invited based on contributions

## Resources

### Helpful Links

- [Project Wiki](https://github.com/lackadaisical-security/anonymity-toolkit/wiki)
- [Security Resources](docs/SECURITY_RESOURCES.md)
- [Architecture Guide](docs/ARCHITECTURE.md)
- [Privacy Papers](docs/PRIVACY_PAPERS.md)

### Development Tools

- [Pre-commit hooks](.pre-commit-config.yaml)
- [CI/CD Pipeline](.github/workflows/)
- [Development Scripts](scripts/dev/)
- [Testing Framework](tests/README.md)

### Communication

- GitHub Issues: Bug reports, features
- Discussions: General questions
- Security Email: security@lackadaisical-security.com
- IRC: #lackadaisical on OFTC (Tor-friendly)

## Thank You!

Your contributions help make the internet a more private and secure place. Every contribution, no matter how small, is valuable and appreciated.

Remember: **Privacy is a human right**, and your work helps protect it.