# Security Policy

## Overview

The XRPL Wallet MCP Server handles sensitive cryptographic operations including private key management. We take security extremely seriously and appreciate responsible disclosure of any vulnerabilities.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |
| 0.x.x   | :x: (Pre-release)  |

Only the latest minor version of each supported major version receives security updates.

## Reporting a Vulnerability

### How to Report

**DO NOT** create a public GitHub issue for security vulnerabilities.

Please report security vulnerabilities through one of these channels:

1. **GitHub Security Advisories** (Preferred)
   - Navigate to the Security tab of this repository
   - Click "Report a vulnerability"
   - Fill in the vulnerability details

2. **Email**
   - Send to: contact@9rese.com
   - Use PGP encryption if possible (key below)
   - Subject: [SECURITY] Brief description

### What to Include

Please provide:

- **Description**: Clear description of the vulnerability
- **Impact**: What an attacker could achieve
- **Reproduction Steps**: Detailed steps to reproduce
- **Affected Versions**: Which versions are affected
- **Potential Fix**: If you have suggestions
- **Your Contact**: For follow-up questions

### PGP Key

```
[PGP PUBLIC KEY BLOCK - To be added when project goes live]
```

## Response Timeline

| Stage | Timeline |
|-------|----------|
| Acknowledgment | Within 48 hours |
| Initial Assessment | Within 7 days |
| Status Update | Every 7 days |
| Fix Development | Based on severity |
| Public Disclosure | Coordinated with reporter |

### Severity-Based Resolution Targets

| Severity | Target Resolution |
|----------|-------------------|
| Critical | 7 days |
| High | 14 days |
| Medium | 30 days |
| Low | 90 days |

## Safe Harbor

We support safe harbor for security researchers who:

- Act in good faith to avoid privacy violations, destruction of data, and interruption or degradation of our services
- Only interact with accounts you own or with explicit permission from the account holder
- Do not exploit a security issue for purposes other than verification
- Do not perform actions that could harm our users or systems
- Provide us reasonable time to respond before any disclosure

We will not pursue legal action against researchers who follow these guidelines.

## Security Measures

### What We Protect

This project implements multiple security layers:

1. **Cryptographic Security**
   - AES-256-GCM encryption for wallet data
   - Argon2id key derivation for password-based encryption
   - Secure random generation via Node.js crypto

2. **Access Control**
   - Input validation on all MCP tool inputs
   - Rate limiting on sensitive operations
   - Authentication lockout after failed attempts

3. **Audit & Monitoring**
   - Tamper-evident audit logging
   - Security event monitoring
   - No logging of sensitive data (keys, passwords)

4. **Supply Chain**
   - Dependency scanning in CI/CD
   - Lockfile enforcement
   - SBOM generation

### What Users Should Do

1. **Keep Updated**: Always use the latest version
2. **Strong Passwords**: Use strong, unique passwords for wallet encryption
3. **Secure Environment**: Run on trusted systems with up-to-date security patches
4. **Backup Safely**: Store wallet backups securely offline
5. **Verify Downloads**: Check release signatures when available

## Scope

### In Scope

- XRPL Wallet MCP Server codebase
- Cryptographic implementations
- Authentication/authorization logic
- Input validation
- Audit logging
- Dependencies (npm packages)

### Out of Scope

- Attacks requiring physical access to user's machine
- Social engineering attacks
- Denial of service attacks
- Issues in third-party services (XRPL network itself)
- Issues already reported or known

## Recognition

We maintain a security acknowledgments page for researchers who help improve our security. With your permission, we will:

- Credit you in release notes
- Add you to our Hall of Fame
- Provide a letter of acknowledgment if requested

## Security Updates

Security updates are announced through:

1. GitHub Security Advisories
2. Release notes
3. CHANGELOG.md

Subscribe to GitHub notifications for this repository to stay informed.

## Contact

- **Security issues**: contact@9rese.com
- **General questions**: contact@9rese.com
- **GitHub Discussions**: For non-sensitive security questions

---

*This security policy follows guidelines from the [OpenSSF Security Baseline](https://baseline.openssf.org/) and [disclose.io](https://disclose.io/).*
