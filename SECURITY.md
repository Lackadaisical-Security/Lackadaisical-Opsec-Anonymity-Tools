# Security Policy

## Overview

The Lackadaisical Anonymity Toolkit is designed with security as a primary concern. This document outlines our security policies, vulnerability reporting procedures, and security best practices.

## Supported Versions

We actively support and provide security updates for the following versions:

| Version | Supported          | End of Support |
| ------- | ------------------ | -------------- |
| 1.x     | :white_check_mark: | Current        |
| < 1.0   | :x:                | Deprecated     |

## Reporting a Vulnerability

### How to Report

If you discover a security vulnerability in the Lackadaisical Anonymity Toolkit, please report it responsibly:

1. **DO NOT** create a public GitHub issue
2. **DO NOT** disclose the vulnerability publicly until it has been addressed
3. **DO** send an email to: **security@lackadaisical-security.com**

### What to Include

Please provide the following information in your report:

* **Description**: Clear description of the vulnerability
* **Impact**: Potential impact and severity assessment
* **Reproduction**: Step-by-step instructions to reproduce the issue
* **Affected Versions**: Which versions are affected
* **Proof of Concept**: Code, screenshots, or other evidence (if applicable)
* **Suggested Fix**: Potential solutions (if you have any)
* **Contact Information**: How we can reach you for follow-up

### Our Commitment

When you report a vulnerability, we commit to:

* **Acknowledge** your report within 48 hours
* **Provide regular updates** on our progress (at least every 7 days)
* **Work with you** to understand and validate the issue
* **Notify you** when the vulnerability is fixed
* **Credit you** (if desired) in our security advisory and release notes

### Response Timeline

* **Critical vulnerabilities** (RCE, auth bypass): 24-48 hours initial response, 7-14 days to patch
* **High severity** (data exposure, privilege escalation): 48-72 hours initial response, 14-30 days to patch
* **Medium severity** (DoS, information disclosure): 3-5 days initial response, 30-60 days to patch
* **Low severity** (minor info leak): 5-7 days initial response, 60-90 days to patch

## Security Best Practices

### For Users

#### Installation Security

1. **Verify Downloads**
   ```bash
   # Verify GPG signature
   gpg --verify lackadaisical-toolkit-1.0.tar.gz.sig
   
   # Check SHA256 checksum
   sha256sum -c lackadaisical-toolkit-1.0.tar.gz.sha256
   ```

2. **Install from Official Sources**
   * Use official GitHub releases
   * Verify repository authenticity
   * Check commit signatures

3. **Use Isolated Environments**
   * Run in virtual machines when possible
   * Use containers for isolation
   * Consider Qubes OS for maximum isolation

#### Operational Security

1. **Regular Updates**
   ```bash
   # Check for updates
   lackadaisical --update-check
   
   # Update toolkit
   sudo ./scripts/deploy.sh update
   ```

2. **Secure Configuration**
   * Use strong passwords for Tor control
   * Encrypt sensitive configuration files
   * Set proper file permissions (600 for configs)
   * Rotate credentials regularly

3. **Network Security**
   * Use Tor for anonymity
   * Chain VPNs for additional layers
   * Verify no DNS leaks
   * Check for WebRTC leaks

4. **Data Protection**
   * Encrypt sensitive data at rest
   * Use secure deletion for temporary files
   * Clear metadata from all files
   * Use encrypted communications

#### Runtime Security

1. **Privilege Management**
   ```bash
   # Only use sudo when necessary
   # Most tools work without root
   lackadaisical <module> [options]
   
   # Use sudo only for network tools
   sudo lackadaisical mac-spoof --random
   ```

2. **Process Isolation**
   * Run untrusted code in containers
   * Use AppArmor or SELinux profiles
   * Limit resource access
   * Monitor system calls

3. **Network Monitoring**
   ```bash
   # Monitor for leaks
   lackadaisical privacy-check
   
   # Check active connections
   sudo lackadaisical activity-monitor
   ```

### For Developers

#### Code Security

1. **Input Validation**
   * Validate all user inputs
   * Sanitize file paths
   * Check command arguments
   * Prevent injection attacks

2. **Cryptography**
   * Use established libraries (cryptography, libsodium)
   * Never implement custom crypto
   * Use appropriate key sizes (RSA 4096+, AES 256+)
   * Implement perfect forward secrecy

3. **Secure Coding**
   * Follow OWASP guidelines
   * Use memory-safe languages when possible
   * Avoid buffer overflows
   * Prevent race conditions
   * No hardcoded credentials

4. **Dependencies**
   * Keep dependencies updated
   * Review dependency security advisories
   * Pin versions in production
   * Use dependency scanning tools

#### Code Review

All code must undergo security review:

* **Automated scanning** with CodeQL, Bandit, etc.
* **Manual code review** by at least one other developer
* **Security-focused review** for cryptographic or privileged code
* **Third-party audit** for critical components

#### Testing

1. **Security Testing**
   ```bash
   # Run security tests
   pytest tests/security/
   
   # Static analysis
   bandit -r modules/ tools/
   
   # Dependency check
   safety check
   ```

2. **Fuzzing**
   * Fuzz parsers and input handlers
   * Test edge cases
   * Check for crashes and hangs

3. **Integration Testing**
   * Test complete attack chains
   * Verify security controls
   * Check for bypass techniques

## Security Features

### Built-in Security

1. **Secure Defaults**
   * All tools use secure defaults
   * Paranoid mode available
   * Automatic security hardening

2. **Anti-Forensics**
   * Memory wiping
   * Secure deletion
   * Log cleaning
   * Trace removal

3. **Privacy Protection**
   * No telemetry
   * No analytics
   * No phone-home
   * Minimal logging

4. **Encryption**
   * AES-256 for data at rest
   * ChaCha20-Poly1305 for communications
   * RSA-4096 for key exchange
   * Post-quantum crypto support (experimental)

### Threat Model

#### In Scope

* **Network surveillance**: ISP, government, corporate monitoring
* **Forensic analysis**: Local law enforcement, corporate investigations
* **Malware**: Spyware, keyloggers, RATs
* **Physical access**: Evil maid attacks, border searches
* **Metadata analysis**: Traffic correlation, timing attacks

#### Out of Scope

* **Nation-state attackers with unlimited resources**: APTs with zero-days
* **Physical torture**: Rubber-hose cryptanalysis
* **Compromised hardware**: Hardware implants, backdoors
* **Quantum computers**: Future threat to current crypto

## Known Limitations

### Technical Limitations

1. **Browser Fingerprinting**: Cannot completely eliminate, only reduce
2. **Traffic Analysis**: Advanced correlation attacks may succeed
3. **Zero-day Exploits**: Cannot protect against unknown vulnerabilities
4. **Social Engineering**: Human factor remains vulnerable

### Legal Limitations

1. **Jurisdiction**: Laws vary by country
2. **Lawful Intercept**: Some jurisdictions require backdoors
3. **Key Disclosure**: Some countries can compel key disclosure

## Security Advisories

### Vulnerability Disclosure

We publish security advisories for all confirmed vulnerabilities:

* **GitHub Security Advisories**: Primary channel
* **Mailing List**: security-announce@lackadaisical-security.com
* **RSS Feed**: https://lackadaisical-security.com/security/feed.xml
* **PGP-signed emails**: For critical issues

### Advisory Format

```
LOAT-SA-YYYY-NNN: Title
Severity: Critical/High/Medium/Low
CVE: CVE-YYYY-NNNNN
Affected Versions: x.x.x - y.y.y
Fixed in: z.z.z

Description:
[Detailed description]

Impact:
[Security impact]

Mitigation:
[Immediate mitigations]

Solution:
[How to fix]

Credits:
[Researcher credits]
```

## Compliance and Certifications

### Standards Compliance

* **OWASP Top 10**: Addressed in design
* **NIST Cybersecurity Framework**: Aligned
* **CIS Benchmarks**: Followed for system hardening
* **ISO 27001**: Security management principles

### Audits

* **Code Audits**: Regular internal and external reviews
* **Penetration Testing**: Annual professional pentests
* **Vulnerability Scanning**: Continuous automated scanning

## Incident Response

### If You're Compromised

1. **Immediate Actions**
   ```bash
   # Emergency shutdown
   sudo lackadaisical emergency --panic
   
   # Secure delete sensitive data
   lackadaisical secure-delete --verify /path/to/sensitive/*
   
   # Clear traces
   sudo lackadaisical trace-remove --aggressive
   ```

2. **Forensic Preservation**
   * Take memory dump (if needed for analysis)
   * Preserve logs (if investigating)
   * Document timeline of events

3. **Recovery**
   * Reinstall from trusted media
   * Restore from clean backups
   * Rotate all credentials
   * Review and update security controls

### Contact

For security-related questions:

* **Email**: security@lackadaisical-security.com
* **PGP Key**: https://lackadaisical-security.com/pgp/security.asc
* **PGP Fingerprint**: `XXXX XXXX XXXX XXXX XXXX  XXXX XXXX XXXX XXXX XXXX`

## Bug Bounty Program

We recognize and reward security researchers:

### Scope

* **In Scope**: All code in this repository
* **Out of Scope**: Third-party dependencies, infrastructure

### Rewards

* **Critical**: $500 - $2000
* **High**: $250 - $500  
* **Medium**: $100 - $250
* **Low**: $50 - $100
* **Hall of Fame**: Recognition and swag

### Rules

1. No public disclosure before fix
2. No exploitation of found vulnerabilities
3. No testing against production systems without permission
4. Provide detailed reproduction steps
5. Submit only one issue per report
6. Be professional and respectful

## Additional Resources

### Documentation

* [Security Guide](docs/SECURITY_GUIDE.md) - Detailed security documentation
* [Deployment Guide](docs/DEPLOYMENT.md) - Secure deployment practices
* [Usage Guide](docs/USAGE_GUIDE.md) - Secure usage patterns

### Tools

* [OpenPGP](https://gnupg.org/) - Encrypted communications
* [Tor](https://www.torproject.org/) - Anonymous communications
* [Tails](https://tails.boum.org/) - Secure operating system
* [Qubes OS](https://www.qubes-os.org/) - Compartmentalized security

### Communities

* EFF (https://www.eff.org/) - Digital rights
* Tor Project (https://www.torproject.org/) - Anonymity network
* OWASP (https://owasp.org/) - Application security

## Export Compliance

### U.S. Export Control Laws and Regulations

This software and its contents are subject to U.S. export control laws and regulations, specifically the Export Administration Regulations (EAR) administered by the Bureau of Industry and Security (BIS) of the U.S. Department of Commerce.

### Cryptographic Technology Classification

This repository contains strong cryptographic software and technology, including:

* **Encryption algorithms**: AES-256, ChaCha20-Poly1305, RSA-4096
* **Cryptographic libraries**: Integration with cryptography, libsodium, OpenSSL
* **Secure communication protocols**: TLS, end-to-end encryption
* **Key management systems**: Credential vaults, secure storage
* **Authentication mechanisms**: Cryptographic authentication
* **Steganography tools**: Data hiding using cryptographic techniques
* **Anti-forensics tools**: Secure deletion with cryptographic verification

**Export Control Classification Number (ECCN)**: This software is classified under ECCN 5D002 on the Commerce Control List as publicly available encryption source code.

### License Exception TSU

This software is made publicly available under **License Exception TSU** (Technology and Software - Unrestricted) in accordance with 15 CFR § 740.13(e). This exception permits export of publicly available encryption source code that meets specific criteria.

#### Requirements for License Exception TSU:

1. **Public Availability**: Source code must be publicly available (this repository satisfies this requirement)
2. **Notification**: The U.S. government has been notified of the availability of this source code
3. **No Classified Information**: This software contains no classified information
4. **Not Subject to ITAR**: This software is not subject to International Traffic in Arms Regulations (ITAR)

### Prohibited Destinations and Parties

#### Embargoed Countries and Regions

**Export, re-export, or transfer of this software is STRICTLY PROHIBITED to:**

* **Cuba** - Comprehensive embargo under 31 CFR Part 515
* **Iran** - Comprehensive embargo under 31 CFR Part 560  
* **North Korea (DPRK)** - Comprehensive embargo under 31 CFR Part 510
* **Syria** - Comprehensive embargo under 31 CFR Part 542
* **Crimea, Donetsk, and Luhansk regions of Ukraine** - Regional sanctions under Executive Order 13685
* **Any other country, region, or territory subject to comprehensive U.S. sanctions**

**Note**: This list is subject to change. Users must verify current sanctions at https://sanctionssearch.ofac.treas.gov/

#### Restricted Parties Lists

Export is prohibited to individuals and entities on the following U.S. government lists:

1. **Denied Persons List (DPL)** - BIS denied export privileges
2. **Entity List** - BIS list of entities subject to license requirements
3. **Specially Designated Nationals (SDN) List** - OFAC sanctions list
4. **Unverified List (UVL)** - BIS list of parties whose authenticity is unverified
5. **Military End User (MEU) List** - BIS list of Chinese and Russian military end users
6. **Sectoral Sanctions Identifications (SSI) List** - OFAC sectoral sanctions
7. **Foreign Sanctions Evaders (FSE) List** - OFAC sanctions evaders
8. **Non-SDN Palestinian Legislative Council (NS-PLC) List** - OFAC list
9. **Non-SDN Menu-Based Sanctions (NS-MBS) List** - OFAC list

**Verification Required**: Before any export, users must screen recipients against all restricted parties lists at:
* https://www.trade.gov/consolidated-screening-list
* https://sanctionssearch.ofac.treas.gov/

### Prohibited End Uses

This software may NOT be used for or exported for the following purposes:

1. **Nuclear Activities**: Development, production, or use of nuclear materials or facilities
2. **Missile Technology**: Development or production of missiles or unmanned aerial vehicles
3. **Chemical/Biological Weapons**: Development, production, or use of chemical or biological weapons
4. **Restricted Military End Uses**: Use by military, security, or intelligence services in certain countries
5. **Human Rights Violations**: Use in connection with human rights abuses or violations
6. **Cyber Attacks**: Offensive cyber operations against U.S. interests
7. **Sanctions Evasion**: Facilitation of sanctions evasion activities

### User Certifications and Responsibilities

#### Required Certifications

**By downloading, installing, accessing, or using this software, you certify that:**

1. ✓ You are not located in, under control of, or a national/resident of any embargoed country or region
2. ✓ You are not listed on any U.S. government restricted parties list
3. ✓ You will not export, re-export, or transfer this software to any prohibited country, region, or party
4. ✓ You will not use this software for any prohibited end use
5. ✓ You understand and will comply with all applicable U.S. export control laws and regulations
6. ✓ You understand that violations may result in civil and criminal penalties

#### User Compliance Obligations

**Users are responsible for:**

* **Screening**: Verifying that all users, recipients, and destinations are not prohibited
* **Due Diligence**: Conducting reasonable due diligence on end uses and end users
* **Record Keeping**: Maintaining records of exports for at least 5 years
* **Monitoring**: Staying informed of changes to export control regulations
* **Legal Counsel**: Consulting with qualified legal counsel regarding compliance
* **License Applications**: Obtaining export licenses when required (if License Exception TSU does not apply)

### International Compliance

#### Other Countries' Export Controls

In addition to U.S. export controls, users must comply with export control laws of other jurisdictions:

* **European Union**: Dual-use regulations (EU Regulation 2021/821)
* **United Kingdom**: Export Control Act 2002 and dual-use regulations
* **Canada**: Export and Import Permits Act
* **Australia**: Defence Trade Controls Act 2012
* **Japan**: Foreign Exchange and Foreign Trade Act
* **Other countries**: Local export control and encryption laws

#### Wassenaar Arrangement

This software may fall under the Wassenaar Arrangement on Export Controls for Conventional Arms and Dual-Use Goods and Technologies, which is implemented by 42 participating states. Users should verify compliance with local implementations of Wassenaar controls.

### Notification and Reporting

#### Government Notification

As required by 15 CFR § 742.15(b), notification has been provided to the U.S. government regarding the public availability of this encryption source code.

**Notification Details:**
* Repository URL: https://github.com/Lackadaisical-Security/Lackadaisical-Opsec-Anonymity-Tools
* Contact: security@lackadaisical-security.com
* Classification: Publicly available encryption source code under ECCN 5D002

#### User Reporting Obligations

Users who obtain export licenses must comply with reporting requirements specified in their licenses. Users should also be aware of deemed export rules when sharing this software with foreign nationals.

### Penalties for Violations

**Violations of U.S. export control laws can result in severe penalties:**

* **Criminal Penalties**: Up to 20 years imprisonment and $1,000,000 fine per violation
* **Civil Penalties**: Up to $300,000 or twice the value of the transaction per violation  
* **Administrative Penalties**: Denial of export privileges, seizure of goods
* **Additional Consequences**: Debarment from government contracts, reputation damage

### Compliance Resources

#### Government Resources

* **Bureau of Industry and Security (BIS)**: https://www.bis.doc.gov/
  - Export Administration Regulations: https://www.bis.doc.gov/regulations/
  - ECCN Matrix: https://www.bis.doc.gov/ccl/
  - Encryption Controls: https://www.bis.doc.gov/encryption/

* **Office of Foreign Assets Control (OFAC)**: https://home.treasury.gov/policy-issues/office-of-foreign-assets-control-sanctions-programs-and-information
  - Sanctions Programs: https://home.treasury.gov/policy-issues/financial-sanctions/sanctions-programs-and-country-information
  - Consolidated Screening List: https://sanctionssearch.ofac.treas.gov/

* **Directorate of Defense Trade Controls (DDTC)**: https://www.pmddtc.state.gov/
  - International Traffic in Arms Regulations (ITAR)

* **Consolidated Screening List**: https://www.trade.gov/consolidated-screening-list
  - Unified search across all U.S. government restricted parties lists

#### Additional Guidance

* **BIS Encryption FAQs**: https://www.bis.doc.gov/encryption/encryption_faqs.html
* **OFAC Guidance**: https://home.treasury.gov/policy-issues/office-of-foreign-assets-control-sanctions-programs-and-information/ofac-faqs
* **Export Compliance Training**: Available through BIS and private organizations
* **Legal Counsel**: Consult with attorneys specializing in export control law

### Updates and Changes

Export control regulations are subject to change. Users should:

* Monitor the Federal Register for regulatory changes
* Subscribe to BIS updates at https://www.bis.doc.gov/index.php/subscribe
* Review OFAC sanctions updates regularly
* Consult legal counsel periodically to ensure ongoing compliance

**Last Updated**: 2026-01-29

### Disclaimer of Liability

**THE AUTHORS, CONTRIBUTORS, AND COPYRIGHT HOLDERS MAKE NO REPRESENTATION OR WARRANTY REGARDING:**

* The applicability of export control laws to any specific use case
* The accuracy or completeness of export control information provided
* The current status of any country, region, individual, or entity under export control regulations
* The appropriate classification of this software under export control regulations

**USERS ASSUME FULL AND SOLE RESPONSIBILITY FOR:**

* Determining the applicability of export control laws to their specific use case
* Ensuring compliance with all applicable U.S. and international export control laws
* Obtaining any necessary licenses, approvals, or authorizations
* Verifying the status of destinations and parties against current restricted lists
* Consulting with qualified legal counsel regarding export compliance

**THE AUTHORS, CONTRIBUTORS, AND COPYRIGHT HOLDERS EXPRESSLY DISCLAIM ANY AND ALL LIABILITY FOR:**

* Violations of export control laws by users
* Penalties, fines, or sanctions imposed on users for export control violations  
* Damages arising from non-compliance with export control regulations
* Inaccuracies in export control information provided
* Changes to export control regulations after publication

This disclaimer applies to the maximum extent permitted by law.

---

**Security is a process, not a product. Stay vigilant, stay updated, stay safe.**

*Last updated: 2026-01-29*
