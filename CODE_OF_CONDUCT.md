# Code of Conduct

## Philosophy

The Lackadaisical Anonymity Toolkit is built on **technical excellence, operational security, and old-school hacker ethics**. This project operates under leet-era principles: your code quality, security knowledge, and actual contributions matter - nothing else. If you can write production-grade anonymity tools, understand OPSEC, and operate with integrity, you're in.

**No politics. No bullshit. Just privacy tools that actually work.**

## Core Principles

### 1. Merit is King
- **Your contributions are judged by technical merit only** - code quality, security rigor, tool effectiveness, documentation clarity
- Skill level doesn't matter if you're willing to learn and improve
- Show your work. Document your tools. Defend your approach with threat models
- If your tool has vulnerabilities, fix them or explain why they exist

### 2. Technical Competence Over Everything
- Know what you're talking about or shut up
- Understand the security fundamentals behind your tools
- Research before you ask questions - read the docs, check CVEs, understand the threat model
- "My tool doesn't work" is not a bug report - show configs, logs, reproduction steps
- If you claim military-grade security, provide evidence and threat model analysis

### 3. Operational Security
- **Security is not negotiable** - no backdoors, no logging, no telemetry, no compromises
- Test your tools in hostile environments - VMs, airgapped systems, paranoid setups
- Assume active adversaries - ISPs, governments, forensic analysts, APTs
- Document security assumptions and limitations honestly
- Privacy failures can cost lives - take this seriously

### 4. Intellectual Honesty
- Don't plagiarize code or tools. Cite your sources and inspirations
- If you don't know something, say so - nobody expects you to know every attack vector
- Admit when your tool leaks metadata or has privacy weaknesses
- Document your testing honestly - include failure modes and edge cases
- Cherry-picking test results is bullshit - report all privacy/security trade-offs

### 5. Hacker Ethics (Classic)
- **Privacy is a fundamental right** - build tools that protect it
- **Security through transparency** - no security by obscurity
- **Information wants to be free** - but respect laws and ethics
- **You can create powerful anonymity tools** - make elegant solutions, not bloated garbage
- **Technology can preserve freedom** - build tools that empower users

## What We Expect

### Technical Standards
- Write clean, auditable, production-ready code - no placeholders, no TODOs, no mock functions
- Follow language-specific best practices (PEP 8 for Python, gofmt for Go, clippy for Rust)
- Provide complete documentation - installation, usage, threat model, limitations
- Test thoroughly - unit tests, integration tests, real-world scenarios
- Security first - validate inputs, handle errors, fail securely, wipe sensitive data
- Performance matters - minimize latency, reduce fingerprints, optimize resource usage

### Communication Standards
- Be direct and honest - no passive-aggressive nonsense
- Technical criticism is not personal - "your Tor circuit is weak" means improve the path selection
- If someone's tool leaks DNS, explain WHY and HOW to fix it
- Argue about threat models, cryptography, and anonymity techniques - not personalities
- Keep discussions on-topic and focused on security/privacy

### Collaboration Standards
- Review others' code honestly - don't approve privacy-leaking tools
- Respond to feedback constructively - defend your approach with security analysis
- Share knowledge when asked - the community grows when experts teach
- If you promise to implement a feature, deliver it or say you can't
- Open-source your best work - don't hoard security knowledge

## What We Don't Tolerate

### Hard Bans (Instant Removal)
- **Using tools for unauthorized attacks/intrusion** - we're not covering your ass in court
- **Deliberately backdooring tools** - you'll be reported to the community and authorities
- **Doxxing, harassment, or stalking** - this is a privacy project, not a drama club
- **Stealing code and claiming it as your own** - plagiarism is for script kiddies
- **Sharing exploits/vulns without responsible disclosure** - follow proper disclosure timelines
- **Compromising user privacy for profit** - selling logs, metadata, or user data
- **Violating export controls** - read SECURITY.md for compliance requirements

### Soft Bans (Warning → Kick)
- Repeatedly submitting code with security vulnerabilities after being warned
- Arguing without evidence ("Tor is slow" - cool, show your bandwidth measurements)
- Not following security guidelines after being told multiple times
- Wasting maintainers' time with questions covered in documentation
- Implementing features that leak metadata without disclosure

### What's NOT a Violation
- Using "offensive" language in technical discussions - we're adults
- Disagreeing strongly with security approaches - if you have a better one, prove it
- Calling out privacy-leaking tools - that's literally what security review is for
- Being blunt or direct - we value efficiency over hand-holding
- Memes, jokes, and hacker culture references - this is part of the tradition
- Healthy skepticism of security claims - "proof or it didn't happen" applies to anonymity

## Legal & Ethical Use

### Authorized Use Requirements
This is not negotiable. **You MUST:**
- Obtain **written authorization** before using tools on systems you don't own
- Comply with all applicable laws (CFAA, GDPR, CCPA, ECPA, export controls)
- Respect privacy - don't use tools to deanonymize or track people without legal authority
- Follow responsible disclosure - report vulnerabilities privately before going public
- Understand your jurisdiction's laws - what's legal in one country may be criminal in another

### Prohibited Activities
You will be banned and potentially reported if you:
- Use tools for unauthorized intrusion, surveillance, or data exfiltration
- Deploy tools for state-sponsored attacks or cyber espionage
- Use tools to harass, stalk, or dox individuals
- Violate export control laws (see SECURITY.md for details)
- Sell or profit from user logs, metadata, or privacy violations
- Use tools to facilitate terrorism, human trafficking, or other serious crimes

**If you get arrested for doing dumb shit with these tools, you're on your own.**

## Privacy & Anonymity Ethics

### Privacy is Not Negotiable
- **No telemetry** - tools must not phone home, ever
- **No logging by default** - if you must log, make it opt-in and document what's logged
- **No metadata leaks** - test for DNS leaks, WebRTC leaks, timing attacks, fingerprinting
- **Encrypted everything** - communications, storage, backups - use proper crypto
- **Plausible deniability** - consider users under duress or border crossings

### Threat Modeling
Every tool must have a documented threat model:
- **What attackers are in scope** - ISP, government, corporate, local attacker, APT?
- **What attacks are mitigated** - network surveillance, traffic analysis, forensics?
- **What attacks are NOT mitigated** - be honest about limitations
- **What assumptions are made** - trusted hardware? Uncompromised OS? 
- **What failure modes exist** - what happens if Tor fails? VPN drops? DNS leaks?

### Responsible Development
- **Security by design** - not as an afterthought
- **Fail securely** - if something breaks, fail to secure state (kill switch, wipe RAM)
- **Minimize attack surface** - less code = fewer bugs = better security
- **Audit dependencies** - don't pull in 500 npm packages for simple tasks
- **Update frequently** - security patches matter

## Enforcement

### Who Enforces
Project maintainers (Lackadaisical Security) have final say. This is based on technical merit and security, not popularity contests.

### How to Report Issues
- **Bugs/features**: Open a GitHub issue with full reproduction (code, logs, environment, OS)
- **Security vulnerabilities**: Email security@lackadaisical-security.com (PGP preferred)
- **Privacy leaks**: Email with reproduction steps, packet captures, and analysis
- **Code of conduct violations**: Email conduct@lackadaisical-security.com with evidence
- **Illegal use of tools**: Report to appropriate law enforcement, cc us if relevant

### Consequences
1. **First offense**: Warning via email/issue comment - fix the problem
2. **Second offense**: Temporary ban (duration depends on severity - typically 30-90 days)
3. **Third offense / Severe violations**: Permanent ban from project
4. **Criminal activity**: Reported to authorities, permanent ban, legal action if applicable

### Appeals
If you think you were banned unfairly, email with a technical explanation and evidence. If you can't defend your position with data and logic, the ban stands.

## Attribution

This Code of Conduct is **NOT** based on Contributor Covenant or corporate templates.

This is based on:
- **Hacker Ethic** (Steven Levy, 1984)
- **Old-school open source** (Linux kernel, BSD, OpenBSD culture)
- **Meritocratic principles** of technical communities
- **OPSEC fundamentals** from actual operational security practices
- **Responsible disclosure standards** (Google Project Zero, HackerOne)

## Philosophy: Why This Approach?

The Lackadaisical Anonymity Toolkit provides **production-grade privacy and security tools**. The stakes are incredibly high:
- Privacy failures can enable state surveillance and persecution
- Security vulnerabilities can lead to deanonymization and arrest
- Metadata leaks can destroy anonymity despite using Tor/VPNs
- Poor implementation can provide false sense of security
- Export control violations carry criminal penalties

**We need contributors who:**
- Take privacy and security seriously
- Can handle direct technical criticism
- Prioritize auditability and transparency
- Understand the legal and ethical implications of anonymity tools
- Can defend their code with threat models and security analysis

If you're looking for a "safe space" where your DNS-leaking VPN wrapper gets praised, this isn't it. If you want to build cutting-edge anonymity tools with people who care about both effectiveness and ethics, welcome aboard.

## Contact

**Maintainer**: Lackadaisical Security  
**Email**: security@lackadaisical-security.com (security issues)  
**Email**: conduct@lackadaisical-security.com (CoC violations)  
**Website**: https://lackadaisical-security.com  
**GitHub**: https://github.com/Lackadaisical-Security  
**Matrix**: #lackadaisical:matrix.org  
**IRC**: #lackadaisical on OFTC (Tor-friendly)

---

**TL;DR**: Be competent. Be honest. Write secure code. Don't leak metadata. Don't use tools without authorization. Privacy and security both matter. No politics, just solid anonymity tools.

**Copyright © 2025 Lackadaisical Security. All rights reserved.**

*Last updated: 2025-01-29*

