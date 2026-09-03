# Security Policy

## Supported Versions

Symposium Relay is under active development.

| Version               | Supported   |
| --------------------- | ----------- |
| Latest stable release | Yes         |
| Current prerelease    | Best effort |
| Older releases        | No          |

Users are encouraged to update to the latest stable release before reporting an issue that may already have been fixed.

## Reporting a Vulnerability

Please do not report security vulnerabilities through public GitHub issues, discussions, or other public channels.

Use GitHub Private Vulnerability Reporting for this repository:

1. Open the repository's **Security** page.
2. Open **Advisories**.
3. Select **Report a vulnerability**.
4. Provide as much detail as possible.

Useful information includes:

* affected Symposium Relay version or commit;
* vulnerability description;
* steps to reproduce;
* expected and actual behavior;
* potential security impact;
* proof-of-concept code, logs, or screenshots when relevant;
* suggested mitigation or fix, if known.

Please avoid including unnecessary personal information, credentials, private keys, access tokens, or data belonging to third parties.

## Response Process

We aim to:

* acknowledge a vulnerability report within 3 business days;
* perform initial triage within 7 days;
* keep the reporter informed about significant progress;
* develop and test a fix based on severity and complexity;
* coordinate public disclosure with the reporter when appropriate.

Critical vulnerabilities may be handled on an accelerated schedule.

These timeframes are targets rather than guarantees, particularly while the project is under active development.

## Coordinated Disclosure

Please give the project maintainers a reasonable opportunity to investigate and address a vulnerability before public disclosure.

We ask reporters to:

* avoid publicly disclosing unresolved vulnerabilities;
* avoid accessing, modifying, or deleting data that does not belong to them;
* avoid intentionally degrading or disrupting systems or services;
* limit testing to what is necessary to demonstrate the vulnerability;
* keep vulnerability details confidential while remediation is in progress.

Once a fix is available, we may publish a GitHub Security Advisory describing the vulnerability, affected versions, remediation, and acknowledgements.

## Scope

Security reports relevant to Symposium Relay include, but are not limited to:

* authentication or authorization bypasses;
* moderator privilege escalation;
* remote code execution;
* cryptographic or E2EE implementation flaws;
* signaling or WebRTC vulnerabilities;
* room isolation failures;
* sensitive information disclosure;
* denial-of-service vulnerabilities with meaningful security impact;
* dependency or software supply-chain vulnerabilities;
* release artifact integrity or provenance issues;
* secret or credential exposure.

General bugs, feature requests, usability problems, and non-security crashes should be reported through the normal GitHub issue tracker.

## Good-Faith Research

We welcome responsible, good-faith security research intended to improve Symposium Relay.

Please minimize privacy impact, data access, service disruption, and harm to users while conducting research.

Thank you for helping improve the security of Symposium Relay.
