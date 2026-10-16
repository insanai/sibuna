# Security policy

We welcome confidential reports of vulnerabilities in Sibuna: the daemon, the browser proof-of-work code, the console, storage, and the official build and packaging recipes. The maintainers handle security reports through GitHub's private channel. We publish no personal names, email addresses or telephone numbers as security contacts.

## Supported versions

| Version | Security fixes |
| --- | --- |
| Latest release (including the 1.0.0 pre-releases until 1.0.0) | Supported |
| Earlier releases | Upgrade; backports only when announced |
| Unreleased branches and local builds | Reports welcome; no support commitment |

The releases are listed on the [releases page](https://github.com/insanai/sibuna/releases). Distribution maintainers may support backports of their own. A package-manager rollback does not reverse a database migration; follow the release notes.

## Report privately

Use [GitHub private vulnerability reporting](https://github.com/insanai/sibuna/security/advisories/new) with a GitHub account. The report reaches the repository's maintainers and is not a public issue. GitHub may show the accounts that take part in a private report to each other; this policy cannot hide identity information that a GitHub profile already shows.

Do not put details of an unfixed vulnerability in a public issue, discussion, pull request, design record or package review. If the private form is unavailable, open an issue that only asks for a private security contact, without technical details, logs or deployment names, and wait for a private channel before sending the report. There is no separate security email address.

Include what you can; a working exploit or a severity score is not required:

- The affected release or commit, package channel, operating system, architecture and build features.
- A summary of the impact and of the access or configuration it needs.
- A minimal reproduction against an isolated test deployment, or other evidence.
- Sanitized configuration, request and response samples, and relevant logs.
- A suggested mitigation, related identifiers, and whether exploitation or disclosure is already known.
- Your preferred disclosure timeline and, optionally, how you wish to be credited; a legal name is not required.

Remove live admission seeds, console and peer keys, database URLs, passwords, cookies, recovery codes, private certificates, personal data and unrelated traffic; use synthetic data. Tell us privately if release credentials may be compromised. Test only systems you own or may test, without disrupting service or reading other people's data.

## Response and disclosure

We aim to acknowledge a report within **3 business days**, to give a first assessment within **7 business days**, and to send an update at least weekly while we investigate a confirmed issue. These are the targets of a small team, not a service-level agreement. If you hear nothing, follow up privately; a contact request in a public issue must still hold no technical details.

We assess reproducibility, impact, exposure, affected versions and mitigations. A report without a complete proof of concept is still a report. A confirmed issue receives a fix or a documented mitigation, a regression test, and upgrade guidance; actively exploited and high-impact issues come first.

We coordinate disclosure with the reporter and affected downstream maintainers, normally aiming for a fix and an advisory within **90 days of receipt**. We agree on extensions when necessary; active exploitation or an already public issue may need earlier guidance. Advisories state the affected and fixed versions, the impact, mitigations and upgrade limits. We request a CVE when appropriate and credit reporters only with their consent. Advisories name project roles, not private contacts, and omit reporter identities without consent and identifying deployment data.

We offer no bounty, payment or legal safe harbor. Ordinary bugs and support questions belong in public issues once they hold no sensitive material.

## Deployment responsibilities

Run Sibuna under an unprivileged account with a private, persistent admission seed (`--secret-file`), independent console and peer keys, TLS at the ingress, and tested backups. The console is off until `--console` is given. `/__sibuna/metrics` and `/__sibuna/health` bypass the declarative policy, so restrict them at the ingress or network boundary. The health route reports that the listener answers, not that the origin or the storage is ready. Proof of work does not stop every denial-of-service attack and does not establish that a client is human.

On Unix, Sibuna refuses key, credential and database URL files that the group or others may read. Windows has no such mode bits and Sibuna does not inspect ACLs there: restricting those files to the account that runs Sibuna is the operator's job.

The release assets are not signed. Verify each download against `SHA256SUMS` from the release page before installing it.
