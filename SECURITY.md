# Security policy

Sibuna welcomes confidential vulnerability reports about its daemon, browser
proof-of-work code, management console, storage, and official build/packaging tools.
The designated project maintainers handle security reports through GitHub's private
channel. Personal names, email addresses, phone numbers, and private contact details
are not published as security contacts.

## Supported versions

| Version | Security fixes |
| --- | --- |
| Latest stable release | Supported |
| Earlier releases | Upgrade; backports only if explicitly announced |
| Unreleased branches and local package candidates | Reports welcome; no release-support commitment |

The latest stable release is on the [releases page](https://github.com/insanai/sibuna/releases).
Distribution maintainers may support their own backports. Package-manager rollback
does not reverse database migrations; follow the release's compatibility guidance.

## Report privately

Use [GitHub private vulnerability reporting](https://github.com/insanai/sibuna/security/advisories/new)
with a GitHub account. Reports are shared with authorized repository maintainers,
not posted as public issues. GitHub may display participating account identities to
private-report participants. This policy does not promise anonymity from GitHub or
hide identity information already present in a participant's profile.

Do not put unpatched vulnerability details in a public issue, discussion, pull
request, SID, or package-review thread. If the private form is unavailable, open an
issue containing only a request for a private security contact, without exploit
details, sensitive logs, or deployment identity. Wait for a verified private channel
before sending the report. No separate security email address is advertised.

Include what you can; a full exploit or severity score is not required:

- Affected release/commit, package channel, OS/architecture, and relevant build flags.
- Summary, impact, and required access or configuration.
- Minimal reproduction against an isolated test deployment, or supporting evidence.
- Sanitized configuration, request/response samples, and relevant logs.
- Suggested mitigation, related identifiers, and whether exploitation or public disclosure is known.
- Preferred disclosure timeline and optional contact/credit preference; a legal name is not required.

Remove live seeds, console/cluster keys, passwords, cookies, recovery codes, private
certificates, personal data, and unrelated customer traffic. Use synthetic test data.
Mention compromised release credentials privately. Test only systems you own or have
permission to test, without disrupting services or accessing other people's data.

## Response and disclosure

We aim to acknowledge reports within **3 business days**, provide an initial
assessment within **7 business days**, and send an update at least weekly while a
confirmed issue is actively being investigated. These are small-team targets, not
an SLA or a guaranteed resolution time. If acknowledgement is missing, follow up
privately; the contact-request fallback above must contain no technical details.

We assess reproducibility, impact, exposure, affected versions, and mitigations.
Lack of a complete proof of concept does not by itself invalidate a report. Confirmed
issues receive a fix or documented mitigation, regression checks, and upgrade
guidance. Actively exploited and high-impact issues receive priority.

We coordinate disclosure with the reporter and affected downstream maintainers,
normally aiming for a fix and advisory within **90 days of receipt**. Agree on
extensions when necessary; active exploitation or an already-public issue may need
earlier guidance. This is a coordination target, not a blanket embargo requirement.
Advisories state affected/fixed versions, impact, mitigations, and upgrade limitations.
We request a CVE when appropriate and offer optional credit only with consent.
Public advisories use project roles and omit private maintainer contacts, reporter
identities without consent, and identifying deployment data.

We do not promise a bounty, payment, or legal safe harbor. Ordinary bugs/support can
use public issues after confirming they contain no sensitive material.

## Deployment responsibilities

Use a non-root service identity, independent private persistent admission/console
keys, suitable TLS ingress, and tested backups. Console startup is explicit.
`/__sibuna/metrics` and `/__sibuna/health` bypass declarative policy: restrict their
exposure at the ingress/network boundary. Health indicates listener status, not full
origin/storage readiness. Proof of work does not prevent every denial-of-service
attack or establish human identity.

SID 0001 and SID 0011 under `docs/sid/records/` define maintainer handling and launch
gates. Verify private-report access and notifications before a new package launch.
