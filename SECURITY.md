English · [Español](SECURITY.es.md)

# Security policy

## Reporting a vulnerability

**Don't open a public issue.** Use GitHub's private reporting: the **Security → Report a vulnerability** tab of this repository (GitHub Security Advisories).

If you can, include:

- the version (`/api/health` or the label in the panel) and how you deploy it;
- steps to reproduce it and the impact you see;
- whether it's already public or being exploited.

Don't include real secrets, yours or anyone else's. We reply as soon as we can; this project is maintained by volunteers, so there is no guaranteed timeline, but issues that expose credentials or code get priority.

## Supported versions

Only the latest version on the `main` branch.

## Scope

Any flaw in Tamandua itself is in scope: authentication, sessions, the secret store, the API, the panel and how engines are run. Flaws in third-party tools (Trivy, Gitleaks, Opengrep) are out of scope: report them to their projects. Using the Docker socket is a documented trade-off in [docs/security.md](docs/security.md#known-trade-offs).
