# Verifying the Opengrep binary

The `Dockerfile` downloads the binary and checks it against the pinned SHA-256 (amd64 and arm64): there's nothing to do by hand. This page documents the extra Cosign verification, for anyone who wants to repeat it when upgrading.

Version: v1.30.0 · artifact `opengrep_manylinux_aarch64`

1. Expected SHA-256 (published by GitHub on the release): `a5d5a4a58ba5d46ff51e921663da1c2bba38f4b03987f4aeec87f16c6ad3ecae`
2. Cosign signature (nothing to install, in a container):

```bash
docker run --rm -v "$PWD:/w" -w /w gcr.io/projectsigstore/cosign:v2.4.1 verify-blob \
  --certificate opengrep_manylinux_aarch64.cert --signature opengrep_manylinux_aarch64.sig \
  --certificate-identity-regexp 'https://github\.com/opengrep/opengrep/\.github/workflows/.+' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com opengrep_manylinux_aarch64
```

Result on 2026-09-23: `Verified OK`. For another architecture, repeat with the matching artifact.
