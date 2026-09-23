# Verificación del binario de Opengrep

El `Dockerfile` descarga el binario y lo comprueba contra el SHA-256 fijado (amd64 y arm64): no hace falta hacer nada a mano. Esta página documenta la verificación adicional con Cosign, para quien quiera repetirla al subir de versión.

Versión: v1.30.0 · artefacto `opengrep_manylinux_aarch64`

1. SHA-256 esperado (publicado por GitHub en el release): `a5d5a4a58ba5d46ff51e921663da1c2bba38f4b03987f4aeec87f16c6ad3ecae`
2. Firma Cosign (sin instalar nada, en contenedor):

```bash
docker run --rm -v "$PWD:/w" -w /w gcr.io/projectsigstore/cosign:v2.4.1 verify-blob \
  --certificate opengrep_manylinux_aarch64.cert --signature opengrep_manylinux_aarch64.sig \
  --certificate-identity-regexp 'https://github\.com/opengrep/opengrep/\.github/workflows/.+' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com opengrep_manylinux_aarch64
```

Resultado obtenido el 2026-09-23: `Verified OK`. Para otra arquitectura, repetir con el artefacto correspondiente.
