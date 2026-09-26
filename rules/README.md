# Tamandua rules

Built-in SAST rules maintained by the Tamandua project, written in Semgrep syntax for the **Opengrep** engine (LGPL-2.1). They are ours and ship under MIT (see `LICENSE`): the Semgrep registry rules changed license in December 2024 (internal use only, no offering them as a service) and cannot be part of a product.

Approach: **precision over coverage**. Each rule targets a concrete sink (code execution, SQL, deserialization, unescaped HTML, unverified TLS) and, where the language allows it, uses intra-file taint analysis from request inputs. "Non-literal argument" patterns are medium confidence and say so in `metadata.confidence`.

Severity: `ERROR` → high, `WARNING` → medium, `INFO` → low; `metadata.severity: CRITICAL` raises remote-execution sinks with a flow from the request to critical.

## Texts in English and Spanish

Every rule carries its finding title and its fix in both languages; the engine stores them as they are and each reader gets their own language:

```yaml
    message: "Pass a list of arguments without shell=True and validate the input."   # English fix; Opengrep requires it
    metadata: {cwe: [78], owasp: "A05:2025", category: injection, confidence: MEDIUM,
      title: {en: "Shell command built from dynamic input", es: "Comando de shell construido con datos dinámicos"},
      fix: {en: "Pass a list of arguments without shell=True and validate the input.",
            es: "Pasa una lista de argumentos sin shell=True y valida la entrada."}}
```

- `metadata.title`: a short, specific finding title, the way a security engineer would name it.
- `metadata.fix`: what to change. `message` repeats the English fix.
- Write each language on its own terms ("interpret, don't translate"); both are required (`tests/test_rules_i18n.py`).
- Keep `metadata` a flow mapping that starts on the `metadata:` line with `owasp` on that first line: the OWASP coverage view reads it from there.

User-authored custom rules are a separate, future feature managed from the panel; they don't live in this folder.

Validate: `docker run --rm --network none -v "$PWD/rules:/rules:ro" tamandua/opengrep:1.30.0 scan --validate --config /rules /rules`
