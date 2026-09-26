"""OWASP Top 10:2025 (web): el catálogo contra el que se mide la cobertura. Cada entrada: id, nombre y las sondas del laboratorio que la cubren."""

WEB_TOP_10_2025 = (
    ("A01", "Broken Access Control", ("BOLA", "BFLA", "MASS")),
    ("A02", "Security Misconfiguration", ()),
    ("A03", "Software Supply Chain Failures", ()),
    ("A04", "Cryptographic Failures", ()),
    ("A05", "Injection", ("SQLI",)),
    ("A06", "Insecure Design", ()),
    ("A07", "Authentication Failures", ()),
    ("A08", "Software or Data Integrity Failures", ()),
    ("A09", "Security Logging & Alerting Failures", ()),
    ("A10", "Mishandling of Exceptional Conditions", ()),
)
