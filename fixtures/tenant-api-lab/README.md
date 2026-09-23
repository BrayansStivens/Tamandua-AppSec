# Tenant API Lab

Fixture local y sintético para medir un circuito de auditoría de código/API. Incluye cinco casos vulnerables y sus cinco controles corregidos: BOLA entre organizaciones, función administrativa sin autorización, exposición de un campo sensible, asignación masiva de rol e inyección SQL. [`cases.json`](cases.json) enumera los diez casos y el test suite comprueba su ground truth. Esto no mide por sí solo la precisión de una herramienta externa.

**Advertencia:** la variante `vulnerable` contiene fallos intencionales. El servidor solo se enlaza a `127.0.0.1`. No publicarlo en Internet ni usar datos reales. Los tokens y datos son ficticios.

Requisitos para esta copia del laboratorio: Python 3.9 o superior; solo librería estándar. No hay modelo de IA, descargas ni gasto externo.

```bash
cd appsec-agent/fixtures/tenant-api-lab
python3 -m unittest -v test_app.py
python3 app.py --variant vulnerable --port 8765
# En otra terminal: Authorization: Bearer token-alice
```

La variante corregida se ejecuta con `--variant fixed`. Para un experimento comparable, registrar hash de estos archivos, variante, token sintético, petición/respuesta, hallazgo, costo, cobertura y resultado del retest. El modo `fixed` corrige solo los cinco casos definidos; no constituye una certificación de seguridad del fixture.

[`fixture-lock.json`](fixture-lock.json) fija los hashes SHA-256 de código, casos y pruebas de la versión 0.1.0. Si cambia cualquiera de esos archivos, actualizar versión y hashes antes de reutilizar resultados comparativos. La licencia de distribución del fixture todavía no está decidida; su uso actual es interno.
