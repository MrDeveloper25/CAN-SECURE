# CAN-Secure

## 0. Resumen de decisiones clave

| Decisión | Elección | Justificación breve |
|---|---|---|
| Formato de trama | **Frame dividido (Opción A)** sobre CAN-FD | Permite separar payload cifrado y metadatos de autenticación |
| Cifrado y autenticación | AES-256-GCM, nonce de 96 bits y tag de 128 bits | Proporciona confidencialidad e integridad/autenticidad en una operación |
| Anti-replay | Contador monotónico por ID, actualizado solo después de autenticar | Un paquete repetido no se entrega a la aplicación |
| Gestión de claves | Clave AES-256 de demostración precompartida | La provisión y rotación de claves para producción siguen pendientes |
| Política ante fallos | Modo de alerta y rechazo tras fallos consecutivos | Evita degradación silenciosa del sistema |
| Metodología de evaluación | Comparación baseline (sin protección) vs. CAN-Secure | Da evidencia cuantitativa real de la mejora, no solo cifras aisladas |

---

## 1. Arquitectura general

```
┌──────────────┐        ┌──────────────┐         ┌──────────────┐
│   ECU A      │        │   ECU B      │         │  Monitor/IDS │
│ (nodo sim.)  │        │ (nodo sim.)  │         │  (anomalías) │
│              │        │              │         │              │
│ CAN-Secure   │        │ CAN-Secure   │         │ CAN-Secure   │
│ Wrapper      │        │ Wrapper      │         │ Sniffer      │
└──────┬───────┘        └──────┬───────┘         └──────┬───────┘
       │                       │                        │
       └───────────┬───────────┴────────────┬───────────┘
                    │       BUS CAN (vcan0)   │
                    └─────────────────────────┘
```

Cada nodo corre tres capas internas: aplicación (payload real), CAN-Secure (cifrado autenticado AES-GCM, anti-replay, política de fallos) y transporte (`python-can` sobre SocketCAN o el bus virtual de `python-can`).
De acuerdo al estandar del modelo OSI, el protocolo CAN abarca las capas de datos y fisica, CAN-Secure se situa en el punto medio entre las capas de transporte y red.
Al enviar, CAN-Secure cifra el payload y autentica con AES-GCM el payload cifrado junto con el ID base CAN y el contador. El receptor verifica el tag antes de descifrar y entregar el payload; el anti-replay evita aceptar contadores repetidos o antiguos. El IDS realiza la misma verificación para clasificar el tráfico.

### Estructura de módulos

```
can-secure/
├── core/
│   ├── crypto.py            # Cifrado/descifrado autenticado AES-GCM
│   ├── key_manager.py       # claves simétricas por ECU, rotación
│   ├── frame_codec.py       # empaqueta/desempaqueta nonce + tag + contador
│   ├── replay_guard.py      # contador de secuencia / ventana anti-replay
│   └── failure_policy.py    # política de respuesta ante fallos de verificación
├── nodes/
│   ├── secure_ecu.py        # nodo que envía y recibe tramas autenticadas
│   └── ids_monitor.py       # sniffer que analiza tráfico y detecta anomalías
├── attacks/
│   ├── spoofing.py
│   ├── replay.py
│   └── dos_flood.py
├── sim/
│   └── setup_vcan.sh        # crea la interfaz virtual vcan0
└── eval/
    ├── baseline_run.py      # corre ataques SIN CAN-Secure (línea base)
    ├── secure_run.py        # corre los mismos ataques CON CAN-Secure
    └── metrics.py           # calcula KPIs y compara baseline vs. CAN-Secure
```

---

## 2. Formato de trama: frame dividido

Dado que el protocolo requiere un frame para el payload y otro para los metadatos criptográficos, se emplea CAN-FD. AES-GCM cifra el payload y genera un tag de 16 bytes; cada mensaje protegido se representa así:

| Frame | ID | Contenido |
|---|---|---|
| Frame 1 (datos) | `ID_base` | Ciphertext (mismo tamaño que el payload, máximo 64 bytes) |
| Frame 2 (autenticación) | `ID_base + 1` | Nonce (12 bytes) + tag GCM (16 bytes) + contador (4 bytes), total 32 bytes |

El ID base y el contador se codifican como datos asociados (AAD): quedan autenticados, pero no cifrados. El receptor reensambla el par, comprueba el contador, verifica el tag y solo entonces acepta el contador y entrega el texto plano. Deben reservarse IDs consecutivos para cada par. El nonce se genera aleatoriamente en el prototipo; una integración de producción debe garantizar formalmente que no se repita con la misma clave, incluso tras reinicios o rotaciones.

Cada mensaje protegido ocupa dos frames, frente a uno para un mensaje CAN-FD sin protección; el overhead real en bytes y tiempo de bus depende también del tamaño del payload y se debe medir en la evaluación.

---

## 3. Anti-replay y política ante fallos

- **`replay_guard.py`**: cada ECU mantiene el último contador autenticado recibido por `ID_base`. Se rechaza cualquier mensaje con contador ≤ al último aceptado. El estado se actualiza después de verificar AES-GCM, para que un paquete inválido no adelante el contador.
- **`failure_policy.py`** (nuevo): define qué pasa cuando falla la verificación:
  - 1er fallo → se descarta el mensaje, se registra localmente.
  - 3 fallos consecutivos del mismo `ID_base` → el nodo entra en **modo de alerta**, notifica al IDS monitor mediante un frame especial autenticado con la clave maestra.
  - El modo de alerta puede escalar a una acción de degradación segura (ej. ignorar temporalmente ese ID hasta intervención), lo cual debe documentarse como límite del prototipo (no se simula acción física real sobre el vehículo).

---

## 4. Gestión de claves y KPI de overhead computacional

- El prototipo usa una clave AES-256 compartida de demostración definida en `core/crypto.py`; **no es una clave de producción**. No hay todavía aprovisionamiento por ECU ni rotación integrada en el flujo de los nodos.
- La rotación de claves vía un frame de actualización autenticado con clave maestra es trabajo futuro. Un despliegue debe definir distribución, almacenamiento, separación de claves por emisor/receptor o grupo y recuperación tras reinicio.
- **KPI — overhead computacional**: tiempo de CPU para cifrar y autenticar, y para verificar/descifrar con AES-GCM, medido en el entorno de simulación. Esto **no es representativo de un microcontrolador embebido real** (ej. ARM Cortex-M); se debe comparar con mediciones en el hardware objetivo.
- **KPI nuevo — overhead de tráfico**: % de incremento en número de frames por el esquema de frame dividido, contra el tráfico CAN sin protección.
Nota: Implementación principalmente pensada en python, con posibilidades de traspasar a uso de APIs de C++ en caso de requerir optimización o que los tiempos de respuesta no den los resultados esperados en primera instancia.

---

## 5. Justificación del esquema frente a alternativas

Se comparan alternativas de autenticación y confidencialidad para el prototipo:

| Esquema | Ventaja | Por qué no se elige |
|---|---|---|
| **TESLA protocol** | Autenticación eficiente para broadcast | Requiere sincronización de tiempo y autenticación con retraso; no cifra el payload por sí mismo |
| **CANAuth** | Diseñado específicamente para CAN, usa IDs adicionales | Requiere modificar el esquema de IDs; la confidencialidad depende del diseño usado |
| **MaCAN** | Gestión de claves centralizada para CAN | Mayor complejidad y overhead de negociación para este prototipo |
| **HMAC-SHA256** | Autenticación e integridad ampliamente entendidas | No cifra el payload; combinarlo con cifrado requiere diseñar y gestionar ambos mecanismos correctamente |
| **AES-256-GCM (elegido)** | Cifrado y autenticación AEAD en una operación; tag de 128 bits | Exige nonce único por clave y gestión segura de claves; CAN-FD se usa para transportar el par de frames |

AES-GCM autentica el ciphertext, el ID base y el contador. No se cifra el tag; su función es permitir verificar autenticidad e integridad. La clave fija incluida en el repositorio sirve únicamente para reproducir la demo.

---

## 6. Metodología de evaluación con línea base (baseline)

En vez de reportar únicamente "% de detección de ataques" de forma aislada, se establece un **caso base**:

1. **`baseline_run.py`**: ejecuta spoofing, replay y DoS sobre CAN **sin** CAN-Secure. Se documentan los resultados (ej. 100% de mensajes falsos aceptados, sin detección).
2. **`secure_run.py`**: ejecuta los mismos ataques **con** CAN-Secure activo.
3. **`metrics.py`**: calcula y compara ambos escenarios, generando la evidencia central del proyecto — el "antes y después" — en lugar de una cifra sin contexto.

### KPIs finales (actualizados)

| KPI | Meta |
|---|---|
| % de detección de ataques | >90% |
| Latencia añadida por mensaje | <5 ms |
| Reducción de tráfico malicioso aceptado | >80% |
| Tasa de falsos positivos | <10% |
| Overhead de tráfico (frames adicionales) | Reportado, sin meta fija — es informativo |
| Overhead computacional por mensaje (AES-GCM) | Reportado, con comparación a hardware embebido de referencia |
| Mejora relativa vs. baseline | Reportado como comparación directa |

---

## 7. Pruebas manuales de desarrollo

Se incluye `eval/manual_test.py` como una interfaz de terminal para probar el flujo actual sin hardware ni configurar `vcan0`. Todos los escenarios usan canales virtuales efímeros de `python-can`; no se conectan a interfaces SocketCAN.

Desde la raíz del repositorio, instala las dependencias y abre el menú:

```bash
python3 -m pip install -r requirements.txt
python3 -m eval.manual_test
```

El menú permite ejecutar individualmente:

1. Mensaje legítimo: cifrado AES-GCM y recuperación del payload original.
2. Trama sin frame de autenticación: rechazo y registro del fallo.
3. Tag alterado: rechazo y comprobación de que el contador anti-replay no avanza.
4. Replay exacto: la primera entrega se acepta y el reenvío capturado se rechaza.
5. IDS: validación de una trama legítima y detección de una trama no autenticada.
6. DoS: ráfaga virtual y comprobación de alertas con el umbral actual del IDS.

Cada prueba informa el proceso, el resultado esperado y el observado. Para ejecutar todas las pruebas sin interacción y obtener un código de salida útil para automatización:

```bash
python3 -m eval.manual_test --all
```

Esta utilidad es solo para desarrollo: usa la clave pública de demostración del repositorio y no mide rendimiento de hardware ni valida una integración vehicular. No usar esa clave ni estos resultados como evidencia de seguridad de producción.

---

## 8. Flujo de trabajo de implementación sugerido

1. Montar `vcan0` con `setup_vcan.sh`; confirmar comunicación básica entre dos procesos `python-can`.
2. Validar `frame_codec.py` + `crypto.py`: nodo A cifra con AES-GCM y nodo B verifica el tag, descifra y recupera el payload.
3. Validar `replay_guard.py`; comprobar que los mensajes repetidos se rechazan y que un tag inválido no actualiza el contador.
4. Agregar `key_manager.py` con rotación simple.
5. Agregar `failure_policy.py` y conectar las alertas al `ids_monitor.py`.
6. Correr `eval/baseline_run.py` (sin protección) y guardar resultados.
7. Correr `eval/secure_run.py` (con protección) contra los mismos ataques.
8. Generar comparación final con `eval/metrics.py` para el informe al comité.

---

## 9. Documento y entregables recomendados para el comité

- Código fuente completo con README de instalación y ejecución.
- Informe de resultados baseline vs. CAN-Secure (tablas + gráficas de los KPIs).
- Diagrama de arquitectura (sección 1) y diagrama de trama dividida (sección 2).
- Documentación técnica breve de la política de fallos y sus límites (sección 3).
- Justificación comparativa de esquemas de autenticación (sección 5), para anexar a la sección "Propuesta de solución" del cuestionario original.
