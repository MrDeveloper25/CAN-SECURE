# CAN-Secure

## 0. Resumen de decisiones clave

| Decisión | Elección | Justificación breve |
|---|---|---|
| Formato de trama | **Frame dividido sobre CAN-FD | Permite separar payload cifrado y metadatos de autenticación |
| Cifrado y autenticación | AES-256-GCM, nonce de 96 bits y tag de 128 bits | Proporciona confidencialidad e integridad/autenticidad en una operación |
| Anti-replay | Contador monotónico por ID, actualizado solo después de autenticar | Un paquete repetido no se entrega a la aplicación |
| Gestión de claves | Clave demo en modo manual; almacén local persistente disponible para pruebas | No sustituye a un HSM/secure element ni define provisión remota de producción |
| Política ante fallos | Modo de alerta y rechazo tras fallos consecutivos | Evita degradación silenciosa del sistema |
| Metodología de evaluación | Comparación baseline (sin protección) vs. CAN-Secure | Cuantifica los resultados de escenarios definidos |

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
│   ├── frame_reassembler.py # valida y reúne los dos frames por ID/contador
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
    ├── baseline_run.py      # demo de ataques SIN CAN-Secure (línea base)
    ├── secure_run.py        # demo de ataques CON CAN-Secure
    ├── comparison.py        # compara ambos modos en escenarios emparejados
    └── metrics.py           # resume las métricas de la comparación
```

---

## 2. Formato de trama: frame dividido

El protocolo usa dos frames CAN-FD por mensaje. Cada frame empieza con un byte identificador de tipo y un contador de 32 bits en orden big-endian. El receptor empareja por `(ID_base, contador)`, no por el orden de llegada. No hay negociación automática de versiones:

| Frame | ID | Contenido |
|---|---|---|
| Datos | `ID_base` | Tipo `0xC1` + contador (4 bytes) + ciphertext + padding cero |
| Autenticación | `ID_base + 1` | Tipo `0xC2` + contador (4 bytes) + longitud de ciphertext (1 byte) + nonce (12 bytes) + tag GCM (16 bytes) + padding cero |

El frame de autenticación contiene 34 bytes de campos y se completa con ceros hasta 48 bytes, una longitud DLC válida de CAN-FD. El frame de datos también se rellena con ceros a la siguiente longitud DLC válida; el tamaño original del ciphertext se incluye en el frame de autenticación y el receptor valida el padding. El encabezado del frame de datos deja un máximo de **59 bytes de payload cifrado** (y, por tanto, de texto plano para AES-GCM). Payloads mayores se rechazan antes de transmitir; no se fragmentan implícitamente.

El ID base y el contador se codifican como datos asociados (AAD): quedan autenticados, pero no cifrados. El receptor comprueba que ambos frames tengan el mismo contador, aplica anti-replay, verifica el tag y solo entonces entrega el texto plano. Se admiten frames intercalados y llegada del frame de autenticación antes del de datos. Un par incompleto expira tras un segundo por defecto; el reensamblador limita a 128 los pares pendientes por nodo.

Se admiten IDs CAN estándar de 11 bits; cada mensaje reserva `(ID_base, ID_base + 1)` y cada ID base debe tener un único emisor, que mantenga un contador monotónico por clave. Los pares no pueden solaparse: las bases consecutivas no son válidas. Las ECUs y el IDS aceptan `base_ids` para validar una asignación explícita. La integración debe configurar la lista completa y reservar sus IDs frente a cualquier otro tráfico. El modo sin lista permite la demo flexible, pero no valida la asignación global del bus.

El modo manual conserva contadores solo en memoria. Para una prueba con reinicios se puede usar el almacén persistente descrito en la sección 4 y asignar un archivo anti-replay por receptor.

Cada mensaje protegido necesita dos frames, frente a uno para un mensaje CAN-FD sin protección; el overhead real en bytes y tiempo de bus depende también del tamaño del payload y se debe medir en la evaluación.

---

## 3. Anti-replay y política ante fallos

- **`replay_guard.py`**: cada ECU mantiene el último contador autenticado recibido por `ID_base`. Se rechaza cualquier mensaje con contador ≤ al último aceptado. El estado se actualiza después de verificar AES-GCM, para que un paquete inválido no adelante el contador.
- **`failure_policy.py`**: registra localmente los fallos por ID y señala el umbral configurado. La notificación autenticada al IDS y una acción de degradación segura todavía no están integradas; no se simula una acción física sobre el vehículo.

---

## 4. Gestión de claves y KPI de overhead computacional

- El modo manual usa `DEMO_KEY` en memoria y solo sirve para reproducir escenarios. `KeyManager.persistent(path)` crea una clave AES-256 aleatoria si el archivo no existe, o carga la clave almacenada. El archivo se crea con permisos `0600` y el directorio privado sin acceso de grupo/otros (por defecto `0700`); se rechazan permisos de grupo/otros, enlaces simbólicos y archivos de estado inválidos.
- Se deriva con HKDF-SHA256 una clave AES-256 distinta por `ID_base` (grupo de mensajes). Emisor, receptor e IDS deben compartir la misma clave raíz y versión de derivación para ese grupo; un ID base distinto produce otra clave. Esto separa los grupos dentro del prototipo, pero no sustituye secretos independientes y protegidos por ECU en producción.
- El almacén mantiene la clave raíz activa, el historial de huellas de claves usadas, un prefijo de nonce y su contador de 64 bits, además de contadores de envío por `ID_base`. Cada nonce se forma con un prefijo aleatorio de 32 bits y un contador persistente de 64 bits; el contador se guarda atómicamente y se sincroniza a disco antes de cifrar. Un error posterior consume el nonce, pero no lo reutiliza. Los contadores de envío también se guardan antes de transmitir, por lo que un reinicio puede saltar números, pero no reiniciarlos.
- En las pruebas virtuales, todos los emisores que comparten la misma clave raíz deben usar el mismo almacén persistente para serializar la asignación de nonces y contadores. El archivo anti-replay se configura por receptor mediante `replay_state_path`; no se debe compartir entre ECU e IDS porque sus historiales de recepción son independientes. Ambos tipos de archivo deben vivir en directorios privados y conservarse junto con su clave.
- `rotate_key(new_key)` guarda la nueva clave de forma atómica, crea un prefijo de nonce nuevo y conserva los contadores de envío; si no se proporciona clave, genera una aleatoria de 256 bits. Rechaza la reutilización de una clave usada anteriormente. Los otros procesos recargan la clave antes de cifrar/verificar. La rotación es inmediata: mensajes en vuelo cifrados con la clave previa fallan; no existe periodo de gracia ni actualización autenticada por CAN.
- El almacén de prueba guarda la clave raíz en claro, protegida solo por permisos locales; no es una bóveda. No protege frente a acceso privilegiado, restauración de una copia antigua del estado, robo de archivos ni pérdida de disco. En producción se requiere provisión autenticada, secretos independientes por ECU o grupo, almacenamiento protegido (HSM/secure element), recuperación coordinada y protección anti-rollback. Si se restaura una copia anterior del estado, no se debe volver a cifrar con esa clave: hay que provisionar una clave nueva mediante un proceso seguro.
- El almacén usa primitivas de Linux (`fcntl`) y está destinado a pruebas locales; no implementa sincronización distribuida entre ECUs físicas. No se debe copiar un almacén independiente a varios emisores que compartan la misma clave: sus prefijos aleatorios no constituyen una garantía global de unicidad. En el prototipo virtual, compartir un único archivo y su bloqueo serializa las reservas.
- **KPI — overhead computacional**: tiempo de CPU para cifrar y autenticar, y para verificar/descifrar con AES-GCM, medido en el entorno de simulación. Esto no es representativo de un microcontrolador embebido real; se debe comparar con mediciones en el hardware objetivo.
- **KPI nuevo — overhead de tráfico**: % de incremento en número de frames por el esquema de frame dividido, contra el tráfico CAN sin protección.

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

El módulo principal de evaluación comparable es **`eval/comparison.py`**; utiliza `eval/metrics.py` para resumir los resultados. A diferencia de los scripts de demostración individuales `baseline_run.py` y `secure_run.py`, cada corrida empareja en canales virtuales aislados los mismos escenarios sin protección y con CAN-Secure:

1. **Spoofing:** se envía una trama CAN-FD sin autenticación.
2. **Replay:** se envía dos veces el mismo par de frames protegido con el mismo contador.
3. **DoS:** se inyecta una ráfaga configurable (100 frames por defecto).
4. **Tráfico benigno:** se envían 10 mensajes del mismo payload en ambos modos.

Cada escenario usa una instancia nueva del observador, IDS y canal; esto evita que contadores y métricas de una corrida contaminen la siguiente. La comparación reporta:

- Detección por evento de ataque (3 eventos por corrida), no alertas divididas por frames.
- Frames maliciosos recibidos por el observador baseline y mensajes maliciosos aceptados por CAN-Secure. La aceptación en baseline se indica como no aplicable: este benchmark mide tramas recibidas, no ejecuta una aplicación baseline que valide mensajes.
- Alertas falsas durante el lote benigno, normalizadas por mensaje benigno. Es una tasa de alerta por mensaje para estos casos (no una tasa estadística de falsos positivos generalizable); baseline se muestra como no aplicable porque no tiene clasificador.
- Overhead de frames y bytes de payload de frames en el tráfico benigno.
- Mediana y p95 del tiempo local de preparar/enviar mensajes con `python-can`.

Ejecuta desde la raíz del proyecto:

```bash
python3 -m pip install -r requirements.txt
python3 -m eval.comparison
```

Opciones disponibles:

```bash
python3 -m eval.comparison --runs 5 --dos-count 100
python3 -m eval.comparison --runs 3 --dos-count 100 --output /tmp/can-secure-results.json
```

`--runs` debe ser positivo; `--dos-count` debe ser al menos 51 para superar el umbral actual del IDS. El JSON opcional incluye configuración, resumen y resultados por escenario/corrida. El reporte es determinista en la cantidad de eventos, pero las latencias varían con el equipo y la carga; son mediciones locales del bus virtual, no latencia física CAN ni rendimiento de hardware embebido. Los bytes reportados son los payloads de los frames, no incluyen arbitraje, CRC, bit stuffing ni el tiempo real de bus. Los resultados validan estos escenarios definidos, no son una certificación ni evidencia suficiente para producción. `baseline_run.py` y `secure_run.py` se conservan como demos aisladas; para una comparación use `eval.comparison`.

---

## 7. Pruebas manuales de desarrollo

`eval/manual_test.py` es el módulo de pruebas de integración manual y regresión de componentes. No sustituye la comparación baseline/protegida de `eval/comparison.py`.

Se incluye `eval/manual_test.py` como una interfaz de terminal para probar el flujo actual sin hardware ni configurar `vcan0`. Todos los escenarios usan canales virtuales efímeros de `python-can`; no se conectan a interfaces SocketCAN.

Desde la raíz del repositorio, instala las dependencias y abre el menú:

```bash
python3 -m pip install -r requirements.txt
python3 -m eval.manual_test
```

El menú permite ejecutar individualmente:

1. Mensaje legítimo: cifrado AES-GCM y recuperación del payload original.
2. Trama sin formato CAN-Secure: rechazo y registro del fallo.
3. Tag alterado: rechazo y comprobación de que el contador anti-replay no avanza.
4. Replay exacto: la primera entrega se acepta y el reenvío capturado se rechaza.
5. IDS: validación de una trama legítima y detección de una trama no autenticada.
6. DoS: ráfaga virtual y comprobación de alertas con el umbral actual del IDS.
7. Pares intercalados y frames fuera de orden, comprobados en ECU e IDS.
8. Pérdida de un frame, expiración del par y registro del fallo.
9. Límite de payload, rechazo de IDs solapados y recepción del payload máximo.
10. Duplicado parcial sin entrega múltiple del mensaje.
11. Persistencia de clave, nonce, contador de envío y estado anti-replay tras recrear sus gestores.
12. Rotación persistente, rechazo de claves reutilizadas y continuidad del contador.
13. Reinicio de emisor/receptor en el bus virtual: el envío continúa y un mensaje anterior sigue rechazado.
14. Reservas concurrentes sobre un almacén persistente no repiten nonce ni contador.

Cada prueba muestra al comenzar el escenario y, al terminar, una línea `PASS`/`FAIL` con el dato observado y su duración. Si falla, también imprime el resultado esperado. El resumen final separa protocolo/IDS de claves/estado, indica el total y enumera los fallos. Para ejecutar todas las pruebas sin interacción y obtener un código de salida útil para automatización:

```bash
python3 -m eval.manual_test --all
```

Esta utilidad es solo para desarrollo: usa la clave pública de demostración del repositorio y no mide rendimiento de hardware ni valida una integración vehicular. No usar esa clave ni estos resultados como evidencia de seguridad de producción.