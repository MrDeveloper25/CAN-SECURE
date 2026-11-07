# CAN-Secure

## 0. Resumen de decisiones clave

| Decisión | Elección | Justificación breve |
|---|---|---|
| Formato de trama | **Frame dividido (Opción A)** sobre CAN clásico | Compatible con hardware existente, fiel al objetivo de no requerir rediseño |
| Esquema de autenticación | HMAC-SHA256, longitud configurable (por defecto 32 bytes completos) | CAN-FD permite 64 bytes/trama, así que el MAC completo + contador cabe sin presión de ancho de banda; se puede truncar (8/16 bytes) para medir el trade-off seguridad/overhead como KPI |
| Balance simplicidad/seguridad vs. alternativas evaluadas (ver sección 5) | Contador anti-replay, posible tras ampliar el limite de datos enviados por mensaje |
| Bloquea reenvío de tramas capturadas, aún y cuando el MAC sea válido | Encriptación de punto a punto mediante hasheo con HMAC-SHA256 |
| Gestión de claves | Claves simétricas preinstaladas + rotación periódica vía nodo central | Bajo costo computacional para ECUs con recursos limitados |
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

Cada nodo corre tres capas internas: aplicación (payload real), CAN-Secure (MAC, anti-replay, política de fallos) y transporte (`python-can` sobre SocketCAN).
De acuerdo al estandar del modelo OSI, el protocolo CAN abarca las capas de datos y fisica, CAN-Secure se situa en el punto medio entre las capas de transporte y red.
Con salida desde la ECU del vehiculo se espera la metadata emitida tras la capa de red, momento donde el sniffer se encarga de loggear la información y tras realizar
la encriptación correspondiente y asignar las llaves de decriptación se otorga un ID unico a la operación y se envia a la siguiente capa.
Con destino hacia la ECU, la capa de transporte entrega a CAN-Secure una trama, el sistema se encarga entonces de confirmar que se trate de una trama esperada dentro de los registros del sniffer,
de ser el caso, se evaluan las llaves de decriptación, se entrega el paquete y se registra el estado de la operación, en caso de volver a recibirse pero haber sido marcada como completa CAN-Secure
filtra estas tramas para evitar ataques replay.

### Estructura de módulos

```
CAN-SECURE/
├── run.py                   # punto de entrada único (CLI): baseline | secure | metrics | all | attack | ids
├── requirements.txt         # dependencias (python-can)
├── core/
│   ├── config.py            # configuración central: bus, IDs, longitud de MAC, clave
│   ├── crypto.py            # HMAC-SHA256 (longitud configurable), generación/verificación de MAC
│   ├── key_manager.py       # claves simétricas por ECU, rotación
│   ├── frame_codec.py       # empaqueta/desempaqueta payload + MAC (frame dividido)
│   ├── reassembler.py       # empareja Frame 1 (datos) + Frame 2 (auth) por ID, tolerante a intercalado
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
│   └── setup_vcan.sh        # crea la interfaz virtual vcan0 (Linux/SocketCAN)
├── eval/
│   ├── scenario.py          # secuencia de tráfico/ataques compartida (comparación justa)
│   ├── baseline_run.py      # corre ataques SIN CAN-Secure (línea base)
│   ├── secure_run.py        # corre los mismos ataques CON CAN-Secure
│   └── metrics.py           # calcula KPIs y compara baseline vs. CAN-Secure
├── tests/
│   └── test_core.py         # tests unitarios de crypto, codec, replay, política y reensamblador
└── results/                 # salida JSON de KPIs (baseline.json, secure.json)
```

> **Nota de ejecución (bus simulado):** los escenarios de `eval/` orquestan ECU, IDS y
> atacantes en **un solo proceso** sobre el bus `virtual` de python-can (que comparte
> tráfico entre instancias del mismo proceso), lo que funciona en Windows/Linux sin
> privilegios. Para un despliegue **multi-proceso real** se cambia `BUS_INTERFACE` a
> `socketcan` y `BUS_CHANNEL` a `vcan0` en `core/config.py` y se levanta la interfaz con
> `sim/setup_vcan.sh` (Linux). El mismo código corre en ambos modos.

---

## 2. Formato de trama: frame dividido

Dado que CAN clásico limita a 8 bytes de datos y un HMAC-SHA256 completo son 32 bytes, se emplea CAN-FD para ampliar las posibilidades de longitud de trama:

| Frame | ID | Contenido (64 bytes) |
|---|---|---|
| Frame 1 (datos) | `ID_base` | Payload real (hasta 28 bytes) |
| Frame 2 (autenticación) | `ID_base + 1` | MAC encriptado (32 bytes) + contador de secuencia (4 bytes) |

Ambos frames forman parte de una misma trama enviada de forma simultanea, recibida por el sistema y evaluada evitando los primeros bytes (1-28) correspondientes al mensaje o datos.
Es una metodologia de trabajo arreglada, por lo que las tramas deben siempre seguir un estandar de formato, garantizando de igual manera que tramas no autorizadas con formatos diferentes sean automaticamente rechazadas.
El receptor reensambla ambos frames por `ID_base` antes de verificar. Esto **duplica el tráfico** para mensajes protegidos — es un costo aceptado y medible, no un detalle a ocultar: se reporta como KPI de overhead (sección 4).

---

## 3. Anti-replay y política ante fallos

- **`replay_guard.py`**: cada ECU mantiene el último contador válido recibido por `ID_base`. Se rechaza cualquier mensaje con contador ≤ al último aceptado.
- **`failure_policy.py`** (nuevo): define qué pasa cuando falla la verificación:
  - 1er fallo → se descarta el mensaje, se registra localmente.
  - 3 fallos consecutivos del mismo `ID_base` → el nodo entra en **modo de alerta**, notifica al IDS monitor mediante un frame especial autenticado con la clave maestra.
  - El modo de alerta puede escalar a una acción de degradación segura (ej. ignorar temporalmente ese ID hasta intervención), lo cual debe documentarse como límite del prototipo (no se simula acción física real sobre el vehículo).

---

## 4. Gestión de claves y KPI de overhead computacional

- Claves simétricas preinstaladas por ECU (simuladas en configuración, no hardcodeadas en el código de demo).
- Nodo central rota claves periódicamente vía un frame de "actualización" autenticado con clave maestra.
- **KPI nuevo — overhead computacional**: tiempo de CPU para calcular y verificar HMAC por mensaje, medido en el entorno de simulación (Python/SocketCAN). Se documenta explícitamente que esto **no es representativo de un microcontrolador embebido real** (ej. ARM Cortex-M), y se compara contra cifras de referencia de la literatura para dar contexto honesto sobre viabilidad en hardware real.
- **KPI nuevo — overhead de tráfico**: % de incremento en número de frames por el esquema de frame dividido, contra el tráfico CAN sin protección.
Nota: Implementación principalmente pensada en python, con posibilidades de traspasar a uso de APIs de C++ en caso de requerir optimización o que los tiempos de respuesta no den los resultados esperados en primera instancia.

---

## 5. Justificación del esquema frente a alternativas

Antes de fijar HMAC-SHA256 truncado como solución, se comparan brevemente los esquemas más citados en la literatura de seguridad CAN:

| Esquema | Ventaja | Por qué no se elige |
|---|---|---|
| **TESLA protocol** | Autenticación con retraso de clave, eficiente en broadcast | Requiere sincronización de tiempo estricta entre ECUs, mayor complejidad de implementación para un prototipo |
| **CANAuth** | Diseñado específicamente para CAN, usa IDs adicionales | Requiere modificar el arbitraje de IDs, mayor intrusión en la red existente |
| **MaCAN** | Estándar más robusto, gestión de claves centralizada | Mayor overhead de mensajes de negociación, más complejo de simular en el tiempo del proyecto modular |
| **HMAC-SHA256 (elegido)** | Simplicidad de implementación, bajo overhead de negociación, ampliamente entendido | Longitud de MAC configurable (`config.MAC_LENGTH`): por defecto 32 bytes completos porque CAN-FD lo permite; truncar a 8/16 bytes ahorra ancho de banda a costa de resistencia criptográfica — se expone como trade-off medible (KPI de overhead) |

Esta comparación se agrega como párrafo breve en la sección "Propuesta de solución" del documento original, para demostrar investigación previa y no una elección arbitraria.

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
| Overhead computacional por mensaje (HMAC) | Reportado, con comparación a hardware embebido de referencia |
| Mejora relativa vs. baseline | Reportado como comparación directa |

---

## 7. Flujo de trabajo de implementación sugerido

1. Montar `vcan0` con `setup_vcan.sh`; confirmar comunicación básica entre dos procesos `python-can`.
2. Implementar `frame_codec.py` + `crypto.py` (sin anti-replay aún) — nodo A envía, nodo B verifica MAC.
3. Agregar `replay_guard.py`; validar con `attacks/replay.py` que el ataque ahora es bloqueado.
4. Agregar `key_manager.py` con rotación simple.
5. Agregar `failure_policy.py` y conectar las alertas al `ids_monitor.py`.
6. Correr `eval/baseline_run.py` (sin protección) y guardar resultados.
7. Correr `eval/secure_run.py` (con protección) contra los mismos ataques.
8. Generar comparación final con `eval/metrics.py` para el informe al comité.

### Cómo ejecutar (desde la raíz del proyecto)

```bash
pip install -r requirements.txt

python gui.py              # INTERFAZ GRÁFICA (botones, log en vivo, KPIs, gráfica)

python run.py baseline     # escenario sin protección  -> results/baseline.json
python run.py secure       # escenario con CAN-Secure   -> results/secure.json
python run.py metrics      # compara ambos y muestra los KPIs
python run.py all          # las tres fases anteriores en orden

python run.py attack dos   # lanzar un ataque suelto (spoof|replay|dos)
python -m unittest discover tests   # tests unitarios de la lógica central
```

### Modos de ejecución

| Modo | Interfaz CAN | Dónde | Notas |
|---|---|---|---|
| **Simulación** (por defecto) | `virtual` (CAN-FD) | Windows/Linux, un proceso | MAC completo 32 bytes. No requiere hardware |
| **SocketCAN** | `vcan0` (CAN-FD) | Linux | Multi-proceso real; `sim/setup_vcan.sh` |
| **Hardware** | `slcan` (CAN clásico) | Arduino + shield MCP2515 → vehículo | MAC truncado a 4 bytes. Ver **[HARDWARE.md](HARDWARE.md)** |

El modo se elige desde la GUI (selector *Simulación / Hardware*) o con
`config.apply_mode(...)`. ⚠️ Inyectar ataques en un vehículo real es peligroso:
lee la sección de seguridad de [HARDWARE.md](HARDWARE.md) antes de conectar nada.

---

## 8. Documento y entregables recomendados para el comité

- Código fuente completo con README de instalación y ejecución.
- Informe de resultados baseline vs. CAN-Secure (tablas + gráficas de los KPIs).
- Diagrama de arquitectura (sección 1) y diagrama de trama dividida (sección 2).
- Documentación técnica breve de la política de fallos y sus límites (sección 3).
- Justificación comparativa de esquemas de autenticación (sección 5), para anexar a la sección "Propuesta de solución" del cuestionario original.
