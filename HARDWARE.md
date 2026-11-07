# CAN-Secure — Modo Hardware (Arduino + vehículo)

Esta guía explica cómo pasar de la **simulación** al **hardware real** para
probar CAN-Secure sobre un bus CAN físico (banco de pruebas o vehículo).

> ⚠️ **Lee primero la sección de SEGURIDAD al final.** Inyectar tráfico en el
> CAN de un vehículo real puede afectar frenos, dirección o motor.

---

## 1. Hardware necesario

Un **Arduino Uno R3 solo NO habla CAN.** Necesitas añadir un controlador CAN:

| Componente | Función |
|---|---|
| Arduino Uno R3 | Microcontrolador / puente USB-serie |
| **Shield o módulo CAN MCP2515 + transceptor (TJA1050 / MCP2551)** | Habla el protocolo CAN físico |
| Conector OBD-II → cables (CAN-H / CAN-L) | Conexión al vehículo |

- El **MCP2515 es CAN clásico** (máx. **8 bytes por trama**), **no CAN-FD**.
  Por eso en modo hardware CAN-Secure trunca el MAC a **4 bytes** (MAC 4B +
  contador 4B = 8B exactos). Lo hace automáticamente `config.apply_mode("hardware")`.

### Conexión al vehículo (OBD-II)
- Pin **6** = CAN-H, pin **14** = CAN-L del conector OBD-II.
- Bitrate típico del bus de diagnóstico: **500 kbps** (algunos 250 kbps).
  Ajústalo en la GUI (campo *Bitrate*) o en `core/config.py` (`SERIAL_BITRATE`).

---

## 2. Firmware del Arduino (puente slcan)

`python-can` se comunica con el Arduino usando la interfaz **`slcan`** (Serial
Line CAN). El Arduino debe correr un firmware que traduzca Serie ↔ CAN y hable
el protocolo slcan (comandos tipo `O`, `C`, `t...`).

Opciones comunes:
- Firmware **slcan para MCP2515** (p. ej. proyectos open source "arduino-slcan"
  o "CANHacker"-compatibles) cargado con el IDE de Arduino.
- O una placa que ya traiga slcan de fábrica (CANable, etc.).

Tras cargar el firmware, anota el **puerto COM** que aparece en el IDE de
Arduino (Windows: `COM3`, `COM4`…; Linux: `/dev/ttyUSB0`).

---

## 3. Dependencia de Python

El modo hardware usa `pyserial` (lo arrastra `python-can` para slcan):

```bash
pip install -r requirements.txt
```

---

## 4. Probar el modo hardware

### Desde la interfaz gráfica (recomendado)
```bash
python gui.py
```
1. Selecciona **Hardware (Arduino)**.
2. Escribe el **Puerto** (ej. `COM3`) y el **Bitrate** (ej. `500000`).
3. Empieza **solo con monitoreo** (es lo seguro): pulsa **CAN-Secure** con el
   vehículo encendido en reposo y observa el tráfico real en el log.

### Desde la terminal
Edita `core/config.py` → `apply_mode("hardware")` y ajusta `SERIAL_PORT`, o usa
`run.py` tras fijar el modo. Verifica primero la conexión básica:

```python
import can
bus = can.Bus(interface="slcan", channel="COM3", bitrate=500000)
print(bus.recv(2.0))   # debe imprimir una trama real del vehículo
```

---

## 5. Pruebas unitarias con hardware

Los tests de `tests/test_core.py` validan la **lógica** (HMAC, anti-replay,
codec, reensamblador) y **no requieren hardware** — córrelos siempre:

```bash
python -m unittest discover tests
```

Para validar el **camino físico** (que las tramas realmente viajan por el bus),
lo correcto es una prueba de **lazo (loopback) en banco**: dos nodos CAN en una
protoboard, uno envía con `SecureECU` y otro verifica, sin tocar el vehículo.

---

## 6. ⚠️ SEGURIDAD (importante)

- **Monitorear (IDS en modo pasivo) es seguro** y es lo más valioso para la
  investigación: lees el tráfico real sin inyectar nada.
- **Inyectar ataques (Spoof / Replay / DoS) en un vehículo real es peligroso.**
  Un flood de CAN puede dejar inoperables módulos críticos.
- Reglas:
  1. Haz inyección **solo** en un **banco de pruebas** (ECUs sueltas) o con el
     vehículo **detenido y apagado**.
  2. **Nunca** mientras alguien conduce o el vehículo está en marcha.
  3. Usa **tu propio vehículo** o uno con autorización explícita.
  4. Empieza siempre por el monitoreo antes de cualquier inyección.
- CAN-Secure es un **prototipo académico**: no sustituye los controles de
  seguridad del fabricante ni está certificado para uso en carretera.
