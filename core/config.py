"""Configuracion central de CAN-Secure.

Un solo lugar para los parametros que antes estaban repetidos (y a veces
inconsistentes) en cada archivo: canal del bus, IDs, longitud del MAC y clave.

MODOS DE BUS
------------
- 'sim'      -> bus 'virtual' de python-can (un solo proceso, Windows/Linux,
               CAN-FD, sin privilegios). Es el modo por defecto para la demo.
- 'socketcan'-> 'vcan0' en Linux para despliegue multi-proceso real.
- 'hardware' -> Arduino + shield CAN (MCP2515) por puerto serie (interfaz
               'slcan'). CAN CLASICO (8 bytes/trama), por eso el MAC se trunca.

Se cambia de modo con apply_mode('sim'|'hardware'|'socketcan') o directamente
desde la interfaz grafica. Todo el codigo construye su bus con make_bus(), asi
que el cambio es inmediato y centralizado.
"""

# ---------------------------------------------------------------------------
# Bus (valores actuales; apply_mode() los ajusta segun el modo)
# ---------------------------------------------------------------------------
BUS_INTERFACE = "virtual"       # 'virtual' | 'socketcan' | 'slcan'
BUS_CHANNEL = "can-secure-bus"  # nombre del canal (o 'vcan0' en socketcan)
BUS_FD = True                   # CAN-FD (64 bytes). En hardware clasico -> False.

# --- Hardware (Arduino + shield MCP2515 via slcan) -------------------------
SERIAL_PORT = "COM3"            # puerto del Arduino (Windows: COMx, Linux: /dev/ttyUSBx)
SERIAL_BITRATE = 500000         # bitrate del bus CAN del vehiculo (500k tipico OBD-II)

# ---------------------------------------------------------------------------
# Identificadores de trama (esquema de frame dividido)
# ---------------------------------------------------------------------------
# Frame 1 (datos)          -> ID par  (DATA_ID)
# Frame 2 (autenticacion)  -> ID impar (DATA_ID + 1)
DATA_ID = 0x100
AUTH_ID_OFFSET = 1
DOS_FLOOD_ID = 0x000  # ID usado por el ataque DoS para saturar el bus.

# ---------------------------------------------------------------------------
# Criptografia
# ---------------------------------------------------------------------------
# HMAC-SHA256 produce 32 bytes. En CAN-FD (sim) cabe completo (32B). En CAN
# clasico (hardware, 8B/trama) se trunca: MAC 4B + contador 4B = 8B exactos.
MAC_LENGTH = 32           # bytes del MAC transmitido (<= 32).
SEQ_COUNTER_BYTES = 4     # contador anti-replay (uint32, big-endian).

# Clave simetrica de DEMO. En un despliegue real se precarga de forma segura
# por ECU (ver key_manager.py), NUNCA hardcodeada como aqui.
DEFAULT_SECRET_KEY = b"secret_key_ecu1"

# ---------------------------------------------------------------------------
# Deteccion
# ---------------------------------------------------------------------------
DOS_THRESHOLD_PER_SEC = 50   # msgs/seg por encima del cual el IDS alerta DoS.
REASSEMBLY_TIMEOUT = 0.2     # seg que espera un frame de datos a su par de auth.


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def auth_id_for(base_id: int) -> int:
    """ID del frame de autenticacion que acompana a un frame de datos."""
    return base_id + AUTH_ID_OFFSET


def is_auth_id(arbitration_id: int) -> bool:
    """True si el ID corresponde a un frame de autenticacion (impar)."""
    return (arbitration_id % 2) == AUTH_ID_OFFSET


def apply_mode(mode: str):
    """Ajusta la configuracion del bus segun el modo elegido.

    'sim'       -> virtual + CAN-FD + MAC 32B.
    'socketcan' -> vcan0   + CAN-FD + MAC 32B (Linux).
    'hardware'  -> slcan   + CAN clasico + MAC 4B (Arduino/MCP2515).
    """
    global BUS_INTERFACE, BUS_CHANNEL, BUS_FD, MAC_LENGTH
    if mode == "sim":
        BUS_INTERFACE, BUS_CHANNEL, BUS_FD, MAC_LENGTH = "virtual", "can-secure-bus", True, 32
    elif mode == "socketcan":
        BUS_INTERFACE, BUS_CHANNEL, BUS_FD, MAC_LENGTH = "socketcan", "vcan0", True, 32
    elif mode == "hardware":
        # CAN clasico: MAC 4B + contador 4B = 8B (cabe en una trama de 8 bytes).
        BUS_INTERFACE, BUS_FD, MAC_LENGTH = "slcan", False, 4
    else:
        raise ValueError(f"Modo desconocido: {mode}")


def make_bus(receive_own_messages: bool = False):
    """Construye el can.Bus segun la configuracion ACTUAL (lectura en runtime).

    Centralizar la creacion aqui permite cambiar de sim a hardware sin tocar
    nodos ni ataques.
    """
    import can  # import diferido: config no depende de python-can al importar.

    if BUS_INTERFACE == "slcan":
        # Arduino + shield MCP2515 con firmware slcan (CAN clasico).
        return can.Bus(interface="slcan", channel=SERIAL_PORT,
                       bitrate=SERIAL_BITRATE,
                       receive_own_messages=receive_own_messages)
    # virtual / socketcan (soportan CAN-FD).
    return can.Bus(interface=BUS_INTERFACE, channel=BUS_CHANNEL, fd=BUS_FD,
                   receive_own_messages=receive_own_messages)
