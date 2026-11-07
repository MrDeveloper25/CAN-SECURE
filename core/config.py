"""Configuracion central de CAN-Secure.

Un solo lugar para los parametros que antes estaban repetidos (y a veces
inconsistentes) en cada archivo: canal del bus, IDs, longitud del MAC y clave.

Cambiando BUS_INTERFACE/BUS_CHANNEL aqui, el MISMO codigo corre tanto sobre el
bus 'virtual' de python-can (un solo proceso, ideal para Windows/demo) como
sobre 'socketcan'/'vcan0' en Linux (multi-proceso real).
"""

# ---------------------------------------------------------------------------
# Bus
# ---------------------------------------------------------------------------
# 'virtual': comparte trafico entre instancias Bus del MISMO proceso. Es lo que
#            usan los escenarios de eval (orquestados en un proceso).
# 'socketcan' + 'vcan0': para despliegue multi-nodo real en Linux (ver
#            sim/setup_vcan.sh).
BUS_INTERFACE = "virtual"
BUS_CHANNEL = "can-secure-bus"
BUS_FD = True  # CAN-FD: hasta 64 bytes de datos por trama.

# ---------------------------------------------------------------------------
# Identificadores de trama (esquema de frame dividido)
# ---------------------------------------------------------------------------
# Frame 1 (datos)          -> ID par  (DATA_ID)
# Frame 2 (autenticacion)  -> ID impar (DATA_ID + 1)
# El reensamblador empareja un frame de datos con su frame de auth por este ID.
DATA_ID = 0x100
AUTH_ID_OFFSET = 1
DOS_FLOOD_ID = 0x000  # ID usado por el ataque DoS para saturar el bus.

# ---------------------------------------------------------------------------
# Criptografia
# ---------------------------------------------------------------------------
# HMAC-SHA256 produce 32 bytes. Como usamos CAN-FD (64 bytes/trama), el MAC
# completo + contador (36 bytes) cabe sin presion de ancho de banda, por eso el
# DEFAULT es 32 (maxima resistencia criptografica).
#
# Se deja CONFIGURABLE para poder medir el truncado como KPI de overhead:
# bajarlo a 8 (64 bits) o 16 (128 bits) reduce bytes a costa de seguridad.
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


def auth_id_for(base_id: int) -> int:
    """ID del frame de autenticacion que acompana a un frame de datos."""
    return base_id + AUTH_ID_OFFSET


def is_auth_id(arbitration_id: int) -> bool:
    """True si el ID corresponde a un frame de autenticacion (impar)."""
    return (arbitration_id % 2) == AUTH_ID_OFFSET
