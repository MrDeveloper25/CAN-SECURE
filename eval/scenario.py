"""Definicion del escenario de ataque comun a baseline y secure.

Mantener la MISMA secuencia de trafico (legitimo + ataques) en ambos escenarios
es lo que hace la comparacion "antes vs despues" justa y cuantitativa.
"""

import time

from core import config
from attacks.spoofing import run_spoofing_attack
from attacks.replay import run_replay_attack
from attacks.dos_flood import run_dos_attack

# Ground truth del escenario (lo que SE ENVIA, conocido por el evaluador).
LEGIT_FRAMES = 5          # tramas legitimas de la ECU.
SPOOF_TARGET_ID = 0x300   # ID distinto del legitimo para evitar colisiones.
REPLAY_TARGET_ID = config.DATA_ID  # debe ser un ID que la ECU ya uso.
REPLAY_OLD_SEQ = 1        # contador ya consumido -> debe dispararse replay.
DOS_COUNT = 60            # supera el umbral de DoS del IDS (50/seg).

# Tipos de ataque que el escenario espera que se detecten.
ATTACK_TYPES = ("spoofing", "replay", "dos")


def send_legit_traffic(ecu):
    """Envia LEGIT_FRAMES tramas autenticadas validas (seq 1..N)."""
    for i in range(LEGIT_FRAMES):
        ecu.send_secure_frame(config.DATA_ID, f"ENGINE_RPM_{3000 + i}".encode())
        time.sleep(0.02)


def run_attacks():
    """Lanza spoofing, replay y DoS espaciados para un emparejamiento limpio."""
    time.sleep(0.1)
    run_spoofing_attack(target_id=SPOOF_TARGET_ID)
    time.sleep(0.3)  # > REASSEMBLY_TIMEOUT: deja detectar el huerfano de spoofing.
    run_replay_attack(target_id=REPLAY_TARGET_ID, old_seq=REPLAY_OLD_SEQ)
    time.sleep(0.2)
    run_dos_attack(count=DOS_COUNT)
