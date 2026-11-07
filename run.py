#!/usr/bin/env python3
"""Punto de entrada unico de CAN-Secure.

Ejecutar SIEMPRE desde la raiz del proyecto para que los imports de paquete
(core/, nodes/, attacks/, eval/) funcionen:

    python run.py baseline        # escenario sin proteccion
    python run.py secure          # escenario con CAN-Secure
    python run.py metrics         # compara baseline vs secure (lee results/)
    python run.py all             # baseline + secure + metrics
    python run.py attack spoof    # lanza un ataque suelto (spoof|replay|dos)
    python run.py ids             # solo el sniffer IDS
"""

import argparse
import sys


def main():
    parser = argparse.ArgumentParser(description="Orquestador de CAN-Secure")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("baseline", help="Escenario sin proteccion")
    sub.add_parser("secure", help="Escenario con CAN-Secure")
    sub.add_parser("metrics", help="Compara baseline vs secure")
    sub.add_parser("all", help="baseline + secure + metrics")
    sub.add_parser("ids", help="Solo el sniffer IDS")

    p_atk = sub.add_parser("attack", help="Lanza un ataque suelto")
    p_atk.add_argument("kind", choices=["spoof", "replay", "dos"])

    args = parser.parse_args()

    if args.command == "baseline":
        from eval.baseline_run import run_baseline
        run_baseline()
    elif args.command == "secure":
        from eval.secure_run import run_secure_eval
        run_secure_eval()
    elif args.command == "metrics":
        from eval.metrics import report
        report()
    elif args.command == "all":
        from eval.baseline_run import run_baseline
        from eval.secure_run import run_secure_eval
        from eval.metrics import report
        run_baseline()
        run_secure_eval()
        report()
    elif args.command == "ids":
        from nodes.ids_monitor import IDSMonitor
        print(IDSMonitor().start_monitoring(duration=10.0))
    elif args.command == "attack":
        if args.kind == "spoof":
            from attacks.spoofing import run_spoofing_attack
            run_spoofing_attack()
        elif args.kind == "replay":
            from attacks.replay import run_replay_attack
            run_replay_attack()
        else:
            from attacks.dos_flood import run_dos_attack
            run_dos_attack()


if __name__ == "__main__":
    sys.exit(main())
