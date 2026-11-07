#!/usr/bin/env python3
"""Interfaz grafica de CAN-Secure (Tkinter, sin dependencias extra).

Ejecutar desde la raiz del proyecto:   python gui.py

Permite:
  - Elegir modo: Simulacion (bus virtual) o Hardware (Arduino + shield CAN).
  - Lanzar escenarios (Baseline, Secure, Todo) y ataques sueltos.
  - Ver el log en vivo con colores (verde=OK, rojo=alerta, azul=info).
  - Ver tarjetas de KPIs y una grafica de barras baseline vs CAN-Secure.

El trabajo de CAN corre en un hilo aparte para no congelar la ventana; el log se
transmite a la GUI por una cola thread-safe.
"""

import io
import json
import queue
import sys
import threading
import tkinter as tk
from contextlib import redirect_stdout
from pathlib import Path
from tkinter import messagebox, ttk

from core import config

RESULTS_DIR = Path(__file__).resolve().parent / "results"

# Paleta.
BG = "#0f1419"
PANEL = "#1a2029"
FG = "#e6e6e6"
ACCENT = "#4da3ff"
OK = "#49c17a"
ALERT = "#ff5c5c"
WARN = "#ffb454"


class QueueWriter(io.TextIOBase):
    """Archivo falso que empuja cada linea escrita a una cola."""

    def __init__(self, q):
        self.q = q

    def write(self, text):
        if text:
            self.q.put(text)
        return len(text)


class CanSecureGUI:
    def __init__(self, root):
        self.root = root
        self.log_queue = queue.Queue()
        self.worker = None
        root.title("CAN-Secure — Panel de control")
        root.configure(bg=BG)
        root.geometry("980x680")

        self._build_header()
        self._build_controls()
        self._build_body()
        self._poll_log()
        self._refresh_kpis()

    # ------------------------------------------------------------- UI build
    def _build_header(self):
        top = tk.Frame(self.root, bg=BG)
        top.pack(fill="x", padx=16, pady=(14, 6))
        tk.Label(top, text="CAN-Secure", font=("Segoe UI", 20, "bold"),
                 bg=BG, fg=ACCENT).pack(side="left")
        tk.Label(top, text="Autenticacion HMAC + anti-replay + IDS sobre CAN",
                 font=("Segoe UI", 10), bg=BG, fg="#8a94a6").pack(side="left", padx=12)

    def _build_controls(self):
        bar = tk.Frame(self.root, bg=PANEL)
        bar.pack(fill="x", padx=16, pady=6)

        # --- Modo ---
        tk.Label(bar, text="Modo:", bg=PANEL, fg=FG, font=("Segoe UI", 10, "bold")
                 ).grid(row=0, column=0, padx=(12, 6), pady=10, sticky="w")
        self.mode = tk.StringVar(value="sim")
        self.mode.trace_add("write", lambda *_: self._on_mode_change())
        ttk.Radiobutton(bar, text="Simulacion", value="sim", variable=self.mode
                        ).grid(row=0, column=1, pady=10)
        ttk.Radiobutton(bar, text="Hardware (Arduino)", value="hardware", variable=self.mode
                        ).grid(row=0, column=2, padx=6, pady=10)

        # --- Puerto / bitrate (hardware) ---
        tk.Label(bar, text="Puerto:", bg=PANEL, fg=FG).grid(row=0, column=3, padx=(18, 4))
        self.port_var = tk.StringVar(value=config.SERIAL_PORT)
        self.port_entry = tk.Entry(bar, textvariable=self.port_var, width=8,
                                   state="disabled")
        self.port_entry.grid(row=0, column=4)
        tk.Label(bar, text="Bitrate:", bg=PANEL, fg=FG).grid(row=0, column=5, padx=(12, 4))
        self.bitrate_var = tk.StringVar(value=str(config.SERIAL_BITRATE))
        self.bitrate_entry = tk.Entry(bar, textvariable=self.bitrate_var, width=8,
                                      state="disabled")
        self.bitrate_entry.grid(row=0, column=6)

        # --- Botones de accion ---
        btns = tk.Frame(self.root, bg=BG)
        btns.pack(fill="x", padx=16, pady=(4, 8))
        self.buttons = []
        for text, cmd, color in [
            ("Correr TODO", self.run_all, ACCENT),
            ("Baseline", self.run_baseline, "#5a6572"),
            ("CAN-Secure", self.run_secure, "#5a6572"),
            ("Ataque: Spoof", lambda: self.run_attack("spoof"), WARN),
            ("Ataque: Replay", lambda: self.run_attack("replay"), WARN),
            ("Ataque: DoS", lambda: self.run_attack("dos"), ALERT),
            ("Limpiar log", self.clear_log, "#3a4250"),
        ]:
            b = tk.Button(btns, text=text, command=cmd, bg=color, fg="white",
                          font=("Segoe UI", 9, "bold"), relief="flat",
                          padx=10, pady=6, cursor="hand2", activebackground=color)
            b.pack(side="left", padx=4)
            if text not in ("Limpiar log",):
                self.buttons.append(b)

    def _build_body(self):
        body = tk.Frame(self.root, bg=BG)
        body.pack(fill="both", expand=True, padx=16, pady=6)

        # Izquierda: log en vivo.
        left = tk.Frame(body, bg=BG)
        left.pack(side="left", fill="both", expand=True)
        tk.Label(left, text="Registro en vivo", bg=BG, fg="#8a94a6",
                 font=("Segoe UI", 9, "bold")).pack(anchor="w")
        self.log = tk.Text(left, bg="#0b0e13", fg=FG, insertbackground=FG,
                           font=("Consolas", 9), wrap="word", relief="flat",
                           padx=8, pady=8)
        self.log.pack(fill="both", expand=True)
        self.log.tag_config("ok", foreground=OK)
        self.log.tag_config("alert", foreground=ALERT)
        self.log.tag_config("info", foreground=ACCENT)
        self.log.tag_config("warn", foreground=WARN)
        self.log.configure(state="disabled")

        # Derecha: KPIs + grafica.
        right = tk.Frame(body, bg=BG, width=320)
        right.pack(side="right", fill="y", padx=(12, 0))
        right.pack_propagate(False)
        tk.Label(right, text="KPIs (CAN-Secure vs Baseline)", bg=BG, fg="#8a94a6",
                 font=("Segoe UI", 9, "bold")).pack(anchor="w")
        self.kpi_frame = tk.Frame(right, bg=BG)
        self.kpi_frame.pack(fill="x", pady=6)
        self.chart = tk.Canvas(right, bg=PANEL, height=220, highlightthickness=0)
        self.chart.pack(fill="x", pady=6)

        # Barra de estado.
        self.status = tk.StringVar(value="Listo — modo Simulacion")
        tk.Label(self.root, textvariable=self.status, bg=PANEL, fg="#8a94a6",
                 anchor="w", padx=12).pack(fill="x", side="bottom")

    # ---------------------------------------------------------------- logica
    def _on_mode_change(self):
        hardware = self.mode.get() == "hardware"
        state = "normal" if hardware else "disabled"
        self.port_entry.configure(state=state)
        self.bitrate_entry.configure(state=state)
        if hardware:
            messagebox.showwarning(
                "Modo hardware",
                "Vas a usar hardware real (Arduino + shield CAN).\n\n"
                "SEGURIDAD: inyectar ataques (Spoof/Replay/DoS) en un vehiculo "
                "real puede dejar inoperables modulos de frenos, direccion o motor.\n\n"
                "Hazlo SOLO en banco de pruebas o con el vehiculo detenido y "
                "apagado, NUNCA conduciendo. El monitoreo (IDS) es la via segura.")
        self.status.set(f"Modo {'Hardware' if hardware else 'Simulacion'}")

    def _apply_config(self):
        """Vuelca la seleccion de la GUI a core.config antes de correr."""
        mode = self.mode.get()
        if mode == "hardware":
            config.SERIAL_PORT = self.port_var.get().strip()
            try:
                config.SERIAL_BITRATE = int(self.bitrate_var.get())
            except ValueError:
                pass
        config.apply_mode(mode)

    def _run_in_thread(self, fn, label):
        if self.worker and self.worker.is_alive():
            messagebox.showinfo("Ocupado", "Ya hay una tarea en ejecucion.")
            return
        self._apply_config()
        self._set_buttons(False)
        self.status.set(f"Ejecutando: {label}...")

        def target():
            writer = QueueWriter(self.log_queue)
            try:
                with redirect_stdout(writer):
                    fn()
            except Exception as exc:  # errores de bus/hardware llegan aqui.
                self.log_queue.put(f"\n[ERROR] {exc}\n")
            finally:
                self.log_queue.put(("__DONE__", label))

        self.worker = threading.Thread(target=target, daemon=True)
        self.worker.start()

    # --- acciones de botones ---
    def run_all(self):
        from eval.baseline_run import run_baseline
        from eval.secure_run import run_secure_eval
        from eval.metrics import report

        def seq():
            run_baseline()
            run_secure_eval()
            report()
        self._run_in_thread(seq, "Todo (baseline+secure+metrics)")

    def run_baseline(self):
        from eval.baseline_run import run_baseline
        self._run_in_thread(run_baseline, "Baseline")

    def run_secure(self):
        from eval.secure_run import run_secure_eval
        self._run_in_thread(run_secure_eval, "CAN-Secure")

    def run_attack(self, kind):
        def atk():
            if kind == "spoof":
                from attacks.spoofing import run_spoofing_attack
                run_spoofing_attack()
            elif kind == "replay":
                from attacks.replay import run_replay_attack
                run_replay_attack()
            else:
                from attacks.dos_flood import run_dos_attack
                run_dos_attack()
        self._run_in_thread(atk, f"Ataque {kind}")

    def clear_log(self):
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.configure(state="disabled")

    # --- log polling ---
    def _poll_log(self):
        try:
            while True:
                item = self.log_queue.get_nowait()
                if isinstance(item, tuple) and item[0] == "__DONE__":
                    self._set_buttons(True)
                    self.status.set(f"Terminado: {item[1]}")
                    self._refresh_kpis()
                else:
                    self._append(item)
        except queue.Empty:
            pass
        self.root.after(80, self._poll_log)

    def _append(self, text):
        tag = None
        if "[ALERTA" in text or "[ERROR" in text or "Alerta" in text:
            tag = "alert"
        elif "[IDS OK]" in text or "100.0%" in text or "legitima" in text:
            tag = "ok"
        elif "[Ataque" in text:
            tag = "warn"
        elif text.startswith("[") or "===" in text or "INICIANDO" in text:
            tag = "info"
        self.log.configure(state="normal")
        self.log.insert("end", text, tag)
        self.log.see("end")
        self.log.configure(state="disabled")

    def _set_buttons(self, enabled):
        for b in self.buttons:
            b.configure(state="normal" if enabled else "disabled")

    # --- KPIs + grafica ---
    def _load(self, name):
        p = RESULTS_DIR / name
        return json.loads(p.read_text()) if p.exists() else None

    def _refresh_kpis(self):
        for w in self.kpi_frame.winfo_children():
            w.destroy()
        secure = self._load("secure.json")
        baseline = self._load("baseline.json")

        cards = []
        if secure:
            m = secure.get("ids_metrics", {})
            detected = sum(1 for k in ("spoofing_detected", "replay_detected", "dos_alerts")
                           if m.get(k, 0) > 0)
            total = secure.get("attack_types_total", 3)
            legit = secure.get("legit_sent", 1) or 1
            valid = m.get("valid_frames", 0)
            fp = max(0, legit - valid) / legit * 100
            cnt = m.get("hmac_verify_count", 0)
            ovh = (m.get("hmac_verify_time_s", 0) / cnt * 1000) if cnt else 0
            cards += [
                ("Deteccion", f"{detected/total*100:.0f}%", OK if detected == total else WARN),
                ("Falsos positivos", f"{fp:.0f}%", OK if fp < 10 else ALERT),
                ("Overhead HMAC", f"{ovh:.3f} ms", OK if ovh < 5 else WARN),
            ]
        if baseline:
            cards.append(("Baseline aceptadas",
                          str(baseline.get("frames_accepted_without_verification", "-")), ALERT))
        if not cards:
            cards = [("Sin datos", "corre un run", "#5a6572")]

        for i, (label, value, color) in enumerate(cards):
            card = tk.Frame(self.kpi_frame, bg=PANEL)
            card.grid(row=i // 2, column=i % 2, padx=4, pady=4, sticky="nsew")
            self.kpi_frame.columnconfigure(i % 2, weight=1)
            tk.Label(card, text=value, bg=PANEL, fg=color,
                     font=("Segoe UI", 15, "bold")).pack(anchor="w", padx=10, pady=(8, 0))
            tk.Label(card, text=label, bg=PANEL, fg="#8a94a6",
                     font=("Segoe UI", 8)).pack(anchor="w", padx=10, pady=(0, 8))

        self._draw_chart(baseline, secure)

    def _draw_chart(self, baseline, secure):
        c = self.chart
        c.delete("all")
        c.update_idletasks()
        w = c.winfo_width() or 300
        h = 220
        c.create_text(w / 2, 14, text="Tramas maliciosas aceptadas",
                      fill="#8a94a6", font=("Segoe UI", 9, "bold"))

        base_val = baseline.get("frames_accepted_without_verification", 0) if baseline else 0
        sec_val = secure.get("ids_metrics", {}).get("valid_frames", 0) if secure else 0
        # En secure, maliciosas aceptadas = 0; mostramos ese contraste.
        sec_malicious = 0
        max_val = max(base_val, 1)
        pairs = [("Baseline", base_val, ALERT), ("CAN-Secure", sec_malicious, OK)]

        bw = 90
        gap = 60
        x0 = (w - (bw * 2 + gap)) / 2
        base_y = h - 36
        for i, (label, val, color) in enumerate(pairs):
            x = x0 + i * (bw + gap)
            bar_h = (val / max_val) * (h - 80)
            c.create_rectangle(x, base_y - bar_h, x + bw, base_y,
                               fill=color, outline="")
            c.create_text(x + bw / 2, base_y - bar_h - 12, text=str(val),
                          fill=FG, font=("Segoe UI", 11, "bold"))
            c.create_text(x + bw / 2, base_y + 14, text=label,
                          fill="#8a94a6", font=("Segoe UI", 9))


def main():
    root = tk.Tk()
    CanSecureGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
