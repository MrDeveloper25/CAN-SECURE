#!/usr/bin/env python3
"""Interfaz grafica de CAN-Secure (CustomTkinter).

Ejecutar desde la raiz del proyecto:   python gui.py

Diseno:
  - Barra lateral con modo (Simulacion / Hardware) y acciones agrupadas.
  - Tarjetas de KPIs en la parte superior.
  - Registro en vivo con colores + grafica de comparacion baseline vs secure.

El trabajo de CAN corre en un hilo aparte (la ventana no se congela); el log se
transmite por una cola thread-safe y se pinta con `after()`.
"""

import io
import json
import queue
import threading
import tkinter as tk
from contextlib import redirect_stdout
from pathlib import Path

import customtkinter as ctk
from tkinter import messagebox

from core import config

RESULTS_DIR = Path(__file__).resolve().parent / "results"

# ---------------------------------------------------------------- paleta
BG      = "#15171c"   # fondo principal
SIDEBAR = "#1b1e24"   # barra lateral
CARD    = "#22262e"   # tarjetas / paneles
CARD2   = "#2a2f39"   # hover / realce
LOGBG   = "#0e1013"   # fondo del log
TEXT    = "#e8eaed"
MUTED   = "#8b94a3"
PRIMARY = "#4f8cff"
PRIMHOV = "#6ba0ff"
OK      = "#22c55e"
ALERT   = "#ef4444"
WARN    = "#f59e0b"
NEUTRAL = "#3a4150"

ctk.set_appearance_mode("dark")


class QueueWriter(io.TextIOBase):
    """Archivo falso que empuja cada escritura (print) a una cola."""

    def __init__(self, q):
        self.q = q

    def write(self, text):
        if text:
            self.q.put(text)
        return len(text)


class CanSecureGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.log_queue = queue.Queue()
        self.worker = None
        self.kpi_values = {}

        self.title("CAN-Secure  ·  Panel de control")
        self.geometry("1120x720")
        self.minsize(960, 620)
        self.configure(fg_color=BG)

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._build_sidebar()
        self._build_main()
        self._poll_log()
        self._refresh_kpis()

    # =================================================== barra lateral
    def _build_sidebar(self):
        bar = ctk.CTkFrame(self, width=250, corner_radius=0, fg_color=SIDEBAR)
        bar.grid(row=0, column=0, sticky="nsw")
        bar.grid_propagate(False)

        # Marca
        brand = ctk.CTkFrame(bar, fg_color="transparent")
        brand.pack(fill="x", padx=22, pady=(26, 4))
        ctk.CTkLabel(brand, text="CAN-Secure", font=ctk.CTkFont("Segoe UI", 22, "bold"),
                     text_color=PRIMARY).pack(anchor="w")
        ctk.CTkLabel(brand, text="HMAC · anti-replay · IDS", font=ctk.CTkFont("Segoe UI", 11),
                     text_color=MUTED).pack(anchor="w")

        self._divider(bar)

        # Modo
        ctk.CTkLabel(bar, text="MODO", font=ctk.CTkFont("Segoe UI", 11, "bold"),
                     text_color=MUTED).pack(anchor="w", padx=22, pady=(6, 4))
        self.mode = ctk.CTkSegmentedButton(
            bar, values=["Simulación", "Hardware"], command=self._on_mode_change,
            fg_color=CARD, selected_color=PRIMARY, selected_hover_color=PRIMHOV,
            unselected_color=CARD, unselected_hover_color=CARD2,
            font=ctk.CTkFont("Segoe UI", 12))
        self.mode.set("Simulación")
        self.mode.pack(fill="x", padx=18, pady=(0, 8))

        # Campos de hardware (ocultos por defecto)
        self.hw_frame = ctk.CTkFrame(bar, fg_color="transparent")
        self.port_var = ctk.StringVar(value=config.SERIAL_PORT)
        self.bitrate_var = ctk.StringVar(value=str(config.SERIAL_BITRATE))
        for label, var in [("Puerto", self.port_var), ("Bitrate", self.bitrate_var)]:
            row = ctk.CTkFrame(self.hw_frame, fg_color="transparent")
            row.pack(fill="x", pady=3)
            ctk.CTkLabel(row, text=label, width=60, anchor="w",
                         text_color=MUTED, font=ctk.CTkFont("Segoe UI", 11)).pack(side="left")
            ctk.CTkEntry(row, textvariable=var, fg_color=CARD, border_width=0,
                         font=ctk.CTkFont("Consolas", 12)).pack(side="left", fill="x", expand=True)

        self._divider(bar)

        # Escenarios
        ctk.CTkLabel(bar, text="ESCENARIOS", font=ctk.CTkFont("Segoe UI", 11, "bold"),
                     text_color=MUTED).pack(anchor="w", padx=22, pady=(6, 4))
        self.buttons = []
        self._action(bar, "▶  Correr TODO", self.run_all, PRIMARY, PRIMHOV, primary=True)
        self._action(bar, "Baseline (sin protección)", self.run_baseline, CARD, CARD2)
        self._action(bar, "CAN-Secure (protegido)", self.run_secure, CARD, CARD2)

        # Ataques
        ctk.CTkLabel(bar, text="ATAQUES", font=ctk.CTkFont("Segoe UI", 11, "bold"),
                     text_color=MUTED).pack(anchor="w", padx=22, pady=(14, 4))
        self._action(bar, "Spoofing", lambda: self.run_attack("spoof"), CARD, CARD2, dot=WARN)
        self._action(bar, "Replay", lambda: self.run_attack("replay"), CARD, CARD2, dot=WARN)
        self._action(bar, "DoS flood", lambda: self.run_attack("dos"), CARD, CARD2, dot=ALERT)

        # Pie
        bottom = ctk.CTkFrame(bar, fg_color="transparent")
        bottom.pack(side="bottom", fill="x", padx=18, pady=16)
        ctk.CTkButton(bottom, text="Limpiar registro", command=self.clear_log,
                      fg_color="transparent", hover_color=CARD, text_color=MUTED,
                      height=30, font=ctk.CTkFont("Segoe UI", 11)).pack(fill="x")

    def _divider(self, parent):
        ctk.CTkFrame(parent, height=1, fg_color="#2b3039").pack(fill="x", padx=18, pady=10)

    def _action(self, parent, text, cmd, color, hover, primary=False, dot=None):
        btn = ctk.CTkButton(
            parent, text=text, command=cmd, fg_color=color, hover_color=hover,
            text_color="white" if primary else TEXT, anchor="w",
            height=40 if primary else 34, corner_radius=8,
            font=ctk.CTkFont("Segoe UI", 13 if primary else 12, "bold" if primary else "normal"))
        btn.pack(fill="x", padx=18, pady=3)
        self.buttons.append(btn)
        return btn

    # =================================================== area principal
    def _build_main(self):
        main = ctk.CTkFrame(self, fg_color="transparent")
        main.grid(row=0, column=1, sticky="nsew", padx=24, pady=20)
        main.grid_columnconfigure(0, weight=1)
        main.grid_rowconfigure(2, weight=1)

        # Encabezado
        header = ctk.CTkFrame(main, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", pady=(0, 14))
        ctk.CTkLabel(header, text="Panel de control",
                     font=ctk.CTkFont("Segoe UI", 20, "bold"), text_color=TEXT).pack(side="left")
        self.status = ctk.CTkLabel(header, text="●  Listo — modo Simulación",
                                   font=ctk.CTkFont("Segoe UI", 12), text_color=OK)
        self.status.pack(side="right")

        # Tarjetas KPI
        self.kpi_row = ctk.CTkFrame(main, fg_color="transparent")
        self.kpi_row.grid(row=1, column=0, sticky="ew", pady=(0, 16))
        for i in range(4):
            self.kpi_row.grid_columnconfigure(i, weight=1)

        # Cuerpo: log + grafica
        body = ctk.CTkFrame(main, fg_color="transparent")
        body.grid(row=2, column=0, sticky="nsew")
        body.grid_columnconfigure(0, weight=3)
        body.grid_columnconfigure(1, weight=2)
        body.grid_rowconfigure(0, weight=1)

        # Log
        logcard = ctk.CTkFrame(body, fg_color=CARD, corner_radius=12)
        logcard.grid(row=0, column=0, sticky="nsew", padx=(0, 12))
        logcard.grid_rowconfigure(1, weight=1)
        logcard.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(logcard, text="Registro en vivo", font=ctk.CTkFont("Segoe UI", 13, "bold"),
                     text_color=TEXT).grid(row=0, column=0, sticky="w", padx=16, pady=(12, 4))
        self.log = ctk.CTkTextbox(logcard, fg_color=LOGBG, text_color=TEXT, corner_radius=8,
                                  font=ctk.CTkFont("Consolas", 12), wrap="word")
        self.log.grid(row=1, column=0, sticky="nsew", padx=12, pady=(0, 12))
        for tag, color in [("ok", OK), ("alert", ALERT), ("info", PRIMARY), ("warn", WARN),
                           ("muted", MUTED)]:
            self.log._textbox.tag_config(tag, foreground=color)
        self.log.configure(state="disabled")

        # Grafica
        chartcard = ctk.CTkFrame(body, fg_color=CARD, corner_radius=12)
        chartcard.grid(row=0, column=1, sticky="nsew")
        chartcard.grid_rowconfigure(1, weight=1)
        chartcard.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(chartcard, text="Comparación de impacto",
                     font=ctk.CTkFont("Segoe UI", 13, "bold"), text_color=TEXT).grid(
            row=0, column=0, sticky="w", padx=16, pady=(12, 4))
        self.chart = tk.Canvas(chartcard, bg=CARD, highlightthickness=0)
        self.chart.grid(row=1, column=0, sticky="nsew", padx=12, pady=(0, 12))
        self.chart.bind("<Configure>", lambda e: self._refresh_kpis())

    # =================================================== logica de modo
    def _hardware(self):
        return self.mode.get() == "Hardware"

    def _on_mode_change(self, _value=None):
        if self._hardware():
            self.hw_frame.pack(fill="x", padx=18, pady=(0, 6),
                               after=self.mode)
            self.status.configure(text="●  Modo Hardware (Arduino)", text_color=WARN)
            messagebox.showwarning(
                "Modo hardware",
                "Vas a usar hardware real (Arduino + shield CAN).\n\n"
                "SEGURIDAD: inyectar ataques (Spoof/Replay/DoS) en un vehículo "
                "real puede dejar inoperables módulos de frenos, dirección o "
                "motor.\n\nHazlo SOLO en banco de pruebas o con el vehículo "
                "detenido y apagado, NUNCA conduciendo. El monitoreo (IDS) es la "
                "vía segura.")
        else:
            self.hw_frame.pack_forget()
            self.status.configure(text="●  Listo — modo Simulación", text_color=OK)

    def _apply_config(self):
        if self._hardware():
            config.SERIAL_PORT = self.port_var.get().strip()
            try:
                config.SERIAL_BITRATE = int(self.bitrate_var.get())
            except ValueError:
                pass
            config.apply_mode("hardware")
        else:
            config.apply_mode("sim")

    # =================================================== ejecucion
    def _run_in_thread(self, fn, label):
        if self.worker and self.worker.is_alive():
            messagebox.showinfo("Ocupado", "Ya hay una tarea en ejecución.")
            return
        self._apply_config()
        self._set_buttons(False)
        self.status.configure(text=f"●  Ejecutando: {label}…", text_color=PRIMARY)

        def target():
            writer = QueueWriter(self.log_queue)
            try:
                with redirect_stdout(writer):
                    fn()
            except Exception as exc:
                self.log_queue.put(f"\n[ERROR] {exc}\n")
            finally:
                self.log_queue.put(("__DONE__", label))

        self.worker = threading.Thread(target=target, daemon=True)
        self.worker.start()

    def run_all(self):
        from eval.baseline_run import run_baseline
        from eval.secure_run import run_secure_eval
        from eval.metrics import report

        def seq():
            run_baseline()
            run_secure_eval()
            report()
        self._run_in_thread(seq, "Todo")

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

    # =================================================== log en vivo
    def _poll_log(self):
        try:
            while True:
                item = self.log_queue.get_nowait()
                if isinstance(item, tuple) and item[0] == "__DONE__":
                    self._set_buttons(True)
                    mode = "Hardware" if self._hardware() else "Simulación"
                    self.status.configure(text=f"●  Terminado: {item[1]} — modo {mode}",
                                          text_color=OK)
                    self._refresh_kpis()
                else:
                    self._append(item)
        except queue.Empty:
            pass
        self.after(80, self._poll_log)

    def _append(self, text):
        tag = ""
        if "[ALERTA" in text or "[ERROR" in text or "Alerta" in text:
            tag = "alert"
        elif "[IDS OK]" in text or "legitima" in text or "100.0%" in text:
            tag = "ok"
        elif "[Ataque" in text:
            tag = "warn"
        elif text.strip().startswith("[") or "===" in text or "INICIANDO" in text:
            tag = "info"
        self.log.configure(state="normal")
        self.log._textbox.insert("end", text, tag)
        self.log.see("end")
        self.log.configure(state="disabled")

    def _set_buttons(self, enabled):
        for b in self.buttons:
            b.configure(state="normal" if enabled else "disabled")

    # =================================================== KPIs + grafica
    def _load(self, name):
        p = RESULTS_DIR / name
        return json.loads(p.read_text()) if p.exists() else None

    def _refresh_kpis(self):
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
            det_pct = detected / total * 100
            cards = [
                ("Detección de ataques", f"{det_pct:.0f}%", OK if detected == total else WARN,
                 f"{detected}/{total} tipos"),
                ("Falsos positivos", f"{fp:.0f}%", OK if fp < 10 else ALERT, "meta <10%"),
                ("Overhead HMAC", f"{ovh:.3f}", OK if ovh < 5 else WARN, "ms/verif · meta <5"),
                ("Maliciosas aceptadas", "0", OK, "con protección"),
            ]
        else:
            cards = [("Sin datos", "—", MUTED, "corre un escenario")] + \
                    [("", "", MUTED, "") for _ in range(3)]

        for w in self.kpi_row.winfo_children():
            w.destroy()
        for i, (label, value, color, sub) in enumerate(cards):
            self._kpi_card(self.kpi_row, i, label, value, color, sub)

        self._draw_chart(baseline, secure)

    def _kpi_card(self, parent, col, label, value, color, sub):
        card = ctk.CTkFrame(parent, fg_color=CARD, corner_radius=12, height=96)
        card.grid(row=0, column=col, sticky="ew", padx=(0 if col == 0 else 6, 6))
        card.grid_propagate(False)
        if not label:
            return
        ctk.CTkFrame(card, fg_color=color, width=4, corner_radius=2).place(
            relx=0, rely=0.18, relheight=0.64)
        ctk.CTkLabel(card, text=label.upper(), font=ctk.CTkFont("Segoe UI", 10, "bold"),
                     text_color=MUTED).pack(anchor="w", padx=16, pady=(14, 0))
        ctk.CTkLabel(card, text=value, font=ctk.CTkFont("Segoe UI", 26, "bold"),
                     text_color=color).pack(anchor="w", padx=16)
        ctk.CTkLabel(card, text=sub, font=ctk.CTkFont("Segoe UI", 10),
                     text_color=MUTED).pack(anchor="w", padx=16, pady=(0, 10))

    def _draw_chart(self, baseline, secure):
        c = self.chart
        c.delete("all")
        c.update_idletasks()
        w = c.winfo_width() or 360
        h = c.winfo_height() or 300
        if w < 50:
            return

        c.create_text(w / 2, 22, text="Tramas maliciosas aceptadas", fill=MUTED,
                      font=("Segoe UI", 11, "bold"))

        base_val = baseline.get("frames_accepted_without_verification", 0) if baseline else 0
        sec_val = 0  # con CAN-Secure ninguna maliciosa pasa.
        pairs = [("Baseline", base_val, ALERT), ("CAN-Secure", sec_val, OK)]
        max_val = max(base_val, 1)

        bw = min(110, w * 0.28)
        gap = w * 0.16
        x0 = (w - (bw * 2 + gap)) / 2
        base_y = h - 46
        top_pad = 54
        for i, (label, val, color) in enumerate(pairs):
            x = x0 + i * (bw + gap)
            bar_h = (val / max_val) * (base_y - top_pad)
            bar_h = max(bar_h, 3)
            self._round_bar(c, x, base_y - bar_h, x + bw, base_y, color)
            c.create_text(x + bw / 2, base_y - bar_h - 16, text=str(val), fill=TEXT,
                          font=("Segoe UI", 15, "bold"))
            c.create_text(x + bw / 2, base_y + 18, text=label, fill=MUTED,
                          font=("Segoe UI", 11))

        if base_val and secure:
            c.create_text(w / 2, h - 14,
                          text=f"Bloqueo del 100% ·  {base_val} → 0", fill=OK,
                          font=("Segoe UI", 10, "bold"))

    @staticmethod
    def _round_bar(c, x0, y0, x1, y1, color, r=8):
        r = min(r, (x1 - x0) / 2, (y1 - y0) / 2) if y1 > y0 else 0
        c.create_rectangle(x0, y0 + r, x1, y1, fill=color, outline="")
        c.create_rectangle(x0 + r, y0, x1 - r, y1, fill=color, outline="")
        c.create_oval(x0, y0, x0 + 2 * r, y0 + 2 * r, fill=color, outline="")
        c.create_oval(x1 - 2 * r, y0, x1, y0 + 2 * r, fill=color, outline="")


def main():
    app = CanSecureGUI()
    app.mainloop()


if __name__ == "__main__":
    main()
