import tkinter as tk
from tkinter import ttk
import threading

import network
import encrypt_order
import notifications
from ui_honeypot import HoneypotController
from ui_sender import CipherRow, MAX_STEPS  

ACCENT   = "#1565C0"
BG       = "#f5f7fa"
CARD_BG  = "#ffffff"
ERR_FG   = "#c62828"
OK_FG    = "#2e7d32"
LABEL_FG = "#37474f"


class ReceiverPanel(tk.Frame):
    def __init__(self, parent, log_callback=None, **kwargs):
        super().__init__(parent, bg=BG, **kwargs)
        self._log = log_callback or (lambda m: None)

        self._ciphertext: str = ""
        self._decoy_text: str = ""
        self._sender_ip: str = ""
        self._fail_count: int = 0
        self._honeypot: HoneypotController | None = None

        self._build_waiting_state()

    def load_message(self, ciphertext: str, decoy_text: str, sender_ip: str):
        self._ciphertext = ciphertext
        self._decoy_text = decoy_text
        self._sender_ip = sender_ip
        self._fail_count = 0
        self._honeypot = None
        self._build_received_state()

    def _clear_all(self):
        for w in self.winfo_children():
            w.destroy()

    def _build_waiting_state(self):
        self._clear_all()
        tk.Label(
            self, text="📬", font=("Segoe UI", 48), bg=BG
        ).pack(pady=(60, 8))
        tk.Label(
            self, text="Waiting for a message…",
            font=("Segoe UI", 14), bg=BG, fg="#90a4ae"
        ).pack()
        tk.Label(
            self,
            text="When a sender transmits an encrypted message to this computer,\n"
                 "it will appear here for decryption.",
            font=("Segoe UI", 10), bg=BG, fg="#b0bec5", justify="center"
        ).pack(pady=(8, 0))

    def _build_received_state(self):
        self._clear_all()

        ct_card = self._card(self, "Received Ciphertext")
        ct_card.pack(fill="x", padx=16, pady=(12, 6))

        ct_body = tk.Frame(ct_card, bg=CARD_BG)
        ct_body.pack(fill="x", padx=12, pady=(0, 10))

        self._ct_display = tk.Text(
            ct_body, height=4, font=("Courier", 10),
            relief="solid", bd=1, wrap="word",
            state="normal", bg="#f9f9f9"
        )
        self._ct_display.insert("1.0", self._ciphertext)
        self._ct_display.config(state="disabled")
        self._ct_display.pack(fill="x")

        dec_card = self._card(self, "Enter Decryption Order & Keys")
        dec_card.pack(fill="x", padx=16, pady=6)

        tk.Label(
            dec_card,
            text="ℹ  Enter steps in the REVERSE order of encryption and use the same keys.",
            font=("Segoe UI", 9), bg=CARD_BG, fg="#607d8b", wraplength=480, justify="left"
        ).pack(anchor="w", padx=12, pady=(6, 2))

        self._cipher_rows: list[CipherRow] = []
        for i in range(MAX_STEPS):
            row = CipherRow(dec_card, row_number=i + 1)
            row.pack(fill="x", padx=12, pady=3)
            self._cipher_rows.append(row)

        self._feedback_label = tk.Label(
            self, text="", font=("Segoe UI", 10), bg=BG,
            fg=ERR_FG, wraplength=480
        )
        self._feedback_label.pack(pady=(6, 0))

        self._decrypt_btn = tk.Button(
            self, text="  Decrypt  →",
            font=("Segoe UI", 12, "bold"),
            bg=ACCENT, fg="white", relief="flat",
            padx=24, pady=10, cursor="hand2",
            command=self._attempt_decrypt
        )
        self._decrypt_btn.pack(pady=(8, 16))

    def _build_success_state(self, plaintext: str):
        self._clear_all()

        tk.Label(self, text="✅", font=("Segoe UI", 36), bg=BG).pack(pady=(40, 4))
        tk.Label(
            self, text="Decryption Successful",
            font=("Segoe UI", 14, "bold"), bg=BG, fg=OK_FG
        ).pack()

        result_card = self._card(self, "Decrypted Message")
        result_card.pack(fill="x", padx=16, pady=16)

        result_body = tk.Frame(result_card, bg=CARD_BG)
        result_body.pack(fill="x", padx=12, pady=(0, 12))

        result_text = tk.Text(
            result_body, height=6, font=("Segoe UI", 12),
            relief="solid", bd=1, wrap="word",
            state="normal", bg="#f1f8e9"
        )
        result_text.insert("1.0", plaintext)
        result_text.config(state="disabled")
        result_text.pack(fill="x")

        tk.Button(
            self, text="Clear / Ready for Next Message",
            font=("Segoe UI", 10), bg="#e8f5e9", fg=OK_FG,
            relief="flat", padx=16, pady=6, cursor="hand2",
            command=self._build_waiting_state
        ).pack(pady=(0, 20))

    def _build_honeypot_state(self):
        self._clear_all()

        container = tk.Frame(self, bg=BG)
        container.pack(fill="both", expand=True)

        self._honeypot = HoneypotController(
            container,
            decoy_text=self._decoy_text,
            on_complete=self._honeypot_finished,
        )
        self._honeypot.start()
        self._log("Honeypot activated for incoming message.")

    def _honeypot_finished(self, decoy_text: str):
        self._clear_all()

        tk.Label(self, text="✅", font=("Segoe UI", 36), bg=BG).pack(pady=(40, 4))
        tk.Label(
            self, text="Decryption Successful",
            font=("Segoe UI", 14, "bold"), bg=BG, fg=OK_FG
        ).pack()

        result_card = self._card(self, "Decrypted Message")
        result_card.pack(fill="x", padx=16, pady=16)

        result_body = tk.Frame(result_card, bg=CARD_BG)
        result_body.pack(fill="x", padx=12, pady=(0, 12))

        result_text = tk.Text(
            result_body, height=6, font=("Segoe UI", 12),
            relief="solid", bd=1, wrap="word",
            state="normal", bg="#fff9c4" 
        )
        result_text.insert("1.0", decoy_text)
        result_text.config(state="disabled")
        result_text.pack(fill="x")

        tk.Button(
            self, text="Clear / Ready for Next Message",
            font=("Segoe UI", 10), bg="#fff9c4", fg="#f57f17",
            relief="flat", padx=16, pady=6, cursor="hand2",
            command=self._build_waiting_state
        ).pack(pady=(0, 20))


    def _attempt_decrypt(self):
        self._feedback_label.config(text="")

        steps = []
        for row in self._cipher_rows:
            try:
                step = row.get_step()
            except ValueError as e:
                self._feedback_label.config(text=str(e))
                return
            if step is not None:
                steps.append(step)

        if not steps:
            self._feedback_label.config(
                text="Enter at least one decryption step."
            )
            return

        for step in steps:
            if step.get("cipher") == "vernam":
                key = step.get("key", "")
                if len(key) < len(self._ciphertext):
                    self._feedback_label.config(
                        text=f"Vernam key too short: key length ({len(key)}) "
                             f"must be ≥ ciphertext length ({len(self._ciphertext)})."
                    )
                    return

        try:
            success, text = encrypt_order.decode(self._ciphertext, steps)
        except Exception as e:
            success, text = False, str(e)

        if success:
            self._log(f"Message from {self._sender_ip} decrypted successfully.")
            self._build_success_state(text)
        else:
            self._fail_count += 1
            self._log(
                f"Failed decryption attempt #{self._fail_count} "
                f"from {self._sender_ip}."
            )

            if self._fail_count == 1:
                self._feedback_label.config(
                    text="✗  Incorrect — please try again."
                )
                self._notify_sender("fail_once")

            else:
                self._notify_sender("unauthorized")
                self._build_honeypot_state()

    def _notify_sender(self, event: str):
        if not self._sender_ip:
            return

        local_ip = network.get_local_ip()

        def _send():
            try:
                network.send_notification(self._sender_ip, event, local_ip)
            except Exception as e:
                self._log(f"Could not notify sender: {e}")

        threading.Thread(target=_send, daemon=True).start()

    @staticmethod
    def _card(parent, title: str) -> tk.LabelFrame:
        return tk.LabelFrame(
            parent, text=f"  {title}  ",
            font=("Segoe UI", 10, "bold"),
            bg=CARD_BG, fg=ACCENT,
            relief="groove", bd=1,
            labelanchor="nw",
        )
