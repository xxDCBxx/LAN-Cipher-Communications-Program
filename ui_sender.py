import tkinter as tk
from tkinter import ttk, messagebox
import threading

import network
import encrypt_order

CIPHER_OPTIONS = ["— select —", "Vigenère", "Affine", "Vernam", "Double Transposition"]
MAX_STEPS = 3

ACCENT   = "#1565C0"
BG       = "#f5f7fa"
CARD_BG  = "#ffffff"
ERR_FG   = "#c62828"
LABEL_FG = "#37474f"

class CipherRow(tk.Frame):
    def __init__(self, parent, row_number: int, on_change=None, **kwargs):
        super().__init__(parent, bg=CARD_BG, **kwargs)
        self._on_change = on_change
        self._show_states: dict[str, bool] = {}
        self._key_widgets: list[tuple] = [] 

        tk.Label(self, text=f"Step {row_number}:", font=("Segoe UI", 10, "bold"),
                 bg=CARD_BG, fg=LABEL_FG, width=7, anchor="e").pack(side="left", padx=(0, 6))

        self._cipher_var = tk.StringVar(value=CIPHER_OPTIONS[0])
        self._cipher_var.trace_add("write", self._on_cipher_changed)
        self._dropdown = ttk.Combobox(
            self, textvariable=self._cipher_var,
            values=CIPHER_OPTIONS, state="readonly", width=22,
            font=("Segoe UI", 10)
        )
        self._dropdown.pack(side="left", padx=(0, 10))

        self._key_area = tk.Frame(self, bg=CARD_BG)
        self._key_area.pack(side="left", fill="x", expand=True)

    def get_cipher_name(self) -> str:
        return self._cipher_var.get()

    def get_step(self) -> dict | None:
        name = self._cipher_var.get()
        if name == CIPHER_OPTIONS[0]:
            return None

        if name == "Vigenère":
            key = self._entries.get("vig_key", tk.Entry(self)).get().strip()
            if not key:
                raise ValueError("Vigenère: key cannot be empty.")
            return {"cipher": "vigenere", "key": key}

        elif name == "Affine":
            a_str = self._entries.get("aff_a", tk.Entry(self)).get().strip()
            b_str = self._entries.get("aff_b", tk.Entry(self)).get().strip()
            if not a_str or not b_str:
                raise ValueError("Affine: both 'a' and 'b' values are required.")
            try:
                a, b = int(a_str), int(b_str)
            except ValueError:
                raise ValueError("Affine: 'a' and 'b' must be integers.")
            from math import gcd
            if gcd(a, 26) != 1:
                from cipher_affine import VALID_A_VALUES
                raise ValueError(
                    f"Affine: 'a'={a} is not coprime with 26.\n"
                    f"Valid values: {VALID_A_VALUES}"
                )
            return {"cipher": "affine", "a": a, "b": b}

        elif name == "Vernam":
            key = self._entries.get("ver_key", tk.Entry(self)).get()
            if not key:
                raise ValueError("Vernam: key cannot be empty.")
            return {"cipher": "vernam", "key": key}

        elif name == "Double Transposition":
            k1 = self._entries.get("dt_key1", tk.Entry(self)).get().strip()
            k2 = self._entries.get("dt_key2", tk.Entry(self)).get().strip()
            if not k1 or not k2:
                raise ValueError("Double Transposition: both Key 1 and Key 2 are required.")
            return {"cipher": "double_transposition", "key1": k1, "key2": k2}

        return None

    def clear(self):
        self._cipher_var.set(CIPHER_OPTIONS[0])

    def _on_cipher_changed(self, *_):
        self._rebuild_key_area()
        if self._on_change:
            self._on_change()

    def _rebuild_key_area(self):
        for w in self._key_area.winfo_children():
            w.destroy()
        self._entries = {}
        self._show_states = {}

        name = self._cipher_var.get()

        if name == "Vigenère":
            self._add_key_field("vig_key", "Key:", show_toggle=True)

        elif name == "Affine":
            self._add_int_field("aff_a", "a:", width=6)
            self._add_int_field("aff_b", "b:", width=6)

        elif name == "Vernam":
            self._add_key_field("ver_key", "Key (full length):", show_toggle=True)

        elif name == "Double Transposition":
            self._add_key_field("dt_key1", "Key 1:", show_toggle=True)
            self._add_key_field("dt_key2", "Key 2:", show_toggle=True)

    def _add_key_field(self, var_name: str, label: str,
                       show_toggle: bool = False, width: int = 18):
        tk.Label(self._key_area, text=label, bg=CARD_BG,
                 font=("Segoe UI", 9), fg=LABEL_FG).pack(side="left", padx=(4, 2))
        entry = tk.Entry(self._key_area, width=width, font=("Courier", 10),
                         show="•", relief="solid", bd=1)
        entry.pack(side="left", padx=(0, 4))
        self._entries[var_name] = entry
        self._show_states[var_name] = False

        if show_toggle:
            def make_toggle(e=entry, vn=var_name):
                def toggle():
                    self._show_states[vn] = not self._show_states[vn]
                    e.config(show="" if self._show_states[vn] else "•")
                return toggle
            tk.Button(
                self._key_area, text="👁", font=("Segoe UI", 9),
                relief="flat", bg=CARD_BG, cursor="hand2",
                command=make_toggle()
            ).pack(side="left", padx=(0, 8))

    def _add_int_field(self, var_name: str, label: str, width: int = 6):
        tk.Label(self._key_area, text=label, bg=CARD_BG,
                 font=("Segoe UI", 9), fg=LABEL_FG).pack(side="left", padx=(4, 2))
        entry = tk.Entry(self._key_area, width=width, font=("Courier", 10),
                         relief="solid", bd=1)
        entry.pack(side="left", padx=(0, 8))
        self._entries[var_name] = entry


class SenderPanel(tk.Frame):
    def __init__(self, parent, log_callback=None, **kwargs):
        super().__init__(parent, bg=BG, **kwargs)
        self._log = log_callback or (lambda m: None)
        self._peer_map: dict[str, str] = {}  # display_name → ip
        self._build_ui()
        self._refresh_peers()

    def _build_ui(self):
        peer_card = self._card(self, "1. Select Recipient")
        peer_card.pack(fill="x", padx=16, pady=(12, 6))

        peer_body = tk.Frame(peer_card, bg=CARD_BG)
        peer_body.pack(fill="x", padx=12, pady=(0, 10))

        self._peer_listbox = tk.Listbox(
            peer_body, height=4, font=("Segoe UI", 10),
            relief="solid", bd=1, selectmode="single",
            activestyle="dotbox"
        )
        self._peer_listbox.pack(side="left", fill="x", expand=True)

        scrollbar = ttk.Scrollbar(peer_body, orient="vertical",
                                  command=self._peer_listbox.yview)
        scrollbar.pack(side="left", fill="y")
        self._peer_listbox.config(yscrollcommand=scrollbar.set)

        self._no_peer_label = tk.Label(
            peer_card, text="No peers found on LAN.", font=("Segoe UI", 9),
            bg=CARD_BG, fg="#888"
        )

        tk.Button(
            peer_card, text="🔄 Refresh", font=("Segoe UI", 9),
            relief="flat", bg="#e3f2fd", fg=ACCENT, cursor="hand2",
            command=self._refresh_peers
        ).pack(anchor="e", padx=12, pady=(0, 8))

        msg_card = self._card(self, "2. Compose Message")
        msg_card.pack(fill="x", padx=16, pady=6)

        msg_body = tk.Frame(msg_card, bg=CARD_BG)
        msg_body.pack(fill="x", padx=12, pady=(0, 10))

        tk.Label(msg_body, text="Plaintext:", font=("Segoe UI", 10, "bold"),
                 bg=CARD_BG, fg=LABEL_FG).pack(anchor="w")
        self._plaintext = tk.Text(msg_body, height=4, font=("Segoe UI", 11),
                                  relief="solid", bd=1, wrap="word")
        self._plaintext.pack(fill="x", pady=(2, 10))

        tk.Label(msg_body, text="Decoy text (shown if wrong decryption key used twice):",
                 font=("Segoe UI", 10, "bold"), bg=CARD_BG, fg=LABEL_FG).pack(anchor="w")
        tk.Label(msg_body,
                 text="This will be displayed to an unauthorized user as if it were the real message.",
                 font=("Segoe UI", 9), bg=CARD_BG, fg="#888").pack(anchor="w")
        self._decoy = tk.Text(msg_body, height=3, font=("Segoe UI", 11),
                              relief="solid", bd=1, wrap="word")
        self._decoy.pack(fill="x", pady=(2, 0))

        cipher_card = self._card(self, "3. Encryption Order (up to 3 steps, order matters)")
        cipher_card.pack(fill="x", padx=16, pady=6)

        self._cipher_rows: list[CipherRow] = []
        for i in range(MAX_STEPS):
            row = CipherRow(cipher_card, row_number=i + 1)
            row.pack(fill="x", padx=12, pady=3)
            self._cipher_rows.append(row)

        tk.Label(
            cipher_card,
            text="ℹ  At least one step required. Recipient must enter the SAME steps in REVERSE order.",
            font=("Segoe UI", 9), bg=CARD_BG, fg="#607d8b", wraplength=480, justify="left"
        ).pack(anchor="w", padx=12, pady=(2, 10))

        self._error_label = tk.Label(
            self, text="", font=("Segoe UI", 10), bg=BG, fg=ERR_FG, wraplength=480
        )
        self._error_label.pack(pady=(4, 0))

        tk.Button(
            self, text="  Send Encrypted Message  →",
            font=("Segoe UI", 12, "bold"),
            bg=ACCENT, fg="white", relief="flat",
            padx=24, pady=10, cursor="hand2",
            command=self._send
        ).pack(pady=(8, 16))


    def _refresh_peers(self):
        peers = network.get_peers()
        self._peer_map = {f"{host}  ({ip})": ip for ip, host in peers.items()}

        self._peer_listbox.delete(0, tk.END)
        if self._peer_map:
            self._no_peer_label.pack_forget()
            for display in self._peer_map:
                self._peer_listbox.insert(tk.END, display)
        else:
            self._no_peer_label.pack(pady=4)

        self.after(2000, self._refresh_peers)


    def _send(self):
        self._error_label.config(text="")

        sel = self._peer_listbox.curselection()
        if not sel:
            self._error_label.config(text="Please select a recipient from the list.")
            return
        display_name = self._peer_listbox.get(sel[0])
        target_ip = self._peer_map.get(display_name)
        if not target_ip:
            self._error_label.config(text="Selected peer is no longer available. Refresh and try again.")
            return

        plaintext = self._plaintext.get("1.0", tk.END).strip()
        if not plaintext:
            self._error_label.config(text="Plaintext cannot be empty.")
            return

        decoy = self._decoy.get("1.0", tk.END).strip()
        if not decoy:
            self._error_label.config(text="Decoy text cannot be empty.")
            return

        steps = []
        for row in self._cipher_rows:
            try:
                step = row.get_step()
            except ValueError as e:
                self._error_label.config(text=str(e))
                return
            if step is not None:
                steps.append(step)

        if not steps:
            self._error_label.config(text="Select at least one encryption step.")
            return

        try:
            ciphertext = encrypt_order.encode(plaintext, steps)
        except Exception as e:
            self._error_label.config(text=f"Encryption error: {e}")
            return

        def _do_send():
            try:
                local_ip = network.get_local_ip()
                network.send_message(
                    target_ip,
                    ciphertext.encode("utf-8"),
                    decoy,
                    local_ip,
                )
                cipher_names = ", ".join(
                    s["cipher"].replace("_", " ").title() for s in steps
                )
                self._log(
                    f"Sent to {display_name} | Ciphers: {cipher_names}"
                )
                self.after(0, self._clear_fields)
            except (ConnectionRefusedError, TimeoutError, RuntimeError) as e:
                self.after(0, lambda: self._error_label.config(
                    text=f"Send failed: {e}"
                ))

        threading.Thread(target=_do_send, daemon=True).start()

    def _clear_fields(self):
        self._plaintext.delete("1.0", tk.END)
        self._decoy.delete("1.0", tk.END)
        for row in self._cipher_rows:
            row.clear()
        self._error_label.config(text="")
        messagebox.showinfo("Sent", "Message sent successfully.")

    @staticmethod
    def _card(parent, title: str) -> tk.LabelFrame:
        return tk.LabelFrame(
            parent, text=f"  {title}  ",
            font=("Segoe UI", 10, "bold"),
            bg=CARD_BG, fg=ACCENT,
            relief="groove", bd=1,
            labelanchor="nw",
        )
