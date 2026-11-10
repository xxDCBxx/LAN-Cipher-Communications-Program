import tkinter as tk
from tkinter import ttk, messagebox
import datetime
import socket

import network
import notifications
from ui_sender import SenderPanel
from ui_receiver import ReceiverPanel

APP_TITLE = "LAN Cipher Communications"
WIN_WIDTH = 700
WIN_HEIGHT = 780
ACCENT = "#1565C0"
BG = "#f5f7fa"


# ── How-to-use text ────────────────────────────────────────────────────────────
HOW_TO_USE = """\
LAN Cipher Communications — How to Use
═══════════════════════════════════════════════════════

SENDING A MESSAGE
─────────────────
1. Make sure both computers are on the same LAN network and
   both have this program running.
2. Go to the "Send" tab.
3. Select the recipient from the peer list.
   (Click "Refresh" if the list is empty — it may take a few seconds
   for peers to appear after launch.)
4. Type your message in the "Plaintext" field.
5. Type a decoy message in the "Decoy text" field.
   (This will be shown to an unauthorized user who fails decryption twice.)
6. Choose up to 3 encryption steps. ORDER MATTERS.
   For each step, select a cipher and enter its key:
     • Vigenère       — enter a keyword (letters only)
     • Affine         — enter two integers: 'a' (must be coprime with 26)
                        and 'b'. Valid 'a' values: 1,3,5,7,9,11,15,17,19,21,23,25
     • Vernam         — enter a key that is at least as long as your message
     • Double Trans.  — enter two keyword strings (Key 1 and Key 2)
7. Click "Send Encrypted Message".
   You will be notified if the recipient fails to decrypt.

RECEIVING A MESSAGE
───────────────────
1. When a message arrives, the "Receive" tab will automatically
   become active and show the ciphertext.
2. Enter the decryption steps in the REVERSE ORDER of what the
   sender used, with the same keys.
   Example: If sender used  Step1=Vigenère → Step2=Affine
            you must enter  Step1=Affine   → Step2=Vigenère
3. Click "Decrypt".
   • Success → the plaintext is displayed.
   • 1st failure → you will see "Incorrect — please try again."
   • 2nd failure → a verification process will start.
     (If you are the intended recipient and triggered this by mistake,
      contact the sender to resend the message.)

NOTIFICATIONS
─────────────
• As a sender, you will receive pop-up alerts if the recipient
  fails decryption (once, then twice).
• A second failure triggers a "Possible unauthorized access" alert.

CIPHER KEY VISIBILITY
─────────────────────
• Click the 👁 eye icon next to any key field to reveal/hide it.

SUPPORTED CIPHERS
─────────────────
  Vigenère         — classical keyword-based substitution
  Affine           — mathematical E(x) = (ax + b) mod 26
  Vernam           — XOR one-time pad (key ≥ message length)
  Double Trans.    — columnar transposition applied twice
"""


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry(f"{WIN_WIDTH}x{WIN_HEIGHT}")
        self.minsize(620, 600)
        self.configure(bg=BG)

        notifications.set_root(self)

        self._build_ui()
        self._start_network()

    def _build_ui(self):
        title_bar = tk.Frame(self, bg=ACCENT, height=48)
        title_bar.pack(fill="x")
        title_bar.pack_propagate(False)

        tk.Label(
            title_bar,
            text="🔐  LAN Cipher Communications",
            font=("Segoe UI", 14, "bold"),
            bg=ACCENT, fg="white"
        ).pack(side="left", padx=16, pady=8)

        tk.Button(
            title_bar,
            text="?  How to Use",
            font=("Segoe UI", 9),
            bg="#1976D2", fg="white", relief="flat",
            padx=10, cursor="hand2",
            command=self._show_help
        ).pack(side="right", padx=12, pady=10)

        self._ip_label = tk.Label(
            title_bar,
            text=f"Your IP: …",
            font=("Segoe UI", 9),
            bg=ACCENT, fg="#bbdefb"
        )
        self._ip_label.pack(side="right", padx=8)

        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TNotebook", background=BG)
        style.configure("TNotebook.Tab",
                        font=("Segoe UI", 11, "bold"),
                        padding=[14, 6])
        style.map("TNotebook.Tab",
                  background=[("selected", ACCENT), ("!selected", "#dce3ec")],
                  foreground=[("selected", "white"), ("!selected", "#555")])

        self._notebook = ttk.Notebook(self)
        self._notebook.pack(fill="both", expand=True, padx=0, pady=0)

        send_frame = tk.Frame(self._notebook, bg=BG)
        self._notebook.add(send_frame, text="  ✉  Send  ")

        scroll_send = tk.Canvas(send_frame, bg=BG, highlightthickness=0)
        vsb_send = ttk.Scrollbar(send_frame, orient="vertical",
                                  command=scroll_send.yview)
        scroll_send.configure(yscrollcommand=vsb_send.set)
        vsb_send.pack(side="right", fill="y")
        scroll_send.pack(side="left", fill="both", expand=True)

        self._sender_inner = tk.Frame(scroll_send, bg=BG)
        _window_id = scroll_send.create_window((0, 0), window=self._sender_inner,
                                                anchor="nw")

        def _on_sender_configure(e):
            scroll_send.configure(scrollregion=scroll_send.bbox("all"))

        def _on_canvas_resize(e):
            scroll_send.itemconfig(_window_id, width=e.width)

        self._sender_inner.bind("<Configure>", _on_sender_configure)
        scroll_send.bind("<Configure>", _on_canvas_resize)

        self._sender_panel = SenderPanel(
            self._sender_inner, log_callback=self._log
        )
        self._sender_panel.pack(fill="both", expand=True)

        def _on_mousewheel_send(event):
            scroll_send.yview_scroll(int(-1 * (event.delta / 120)), "units")
        scroll_send.bind_all("<MouseWheel>", _on_mousewheel_send)

        self._receive_frame = tk.Frame(self._notebook, bg=BG)
        self._notebook.add(self._receive_frame, text="  📬  Receive  ")

        scroll_recv = tk.Canvas(self._receive_frame, bg=BG, highlightthickness=0)
        vsb_recv = ttk.Scrollbar(self._receive_frame, orient="vertical",
                                  command=scroll_recv.yview)
        scroll_recv.configure(yscrollcommand=vsb_recv.set)
        vsb_recv.pack(side="right", fill="y")
        scroll_recv.pack(side="left", fill="both", expand=True)

        self._receiver_inner = tk.Frame(scroll_recv, bg=BG)
        _recv_window_id = scroll_recv.create_window((0, 0), window=self._receiver_inner,
                                                     anchor="nw")

        def _on_receiver_configure(e):
            scroll_recv.configure(scrollregion=scroll_recv.bbox("all"))

        def _on_recv_canvas_resize(e):
            scroll_recv.itemconfig(_recv_window_id, width=e.width)

        self._receiver_inner.bind("<Configure>", _on_receiver_configure)
        scroll_recv.bind("<Configure>", _on_recv_canvas_resize)

        self._receiver_panel = ReceiverPanel(
            self._receiver_inner, log_callback=self._log
        )
        self._receiver_panel.pack(fill="both", expand=True)

        log_frame = tk.LabelFrame(
            self,
            text="  Message History  ",
            font=("Segoe UI", 9, "bold"),
            bg=BG, fg=ACCENT,
            relief="groove", bd=1,
            labelanchor="nw",
        )
        log_frame.pack(fill="x", padx=8, pady=(0, 6), side="bottom")

        log_inner = tk.Frame(log_frame, bg=BG)
        log_inner.pack(fill="x", padx=4, pady=4)

        self._log_text = tk.Text(
            log_inner, height=5, font=("Courier", 9),
            relief="flat", bd=0, bg="#eceff1", fg="#455a64",
            state="disabled", wrap="word"
        )
        log_vsb = ttk.Scrollbar(log_inner, orient="vertical",
                                  command=self._log_text.yview)
        self._log_text.configure(yscrollcommand=log_vsb.set)
        log_vsb.pack(side="right", fill="y")
        self._log_text.pack(side="left", fill="x", expand=True)

        tk.Button(
            log_frame, text="Clear", font=("Segoe UI", 8),
            relief="flat", bg="#eceff1", fg="#78909c",
            cursor="hand2", command=self._clear_log
        ).pack(anchor="e", padx=4, pady=(0, 4))

    def _start_network(self):
        network.on_message_received(self._on_message_received)
        network.on_notification_received(self._on_notification_received)

        network.start()

        ip = network.get_local_ip()
        self._ip_label.config(text=f"Your IP: {ip}")
        self._log(f"Network started — Your IP: {ip} | Hostname: {socket.gethostname()}")

    def _on_message_received(self, peer_ip: str, ct_bytes: bytes,
                              decoy: str, sender_ip: str,
                              bailout_record: dict | None = None,
                              verifier: dict | None = None):
        ciphertext = ct_bytes.decode("utf-8")

        def _handle():
            self._log(f"Message received from {sender_ip}")
            self._notebook.select(1)
            self._receiver_panel.load_message(
                ciphertext, decoy, sender_ip, bailout_record, verifier
            )

        self.after(0, _handle)

    def _on_notification_received(self, event: str, sender_ip: str):
        self.after(0, lambda: notifications.dispatch_notification(event, sender_ip))
        self.after(0, lambda: self._log(f"Notification received: '{event}' from {sender_ip}"))

    def _log(self, message: str):
        def _append():
            timestamp = datetime.datetime.now().strftime("%H:%M:%S")
            self._log_text.config(state="normal")
            self._log_text.insert(tk.END, f"[{timestamp}] {message}\n")
            self._log_text.see(tk.END)
            self._log_text.config(state="disabled")
        self.after(0, _append)

    def _clear_log(self):
        self._log_text.config(state="normal")
        self._log_text.delete("1.0", tk.END)
        self._log_text.config(state="disabled")

    def _show_help(self):
        win = tk.Toplevel(self)
        win.title("How to Use — LAN Cipher Communications")
        win.geometry("580x520")
        win.resizable(True, True)
        win.configure(bg="#fff")

        text = tk.Text(win, font=("Courier", 10), wrap="word",
                       relief="flat", bd=0, padx=16, pady=12,
                       bg="#fff", fg="#263238")
        vsb = ttk.Scrollbar(win, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        text.pack(fill="both", expand=True)
        text.insert("1.0", HOW_TO_USE)
        text.config(state="disabled")

    def on_close(self):
        network.stop()
        self.destroy()


if __name__ == "__main__":
    app = App()
    app.protocol("WM_DELETE_WINDOW", app.on_close)
    app.mainloop()
