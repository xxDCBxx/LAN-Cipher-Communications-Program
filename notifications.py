import tkinter as tk
from tkinter import messagebox

_root: tk.Tk | None = None


def set_root(root: tk.Tk) -> None:
    global _root
    _root = root


def show_popup(title: str, message: str) -> None:
    if _root is None:
        print(f"[POPUP] {title}: {message}")
        return

    def _show():
        messagebox.showwarning(title, message)

    _root.after(0, _show)


def notify_fail_once() -> None:
    show_popup(
        "Decryption Failed",
        "The recipient failed to decrypt the message.\n"
        "They have one attempt remaining.",
    )


def notify_unauthorized() -> None:
    show_popup(
        "⚠ Security Alert",
        "Possible unauthorized access detected!\n\n"
        "The recipient failed decryption twice.\n"
        "The honeypot sequence has been activated.",
    )


def dispatch_notification(event: str, sender_ip: str = "") -> None:
    if event == "fail_once":
        notify_fail_once()
    elif event == "unauthorized":
        notify_unauthorized()
    else:
        show_popup("Network Notification", f"Received event: '{event}' from {sender_ip}")
