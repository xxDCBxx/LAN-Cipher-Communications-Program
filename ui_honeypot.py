import random
import string
import tkinter as tk

import network

CAPTCHA_MIN_LEN = 4
CAPTCHA_MAX_LEN = 5

BG = "#1b0000"
PANEL = "#2a0a0a"
FG = "#ffcdd2"
ACCENT = "#ff5252"

_CAPTCHA_CHARS = "".join(
    c for c in string.ascii_uppercase + string.digits if c not in "0O1I"
)

_FIRST_ROAST = (
    "Oh, you again? Welcome to lockdown. "
    "Type the code below BACKWARDS. Yes, backwards. Take your time."
)

_ROASTS = [
    "Wow. Reading a four-character code in reverse. Truly the Everest of our time.",
    "Incorrect. Have you considered a career in anything that isn't hacking?",
    "That was not it. Even the CAPTCHA is embarrassed for you.",
    "Bold strategy: typing the wrong thing with total confidence.",
    "Wrong again. Your keyboard called, it wants an apology.",
    "Not even close. I'd say 'nice try,' but I'd be lying.",
    "Is that your final answer? Because it's a spectacular failure.",
    "Reverse means BACKWARDS. Last-to-first. Right-to-left. You're welcome.",
    "Congratulations, you've unlocked: Disappointment.",
    "A houseplant would have solved this by now. A dead one.",
    "Still wrong. The message isn't going anywhere, but your dignity is.",
    "Impressive. You managed to be wrong in a brand-new way.",
    "Maybe try the 'looking at the screen' technique?",
    "Every wrong answer is being logged. Mostly for our entertainment.",
    "Your persistence is adorable. Your accuracy is not.",
]


def _generate_captcha_text() -> str:
    while True:
        length = random.randint(CAPTCHA_MIN_LEN, CAPTCHA_MAX_LEN)
        text = "".join(random.choices(_CAPTCHA_CHARS, k=length))
        if text != text[::-1]:
            return text


class LockdownFrame(tk.Frame):
    def __init__(self, parent, decoy_text: str, bailout_record: dict | None,
                 on_bailout, on_decoy, **kwargs):
        super().__init__(parent, bg=BG, **kwargs)
        self._decoy_text = decoy_text
        self._bailout_record = bailout_record
        self._on_bailout = on_bailout
        self._on_decoy = on_decoy
        self._fail_count = 0
        self._captcha_text = ""
        self._last_roast = _FIRST_ROAST
        self._build_ui()
        self._new_captcha()
        self._set_roast(_FIRST_ROAST)

    def _build_ui(self):
        tk.Label(self, text="🔒", font=("Segoe UI", 44), bg=BG).pack(pady=(28, 2))
        tk.Label(
            self, text="SYSTEM LOCKDOWN",
            font=("Segoe UI", 18, "bold"), bg=BG, fg=ACCENT
        ).pack()
        tk.Label(
            self, text="Unauthorized access suspected. Verification required.",
            font=("Segoe UI", 10), bg=BG, fg="#ef9a9a"
        ).pack(pady=(2, 14))

        tk.Label(
            self, text="Type the code below in REVERSE order:",
            font=("Segoe UI", 11, "bold"), bg=BG, fg=FG
        ).pack()

        self._captcha_label = tk.Label(
            self, font=("Courier", 34, "bold"), bg=PANEL, fg="#fff176",
            relief="solid", bd=2, padx=18, pady=8
        )
        self._captcha_label.pack(pady=10)

        entry_frame = tk.Frame(self, bg=BG)
        entry_frame.pack(pady=(4, 0))
        self._entry = tk.Entry(
            entry_frame, font=("Courier", 16), width=18,
            relief="solid", bd=1, justify="center"
        )
        self._entry.pack(side="left")
        self._entry.bind("<Return>", lambda e: self._verify())
        self._entry.focus_set()

        tk.Button(
            self, text="Submit  →", font=("Segoe UI", 11, "bold"),
            bg=ACCENT, fg="white", relief="flat", padx=22, pady=6,
            cursor="hand2", command=self._verify
        ).pack(pady=(12, 6))

        self._strike_label = tk.Label(
            self, text="", font=("Segoe UI", 9, "bold"), bg=BG, fg="#ef5350"
        )
        self._strike_label.pack()

        self._roast_label = tk.Label(
            self, text="", font=("Segoe UI", 11, "italic"), bg=BG, fg=FG,
            wraplength=440, justify="center"
        )
        self._roast_label.pack(padx=20, pady=(4, 24))

    def _new_captcha(self):
        self._captcha_text = _generate_captcha_text()
        self._captcha_label.config(text=" ".join(self._captcha_text))
        self._entry.delete(0, tk.END)

    def _set_roast(self, text: str):
        self._last_roast = text
        self._roast_label.config(text=text)

    def _next_roast(self) -> str:
        choices = [r for r in _ROASTS if r != self._last_roast]
        roast = random.choice(choices)
        if self._fail_count >= 5 and random.random() < 0.4:
            roast += f"  (Failure #{self._fail_count}. We're keeping score.)"
        return roast

    def _verify(self):
        entered = self._entry.get()
        if not entered:
            self._set_roast("Typing nothing is a choice. Not a good one, but a choice.")
            return

        if network.verify_bailout(entered, self._bailout_record):
            self._fail_count = 0
            self._on_bailout()
            return

        expected = self._captcha_text[::-1]
        if entered.strip().upper() == expected:
            self._on_decoy(self._decoy_text)
            return

        self._fail_count += 1
        self._strike_label.config(text=f"✗  Wrong entries: {self._fail_count}")
        self._set_roast(self._next_roast())
        self._new_captcha()


class LockdownController:

    def __init__(self, parent_frame: tk.Frame, decoy_text: str,
                 bailout_record: dict | None, on_bailout, on_decoy):
        self._parent = parent_frame
        self._decoy_text = decoy_text
        self._bailout_record = bailout_record
        self._on_bailout = on_bailout
        self._on_decoy = on_decoy
        self._frame = None

    def start(self):
        self._frame = LockdownFrame(
            self._parent,
            decoy_text=self._decoy_text,
            bailout_record=self._bailout_record,
            on_bailout=self._on_bailout,
            on_decoy=self._on_decoy,
        )
        self._frame.pack(fill="both", expand=True)
