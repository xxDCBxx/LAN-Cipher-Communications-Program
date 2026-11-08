import tkinter as tk
from tkinter import ttk
import random
import string
import threading

try:
    from PIL import Image, ImageDraw, ImageFont, ImageTk
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

CAPTCHA_MIN_ATTEMPTS = 8
CAPTCHA_MAX_ATTEMPTS = 15
PAYWALL_COUNTDOWN = 60

def _generate_captcha_text(length: int = 6) -> str:
    chars = string.ascii_uppercase + string.digits
    return "".join(random.choices(chars, k=length))

def _generate_captcha_image(text: str, width: int = 280, height: int = 80):
    if not PIL_AVAILABLE:
        return None

    img = Image.new("RGB", (width, height), color=(245, 245, 245))
    draw = ImageDraw.Draw(img)

    for _ in range(800):
        x = random.randint(0, width)
        y = random.randint(0, height)
        r = random.randint(100, 230)
        g = random.randint(100, 230)
        b = random.randint(100, 230)
        draw.point((x, y), fill=(r, g, b))

    for _ in range(8):
        x1, y1 = random.randint(0, width), random.randint(0, height)
        x2, y2 = random.randint(0, width), random.randint(0, height)
        color = (random.randint(150, 220), random.randint(150, 220), random.randint(150, 220))
        draw.line([(x1, y1), (x2, y2)], fill=color, width=2)

    try:
        font = ImageFont.truetype("arial.ttf", 38)
    except Exception:
        try:
            font = ImageFont.truetype("DejaVuSans.ttf", 38)
        except Exception:
            font = ImageFont.load_default()

    char_width = width // len(text)
    for i, char in enumerate(text):
        x = i * char_width + random.randint(-4, 4)
        y = random.randint(5, 25)
        color = (
            random.randint(0, 100),
            random.randint(0, 100),
            random.randint(0, 100),
        )
        draw.text((x, y), char, fill=color, font=font)

    for _ in range(4):
        x1, y1 = random.randint(0, width), random.randint(0, height)
        x2, y2 = random.randint(0, width), random.randint(0, height)
        draw.line([(x1, y1), (x2, y2)], fill=(80, 80, 80), width=1)

    return ImageTk.PhotoImage(img)



class FakeCaptchaFrame(tk.Frame):
    def __init__(self, parent, on_solved, **kwargs):
        super().__init__(parent, **kwargs)
        self.on_solved = on_solved
        self._attempt_count = 0
        self._solve_threshold = random.randint(CAPTCHA_MIN_ATTEMPTS, CAPTCHA_MAX_ATTEMPTS)
        self._captcha_text = ""
        self._photo = None
        self._build_ui()
        self._new_captcha()

    def _build_ui(self):
        self.configure(bg="#f5f5f5")

        tk.Label(
            self, text="Security Verification Required",
            font=("Segoe UI", 14, "bold"), bg="#f5f5f5", fg="#333"
        ).pack(pady=(20, 4))
        tk.Label(
            self, text="Please complete the CAPTCHA below to continue.",
            font=("Segoe UI", 10), bg="#f5f5f5", fg="#666"
        ).pack(pady=(0, 12))

        self._img_label = tk.Label(self, bg="#f5f5f5", relief="solid", bd=1)
        self._img_label.pack(pady=4)

        self._fallback_label = tk.Label(
            self, font=("Courier", 32, "bold"), bg="#ddd",
            relief="solid", bd=2, padx=10, pady=6, fg="#222"
        )

        tk.Button(
            self, text="🔄  New CAPTCHA", font=("Segoe UI", 9),
            command=self._new_captcha, relief="flat", bg="#e0e0e0", cursor="hand2"
        ).pack(pady=(4, 8))

        entry_frame = tk.Frame(self, bg="#f5f5f5")
        entry_frame.pack()
        tk.Label(entry_frame, text="Type the characters above:", bg="#f5f5f5",
                 font=("Segoe UI", 10)).pack(side="left", padx=(0, 8))
        self._entry = tk.Entry(entry_frame, font=("Courier", 14), width=10,
                               relief="solid", bd=1)
        self._entry.pack(side="left")
        self._entry.bind("<Return>", lambda e: self._verify())

        tk.Button(
            self, text="Verify →", font=("Segoe UI", 11, "bold"),
            bg="#1976D2", fg="white", relief="flat", padx=20, pady=6,
            cursor="hand2", command=self._verify
        ).pack(pady=(12, 4))

        self._error_label = tk.Label(
            self, text="", font=("Segoe UI", 10), bg="#f5f5f5", fg="#c62828"
        )
        self._error_label.pack(pady=(4, 20))

    def _new_captcha(self):
        self._captcha_text = _generate_captcha_text()
        self._entry.delete(0, tk.END)
        self._error_label.config(text="")

        photo = _generate_captcha_image(self._captcha_text)
        if photo is not None:
            self._photo = photo  
            self._img_label.config(image=self._photo)
            self._img_label.pack()
            self._fallback_label.pack_forget()
        else:
            import base64 as _b64
            scrambled = "".join(random.sample(self._captcha_text, len(self._captcha_text)))
            self._fallback_label.config(
                text=f"  {scrambled}  ",
                bg=f"#{random.randint(200,240):02x}{random.randint(200,240):02x}{random.randint(200,240):02x}"
            )
            self._fallback_label.pack()
            self._img_label.pack_forget()

    def _verify(self):
        self._attempt_count += 1

        self._error_label.config(text="✗  Incorrect. Please try again.")
        self._new_captcha()

        if self._attempt_count >= self._solve_threshold:
            self.after(400, self.on_solved)



class FakePaywallFrame(tk.Frame):
    def __init__(self, parent, decoy_text: str, on_expired, **kwargs):
        super().__init__(parent, **kwargs)
        self._decoy_text = decoy_text
        self._on_expired = on_expired
        self._seconds_left = PAYWALL_COUNTDOWN
        self._timer_id = None
        self._build_ui()
        self._start_countdown()

    def _build_ui(self):
        self.configure(bg="#1a237e")

        tk.Label(
            self, text="🔒", font=("Segoe UI", 48), bg="#1a237e"
        ).pack(pady=(30, 4))

        tk.Label(
            self, text="Premium Access Required",
            font=("Segoe UI", 18, "bold"), bg="#1a237e", fg="#ffffff"
        ).pack(pady=(0, 4))

        tk.Label(
            self, text="This feature requires a premium subscription.",
            font=("Segoe UI", 11), bg="#1a237e", fg="#b0bec5"
        ).pack()

        tk.Frame(self, height=1, bg="#3949ab").pack(fill="x", padx=40, pady=16)

        features = [
            "✓  Unlimited encrypted messaging",
            "✓  Advanced cipher algorithms",
            "✓  Priority LAN routing",
            "✓  End-to-end verification",
        ]
        for feat in features:
            tk.Label(
                self, text=feat, font=("Segoe UI", 11),
                bg="#1a237e", fg="#90caf9", anchor="w"
            ).pack(padx=60, anchor="w")

        tk.Frame(self, height=1, bg="#3949ab").pack(fill="x", padx=40, pady=16)

        tk.Button(
            self, text="Subscribe Now  →",
            font=("Segoe UI", 12, "bold"),
            bg="#ffd600", fg="#1a237e", relief="flat",
            padx=24, pady=10, cursor="hand2",
            command=lambda: None,
        ).pack(pady=(0, 8))

        tk.Label(
            self, text="Starting at $9.99/month • Cancel anytime",
            font=("Segoe UI", 9), bg="#1a237e", fg="#78909c"
        ).pack()

        tk.Frame(self, height=1, bg="#3949ab").pack(fill="x", padx=40, pady=16)
        tk.Label(
            self, text="Your access will be restored in:",
            font=("Segoe UI", 10), bg="#1a237e", fg="#78909c"
        ).pack()
        self._timer_label = tk.Label(
            self, text=f"{self._seconds_left}s",
            font=("Segoe UI", 22, "bold"), bg="#1a237e", fg="#ef5350"
        )
        self._timer_label.pack(pady=(4, 24))

    def _start_countdown(self):
        self._tick()

    def _tick(self):
        if self._seconds_left <= 0:
            self._on_expired(self._decoy_text)
            return
        self._timer_label.config(text=f"{self._seconds_left}s")
        self._seconds_left -= 1
        self._timer_id = self.after(1000, self._tick)

    def destroy(self):
        if self._timer_id:
            self.after_cancel(self._timer_id)
        super().destroy()

class HoneypotController:
    def __init__(self, parent_frame: tk.Frame, decoy_text: str, on_complete):
        self._parent = parent_frame
        self._decoy_text = decoy_text
        self._on_complete = on_complete
        self._current_frame = None

    def start(self):
        self._show_captcha()

    def _clear(self):
        if self._current_frame:
            self._current_frame.destroy()
            self._current_frame = None

    def _show_captcha(self):
        self._clear()
        frame = FakeCaptchaFrame(
            self._parent,
            on_solved=self._show_paywall,
            bg="#f5f5f5"
        )
        frame.pack(fill="both", expand=True)
        self._current_frame = frame

    def _show_paywall(self):
        self._clear()
        frame = FakePaywallFrame(
            self._parent,
            decoy_text=self._decoy_text,
            on_expired=self._finish,
            bg="#1a237e"
        )
        frame.pack(fill="both", expand=True)
        self._current_frame = frame

    def _finish(self, decoy_text: str):
        self._clear()
        self._on_complete(decoy_text)
