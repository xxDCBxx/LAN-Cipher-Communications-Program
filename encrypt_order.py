import base64
import hashlib
import hmac
import json
import os

from cipher_vigenere import encrypt as _vig_enc, decrypt as _vig_dec
from cipher_affine import encrypt as _aff_enc, decrypt as _aff_dec
from cipher_vernam import encrypt as _ver_enc, decrypt as _ver_dec
from cipher_double_transposition import encrypt as _dt_enc, decrypt as _dt_dec

_VERIFIER_ITERATIONS = 100_000
_MAX_ACCEPTED_ITERATIONS = 1_000_000


def _canonical_steps(steps: list) -> list:
    out = []
    for s in steps:
        name = s.get("cipher", "").lower()
        if name == "vigenere":
            out.append([name, "".join(c for c in str(s["key"]) if c.isalpha()).upper()])
        elif name == "affine":
            out.append([name, int(s["a"]), int(s["b"]) % 26])
        elif name == "vernam":
            out.append([name, str(s["key"])])
        elif name == "double_transposition":
            out.append([name, str(s["key1"]).upper(), str(s["key2"]).upper()])
        else:
            out.append([name])
    return out


def _hash_text(text: str, steps: list, salt: bytes, iters: int) -> bytes:
    data = json.dumps(
        {"p": text, "k": _canonical_steps(steps)},
        ensure_ascii=True, sort_keys=True,
    ).encode("utf-8")
    return hashlib.pbkdf2_hmac("sha256", data, salt, iters)


def make_verifier(plaintext: str, steps: list) -> dict:
    salt = os.urandom(16)
    digest = _hash_text(plaintext, steps, salt, _VERIFIER_ITERATIONS)
    return {
        "salt": base64.b64encode(salt).decode("ascii"),
        "hash": base64.b64encode(digest).decode("ascii"),
        "iters": _VERIFIER_ITERATIONS,
    }


def check_verifier(text: str, steps: list, verifier: dict | None) -> bool:
    if not verifier:
        return False
    try:
        salt = base64.b64decode(verifier["salt"])
        expected = base64.b64decode(verifier["hash"])
        iters = int(verifier["iters"])
        if not (1 <= iters <= _MAX_ACCEPTED_ITERATIONS):
            return False
        return hmac.compare_digest(_hash_text(text, steps, salt, iters), expected)
    except Exception:
        return False


def _apply_cipher(text: str, step: dict, mode: str) -> str:
    name = step.get("cipher", "").lower()

    if name == "vigenere":
        key = step["key"]
        return _vig_enc(text, key) if mode == "encrypt" else _vig_dec(text, key)

    elif name == "affine":
        a, b = int(step["a"]), int(step["b"])
        return _aff_enc(text, a, b) if mode == "encrypt" else _aff_dec(text, a, b)

    elif name == "vernam":
        key = step["key"]
        return _ver_enc(text, key) if mode == "encrypt" else _ver_dec(text, key)

    elif name == "double_transposition":
        key1, key2 = step["key1"], step["key2"]
        return _dt_enc(text, key1, key2) if mode == "encrypt" else _dt_dec(text, key1, key2)

    else:
        raise ValueError(f"Unknown cipher: '{name}'. "
                         f"Valid options: vigenere, affine, vernam, double_transposition")


def encode(plaintext: str, steps: list) -> str:
    if not steps:
        raise ValueError("At least one cipher step is required.")
    if len(steps) > 3:
        raise ValueError("A maximum of 3 cipher steps are allowed.")

    text = plaintext
    for step in steps:
        text = _apply_cipher(text, step, "encrypt")
    return text


def decode(ciphertext: str, steps: list, verifier: dict | None = None) -> tuple:
    if not steps:
        return False, ""
    if len(steps) > 3:
        return False, ""

    text = ciphertext
    for step in steps:
        try:
            text = _apply_cipher(text, step, "decrypt")
        except Exception:
            return False, ""

    if check_verifier(text, list(reversed(steps)), verifier):
        return True, text
    return False, text


if __name__ == "__main__":
    print("=" * 60)
    print("encrypt_order.py — Cipher Chain Tests")
    print("=" * 60)
    all_passed = True

    def roundtrip(plaintext, steps_enc, steps_dec=None):
        ct = encode(plaintext, steps_enc)
        v = make_verifier(plaintext, steps_enc)
        if steps_dec is None:
            steps_dec = list(reversed(steps_enc))
        ok, pt = decode(ct, steps_dec, v)
        return ct, ok, pt

    # --- Test 1: Single Vigenère round-trip ---
    print("\n[Test 1] Single Vigenère")
    steps = [{"cipher": "vigenere", "key": "SECRET"}]
    ct, ok, pt = roundtrip("Hello World", steps)
    status = "PASS" if ok and pt == "Hello World" else "FAIL"
    if status == "FAIL": all_passed = False
    print(f"  [{status}] Ciphertext: {ct!r} → Recovered: {pt!r}")

    # --- Test 2: Single Affine round-trip ---
    print("\n[Test 2] Single Affine")
    steps = [{"cipher": "affine", "a": 5, "b": 8}]
    ct, ok, pt = roundtrip("LAN Cipher", steps)
    status = "PASS" if ok and pt == "LAN Cipher" else "FAIL"
    if status == "FAIL": all_passed = False
    print(f"  [{status}] Ciphertext: {ct!r} → Recovered: {pt!r}")

    # --- Test 3: Single Vernam round-trip ---
    print("\n[Test 3] Single Vernam")
    steps = [{"cipher": "vernam", "key": "XXXXXXXXXXXXXXXXXXXXXXXXXXX"}]
    ct, ok, pt = roundtrip("Test Message!", steps)
    status = "PASS" if ok and pt == "Test Message!" else "FAIL"
    if status == "FAIL": all_passed = False
    print(f"  [{status}] Recovered: {pt!r}")

    # --- Test 4: Single Double Transposition round-trip ---
    print("\n[Test 4] Single Double Transposition")
    steps = [{"cipher": "double_transposition", "key1": "CARGO", "key2": "SHIP"}]
    ct, ok, pt = roundtrip("Attack at dawn", steps)
    status = "PASS" if ok and pt == "Attack at dawn" else "FAIL"
    if status == "FAIL": all_passed = False
    print(f"  [{status}] Ciphertext: {ct!r} → Recovered: {pt!r}")

    # --- Test 5: 3-cipher chain (Vigenère → Affine → Double Transposition) ---
    print("\n[Test 5] 3-cipher chain: Vigenère → Affine → Double Transposition")
    plaintext = "Send reinforcements immediately!"
    steps = [
        {"cipher": "vigenere", "key": "KEYWORD"},
        {"cipher": "affine", "a": 7, "b": 3},
        {"cipher": "double_transposition", "key1": "ZEBRA", "key2": "LEMON"},
    ]
    ct, ok, pt = roundtrip(plaintext, steps)
    status = "PASS" if ok and pt == plaintext else "FAIL"
    if status == "FAIL": all_passed = False
    print(f"  [{status}] Ciphertext: {ct!r}")
    print(f"  [{status}] Recovered : {pt!r}")

    # --- Test 6: 3-cipher chain with a repeat (Affine → Vigenère → Affine) ---
    print("\n[Test 6] 3-cipher chain with repeat: Affine → Vigenère → Affine")
    plaintext = "Repeat ciphers allowed!"
    steps = [
        {"cipher": "affine", "a": 5, "b": 8},
        {"cipher": "vigenere", "key": "DOUBLE"},
        {"cipher": "affine", "a": 11, "b": 14},
    ]
    ct, ok, pt = roundtrip(plaintext, steps)
    status = "PASS" if ok and pt == plaintext else "FAIL"
    if status == "FAIL": all_passed = False
    print(f"  [{status}] Recovered: {pt!r}")

    # --- Test 7: Wrong key → failure detection ---
    print("\n[Test 7] Wrong key failure detection")
    steps_enc = [{"cipher": "vigenere", "key": "CORRECT"}]
    steps_dec_wrong = [{"cipher": "vigenere", "key": "WRONGKEY"}]
    _, ok, pt = roundtrip("Secret message", steps_enc, steps_dec_wrong)
    status = "PASS" if not ok else "FAIL"
    if status == "FAIL": all_passed = False
    print(f"  [{status}] decode returned success={ok} (expected False)")

    # --- Test 8: Wrong order → failure detection ---
    print("\n[Test 8] Wrong order failure detection")
    steps_enc = [
        {"cipher": "vigenere", "key": "HELLO"},
        {"cipher": "affine", "a": 5, "b": 8},
    ]
    # Wrong order: entering same order as encryption instead of reverse order
    _, ok, pt = roundtrip("Order matters", steps_enc, list(steps_enc))
    status = "PASS" if not ok else "FAIL"
    if status == "FAIL": all_passed = False
    print(f"  [{status}] decode returned success={ok} (expected False)")

    # --- Test 9: Empty steps → error ---
    print("\n[Test 9] Empty steps → error")
    try:
        encode("test", [])
        print("  [FAIL] Should have raised ValueError")
        all_passed = False
    except ValueError as e:
        print(f"  [PASS] ValueError: {e}")

    # --- Test 10: Too many steps → error ---
    print("\n[Test 10] More than 3 steps → error")
    try:
        encode("test", [{"cipher": "vigenere", "key": "A"}] * 4)
        print("  [FAIL] Should have raised ValueError")
        all_passed = False
    except ValueError as e:
        print(f"  [PASS] ValueError: {e}")

    print("\n[Test 11] Partly-right Vigenère keys")
    enc = [{"cipher": "vigenere", "key": "test"}]
    for plaintext in ("test", "Meet me at noon"):
        for bad in ("tes", "testt", "tesx", "te"):
            _, ok, _ = roundtrip(plaintext, enc, [{"cipher": "vigenere", "key": bad}])
            status = "PASS" if not ok else "FAIL"
            if status == "FAIL": all_passed = False
            print(f"  [{status}] {plaintext!r} key {bad!r} → success={ok} (expected False)")
    _, ok, _ = roundtrip("test", enc, [{"cipher": "vigenere", "key": "TEST"}])
    status = "PASS" if ok else "FAIL"
    if status == "FAIL": all_passed = False
    print(f"  [{status}] key 'TEST' → success={ok} (expected True)")

    print("\n[Test 12] No length overhead")
    pt_len = "Attack at dawn"
    for steps in (
        [{"cipher": "vigenere", "key": "KEY"}],
        [{"cipher": "affine", "a": 5, "b": 8}],
        [{"cipher": "vernam", "key": "k" * len(pt_len)}],
    ):
        ct = encode(pt_len, steps)
        status = "PASS" if len(ct) == len(pt_len) else "FAIL"
        if status == "FAIL": all_passed = False
        print(f"  [{status}] {steps[0]['cipher']}: len {len(ct)} == {len(pt_len)}")

    print("\n[Test 13] Missing verifier")
    ct = encode("hello", [{"cipher": "vigenere", "key": "K"}])
    ok, _ = decode(ct, [{"cipher": "vigenere", "key": "K"}], None)
    status = "PASS" if not ok else "FAIL"
    if status == "FAIL": all_passed = False
    print(f"  [{status}] success={ok} (expected False)")

    print()
    print("=" * 60)
    print("All tests passed!" if all_passed else "Some tests FAILED.")
