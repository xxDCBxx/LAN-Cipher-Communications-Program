from cipher_vigenere import encrypt as _vig_enc, decrypt as _vig_dec
from cipher_affine import encrypt as _aff_enc, decrypt as _aff_dec
from cipher_vernam import encrypt as _ver_enc, decrypt as _ver_dec
from cipher_double_transposition import encrypt as _dt_enc, decrypt as _dt_dec

_MARKER = "MSG:"


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
        if not key:
            raise ValueError("Vernam: key cannot be empty.")
        full_key = (key * ((len(text) // len(key)) + 1))[:len(text)]
        return _ver_enc(text, full_key) if mode == "encrypt" else _ver_dec(text, full_key)

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

    for step in steps:
        if step.get("cipher", "").lower() == "vernam":
            key = step.get("key", "")
            if len(key) < len(plaintext):
                raise ValueError(
                    f"Vernam key is too short. "
                    f"Key length ({len(key)}) must be >= plaintext length ({len(plaintext)})."
                )

    text = _MARKER + plaintext
    for step in steps:
        text = _apply_cipher(text, step, "encrypt")
    return text


def decode(ciphertext: str, steps: list) -> tuple:
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

    if text.startswith(_MARKER):
        return True, text[len(_MARKER):]
    return False, text


if __name__ == "__main__":
    print("=" * 60)
    print("encrypt_order.py — Cipher Chain Tests")
    print("=" * 60)
    all_passed = True

    # --- Test 1: Single Vigenère round-trip ---
    print("\n[Test 1] Single Vigenère")
    steps = [{"cipher": "vigenere", "key": "SECRET"}]
    ct = encode("Hello World", steps)
    ok, pt = decode(ct, steps)
    status = "PASS" if ok and pt == "Hello World" else "FAIL"
    if status == "FAIL": all_passed = False
    print(f"  [{status}] Ciphertext: {ct!r} → Recovered: {pt!r}")

    # --- Test 2: Single Affine round-trip ---
    print("\n[Test 2] Single Affine")
    steps = [{"cipher": "affine", "a": 5, "b": 8}]
    ct = encode("LAN Cipher", steps)
    ok, pt = decode(ct, steps)
    status = "PASS" if ok and pt == "LAN Cipher" else "FAIL"
    if status == "FAIL": all_passed = False
    print(f"  [{status}] Ciphertext: {ct!r} → Recovered: {pt!r}")

    # --- Test 3: Single Vernam round-trip ---
    print("\n[Test 3] Single Vernam")
    steps = [{"cipher": "vernam", "key": "XXXXXXXXXXXXXXXXXXXXXXXXXXX"}]
    ct = encode("Test Message!", steps)
    ok, pt = decode(ct, steps)
    status = "PASS" if ok and pt == "Test Message!" else "FAIL"
    if status == "FAIL": all_passed = False
    print(f"  [{status}] Recovered: {pt!r}")

    # --- Test 3b: Single Vernam with exact plaintext length key (4 letters) ---
    print("\n[Test 3b] Single Vernam with 4-letter key and 4-letter plaintext")
    steps_4 = [{"cipher": "vernam", "key": "WXYZ"}]
    ct_4 = encode("cats", steps_4)
    ok_4, pt_4 = decode(ct_4, steps_4)
    status_4 = "PASS" if ok_4 and pt_4 == "cats" else "FAIL"
    if status_4 == "FAIL": all_passed = False
    print(f"  [{status_4}] Plaintext: 'cats', Key: 'WXYZ' → Recovered: {pt_4!r}")

    # --- Test 3c: Vernam key too short (3 letters for 4-letter plaintext) ---
    print("\n[Test 3c] Vernam key too short test")
    try:
        encode("cats", [{"cipher": "vernam", "key": "WXY"}])
        print("  [FAIL] Should have raised ValueError")
        all_passed = False
    except ValueError as e:
        print(f"  [PASS] ValueError: {e}")

    # --- Test 4: Single Double Transposition round-trip ---
    print("\n[Test 4] Single Double Transposition")
    steps = [{"cipher": "double_transposition", "key1": "CARGO", "key2": "SHIP"}]
    ct = encode("Attack at dawn", steps)
    ok, pt = decode(ct, steps)
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
    ct = encode(plaintext, steps)
    ok, pt = decode(ct, list(reversed(steps)))
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
    ct = encode(plaintext, steps)
    ok, pt = decode(ct, list(reversed(steps)))
    status = "PASS" if ok and pt == plaintext else "FAIL"
    if status == "FAIL": all_passed = False
    print(f"  [{status}] Recovered: {pt!r}")

    # --- Test 7: Wrong key → failure detection ---
    print("\n[Test 7] Wrong key failure detection")
    steps_enc = [{"cipher": "vigenere", "key": "CORRECT"}]
    steps_dec_wrong = [{"cipher": "vigenere", "key": "WRONGKEY"}]
    ct = encode("Secret message", steps_enc)
    ok, pt = decode(ct, steps_dec_wrong)
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
    steps_dec_wrong_order = [
        {"cipher": "vigenere", "key": "HELLO"},
        {"cipher": "affine", "a": 5, "b": 8},
    ]
    ct = encode("Order matters", steps_enc)
    ok, pt = decode(ct, steps_dec_wrong_order)
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

    print()
    print("=" * 60)
    print("All tests passed!" if all_passed else "Some tests FAILED.")
