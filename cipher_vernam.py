def encrypt(plaintext: str, key: str) -> str:
    if not key:
        raise ValueError("Vernam key cannot be empty.")
    if len(key) < len(plaintext):
        raise ValueError(
            f"Vernam key is too short. "
            f"Key length ({len(key)}) must be >= plaintext length ({len(plaintext)})."
        )
    result = []
    for i, char in enumerate(plaintext):
        result.append(chr(ord(char) ^ ord(key[i % len(key)])))
    return "".join(result)


def decrypt(ciphertext: str, key: str) -> str:
    if not key:
        raise ValueError("Vernam key cannot be empty.")
    if len(key) < len(ciphertext):
        raise ValueError(
            f"Vernam key is too short. "
            f"Key length ({len(key)}) must be >= ciphertext length ({len(ciphertext)})."
        )
    result = []
    for i, char in enumerate(ciphertext):
        result.append(chr(ord(char) ^ ord(key[i % len(key)])))
    return "".join(result)


if __name__ == "__main__":
    print("=" * 50)
    print("Vernam Cipher — Round-Trip Tests")
    print("=" * 50)

    test_cases = [
        ("Hello, World!", "SecretKeyXYZAB"),
        ("The Quick Brown Fox", "AAAAAAAAAAAAAAAAAAA"),
        ("LAN Cipher 123!", "myverylongkeyhere!!"),
        ("Short", "LongKeyThatExceedsMessage"),
    ]

    all_passed = True
    for plaintext, key in test_cases:
        ciphertext = encrypt(plaintext, key)
        recovered = decrypt(ciphertext, key)
        status = "PASS" if recovered == plaintext else "FAIL"
        if status == "FAIL":
            all_passed = False
        print(f"[{status}] Key='{key[:20]}{'...' if len(key) > 20 else ''}'")
        print(f"  Plaintext  : {plaintext}")
        print(f"  Ciphertext : {repr(ciphertext)}")
        print(f"  Recovered  : {recovered}")
        print()

    # --- Key too short test ---
    print("Key too short test:")
    try:
        encrypt("Hello World", "short")
        print("  [FAIL] Should have raised ValueError")
        all_passed = False
    except ValueError as e:
        print(f"  [PASS] ValueError raised: {e}")

    print()
    print("All tests passed!" if all_passed else "Some tests FAILED.")
