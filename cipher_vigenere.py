def _clean_key(key: str) -> str:
    cleaned = "".join(c for c in key if c.isalpha()).upper()
    if not cleaned:
        raise ValueError("Vigenère key must contain at least one alphabetic character.")
    return cleaned


def encrypt(plaintext: str, key: str) -> str:
    key = _clean_key(key)
    result = []
    key_index = 0
    for char in plaintext:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - ord('A')
            if char.isupper():
                encrypted_char = chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
            else:
                encrypted_char = chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
            result.append(encrypted_char)
            key_index += 1
        else:
            result.append(char)
    return "".join(result)


def decrypt(ciphertext: str, key: str) -> str:
    key = _clean_key(key)
    result = []
    key_index = 0
    for char in ciphertext:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - ord('A')
            if char.isupper():
                decrypted_char = chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
            else:
                decrypted_char = chr((ord(char) - ord('a') - shift) % 26 + ord('a'))
            result.append(decrypted_char)
            key_index += 1
        else:
            result.append(char)
    return "".join(result)


if __name__ == "__main__":
    # --- Round-trip test ---
    test_cases = [
        ("Hello, World!", "SECRET"),
        ("The Quick Brown Fox", "KEY"),
        ("LAN Cipher 123!", "CRYPTO"),
        ("ALLUPPERCASE", "KEYWORD"),
        ("alllowercase", "keyword"),
        ("Mixed CASE text!", "TestKey"),
    ]

    print("=" * 50)
    print("Vigenère Cipher — Round-Trip Tests")
    print("=" * 50)
    all_passed = True
    for plaintext, key in test_cases:
        ciphertext = encrypt(plaintext, key)
        recovered = decrypt(ciphertext, key)
        status = "PASS" if recovered == plaintext else "FAIL"
        if status == "FAIL":
            all_passed = False
        print(f"[{status}] Key='{key}'")
        print(f"  Plaintext : {plaintext}")
        print(f"  Ciphertext: {ciphertext}")
        print(f"  Recovered : {recovered}")
        print()

    # --- Invalid key test ---
    print("Invalid key test (digits only):")
    try:
        encrypt("Hello", "12345")
        print("  [FAIL] Should have raised ValueError")
        all_passed = False
    except ValueError as e:
        print(f"  [PASS] ValueError raised: {e}")

    print()
    print("All tests passed!" if all_passed else "Some tests FAILED.")
