from math import gcd

VALID_A_VALUES = [a for a in range(1, 26) if gcd(a, 26) == 1]

def _mod_inverse(a: int, m: int) -> int:
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    raise ValueError(f"No modular inverse for a={a} mod {m}.")

def _validate_a(a: int) -> None:
    if gcd(a, 26) != 1:
        raise ValueError(
            f"Invalid key: 'a'={a} is not coprime with 26. "
            f"Valid values are: {VALID_A_VALUES}"
        )


def encrypt(plaintext: str, a: int, b: int) -> str:
    _validate_a(a)
    b = b % 26
    result = []
    for char in plaintext:
        if char.isascii() and char.isalpha():
            x = ord(char.upper()) - ord('A')
            encrypted_x = (a * x + b) % 26
            encrypted_char = chr(encrypted_x + ord('A'))
            if char.islower():
                encrypted_char = encrypted_char.lower()
            result.append(encrypted_char)
        else:
            result.append(char)
    return "".join(result)


def decrypt(ciphertext: str, a: int, b: int) -> str:
    _validate_a(a)
    b = b % 26
    a_inv = _mod_inverse(a, 26)
    result = []
    for char in ciphertext:
        if char.isascii() and char.isalpha():
            y = ord(char.upper()) - ord('A')
            decrypted_x = (a_inv * (y - b)) % 26
            decrypted_char = chr(decrypted_x + ord('A'))
            if char.islower():
                decrypted_char = decrypted_char.lower()
            result.append(decrypted_char)
        else:
            result.append(char)
    return "".join(result)


if __name__ == "__main__":
    print("=" * 50)
    print("Affine Cipher — Round-Trip Tests")
    print("=" * 50)

    test_cases = [
        ("Hello, World!", 5, 8),
        ("The Quick Brown Fox", 7, 3),
        ("LAN Cipher 123!", 11, 15),
        ("ALLUPPERCASE", 17, 0),
        ("alllowercase", 3, 20),
        ("Mixed CASE text!", 25, 7),
    ]

    all_passed = True
    for plaintext, a, b in test_cases:
        ciphertext = encrypt(plaintext, a, b)
        recovered = decrypt(ciphertext, a, b)
        status = "PASS" if recovered == plaintext else "FAIL"
        if status == "FAIL":
            all_passed = False
        print(f"[{status}] a={a}, b={b}")
        print(f"  Plaintext : {plaintext}")
        print(f"  Ciphertext: {ciphertext}")
        print(f"  Recovered : {recovered}")
        print()

    print("Invalid 'a' tests:")
    for bad_a in [2, 4, 6, 13]:
        try:
            encrypt("Hello", bad_a, 3)
            print(f"  [FAIL] a={bad_a} should have raised ValueError")
            all_passed = False
        except ValueError as e:
            print(f"  [PASS] a={bad_a} → ValueError: {e}")

    print()
    print("All tests passed!" if all_passed else "Some tests FAILED.")
