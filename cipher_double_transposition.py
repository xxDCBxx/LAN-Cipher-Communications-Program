import math

_LEN_PREFIX = 4  # digits reserved for the plaintext length prefix


def _get_column_order(key: str) -> list:
    indexed = sorted(enumerate(key.upper()), key=lambda x: (x[1], x[0]))
    return [i for i, _ in indexed]


def _col_heights(original_len: int, num_cols: int) -> list:
    num_rows = math.ceil(original_len / num_cols)
    last_row_filled = original_len % num_cols
    if last_row_filled == 0:
        last_row_filled = num_cols
    heights = []
    for col in range(num_cols):
        if col < last_row_filled:
            heights.append(num_rows)
        else:
            heights.append(num_rows - 1)
    return heights


def _columnar_encrypt(text: str, key: str) -> str:
    num_cols = len(key)
    original_len = len(text)
    num_rows = math.ceil(original_len / num_cols)

    padded = text.ljust(num_rows * num_cols, '\x00')
    grid = [padded[i * num_cols:(i + 1) * num_cols] for i in range(num_rows)]

    heights = _col_heights(original_len, num_cols)
    order = _get_column_order(key)

    result = []
    for col in order:
        for row in range(heights[col]):
            result.append(grid[row][col])
    return "".join(result)


def _columnar_decrypt(ciphertext: str, key: str, original_len: int) -> str:

    num_cols = len(key)
    order = _get_column_order(key)
    heights = _col_heights(original_len, num_cols)

    columns = {}
    pos = 0
    for col in order:
        h = heights[col]
        columns[col] = ciphertext[pos:pos + h]
        pos += h

    num_rows = math.ceil(original_len / num_cols)
    result = []
    for row in range(num_rows):
        for col in range(num_cols):
            if row < heights[col]:
                result.append(columns[col][row])
    return "".join(result)


def encrypt(plaintext: str, key1: str, key2: str) -> str:
    if not key1 or not key2:
        raise ValueError("Both keys must be non-empty strings.")
    original_len = len(plaintext)
    if original_len == 0:
        return str(0).zfill(_LEN_PREFIX)
    if original_len >= 10 ** _LEN_PREFIX:
        raise ValueError(f"Plaintext too long (max {10 ** _LEN_PREFIX - 1} characters).")

    prefix = str(original_len).zfill(_LEN_PREFIX)
    intermediate = _columnar_encrypt(plaintext, key1)
    ciphertext = _columnar_encrypt(intermediate, key2)
    return prefix + ciphertext


def decrypt(ciphertext_with_prefix: str, key1: str, key2: str) -> str:
    if not key1 or not key2:
        raise ValueError("Both keys must be non-empty strings.")
    if len(ciphertext_with_prefix) < _LEN_PREFIX:
        raise ValueError("Ciphertext is too short to be valid.")

    original_len = int(ciphertext_with_prefix[:_LEN_PREFIX])
    body = ciphertext_with_prefix[_LEN_PREFIX:]

    if original_len == 0:
        return ""

    len_after_first = original_len

    intermediate = _columnar_decrypt(body, key2, len_after_first)
    plaintext = _columnar_decrypt(intermediate, key1, original_len)
    return plaintext


if __name__ == "__main__":
    print("=" * 50)
    print("Double Transposition Cipher — Round-Trip Tests")
    print("=" * 50)

    test_cases = [
        ("Hello World", "CARGO", "SHIP"),
        ("The Quick Brown Fox Jumps", "SECRET", "KEY"),
        ("LAN Cipher", "ALPHA", "BETA"),
        ("ATTACK AT DAWN", "ZEBRA", "LEMON"),
        ("Short", "AB", "CD"),
        ("Exactly fitting!!", "FOUR", "KEYS"),
        ("A", "XY", "ZW"),
        ("abcdefghij", "ABC", "DEF"),
        ("Hello, World! 123", "CRYPTO", "SECURE"),
        ("MSG:secret message here", "KEY1", "KEY2"),
        ("", "KEY", "ABC"),
    ]

    all_passed = True
    for plaintext, key1, key2 in test_cases:
        ciphertext = encrypt(plaintext, key1, key2)
        recovered = decrypt(ciphertext, key1, key2)
        status = "PASS" if recovered == plaintext else "FAIL"
        if status == "FAIL":
            all_passed = False
        print(f"[{status}] key1='{key1}', key2='{key2}'")
        print(f"  Plaintext : {repr(plaintext)}")
        print(f"  Ciphertext: {repr(ciphertext)}")
        print(f"  Recovered : {repr(recovered)}")
        print()

    # Wrong key test (should not recover original)
    print("Wrong key test:")
    ct = encrypt("Hello World", "CARGO", "SHIP")
    wrong = decrypt(ct, "WRONG", "KEYS")
    status = "PASS" if wrong != "Hello World" else "FAIL"
    if status == "FAIL":
        all_passed = False
    print(f"  [{status}] Wrong keys give different output: {repr(wrong)}")
    print()

    # Empty key test
    print("Empty key test:")
    try:
        encrypt("Hello", "", "KEY")
        print("  [FAIL] Should have raised ValueError")
        all_passed = False
    except ValueError as e:
        print(f"  [PASS] ValueError raised: {e}")

    print()
    print("All tests passed!" if all_passed else "Some tests FAILED.")
