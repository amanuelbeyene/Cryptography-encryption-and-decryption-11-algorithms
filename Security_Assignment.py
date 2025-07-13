import math
import random

# ---------------- Utility Function ----------------
def mod_inv(a: int, m: int) -> int:
    """Return the multiplicative inverse of a modulo m, if it exists."""
    a = a % m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

# ======================= TRANSPOSITION CIPHERS ===========================

# ---------------- Rail-Fence Transposition Cipher ----------------
def rail_fence_encrypt(plaintext: str, num_rails: int) -> str:
    if num_rails <= 1:
        return plaintext
    rails = ['' for _ in range(num_rails)]
    rail = 0
    direction = 1  # start going down
    for char in plaintext:
        rails[rail] += char
        rail += direction
        if rail == 0 or rail == num_rails - 1:
            direction *= -1
    return ''.join(rails)

def rail_fence_decrypt(ciphertext: str, num_rails: int) -> str:
    if num_rails <= 1:
        return ciphertext
    # Reconstruct shape pattern
    pattern = []
    rail = 0
    direction = 1
    for _ in range(len(ciphertext)):
        pattern.append(rail)
        rail += direction
        if rail == 0 or rail == num_rails - 1:
            direction *= -1

    # Allocate characters to rails
    rails = {i: [] for i in range(num_rails)}
    index = 0
    for rail_index in range(num_rails):
        for i in range(len(ciphertext)):
            if pattern[i] == rail_index:
                rails[rail_index].append(ciphertext[index])
                index += 1

    # Reconstruct the plaintext following the pattern.
    result = []
    counter = {i: 0 for i in range(num_rails)}
    for r in pattern:
        result.append(rails[r][counter[r]])
        counter[r] += 1
    return ''.join(result)

# ---------------- Route (Spiral Transposition) Cipher ----------------
def route_cipher_encrypt(plaintext: str, rows: int, cols: int) -> str:
    total = rows * cols
    plaintext = plaintext.ljust(total, 'X')  # pad with "X"
    matrix = []
    index = 0
    for _ in range(rows):
        matrix.append([plaintext[index + j] for j in range(cols)])
        index += cols

    result = []
    top, bottom = 0, rows - 1
    left, right = 0, cols - 1
    while top <= bottom and left <= right:
        for i in range(left, right + 1):
            result.append(matrix[top][i])
        top += 1
        for i in range(top, bottom + 1):
            result.append(matrix[i][right])
        right -= 1
        if top <= bottom:
            for i in range(right, left - 1, -1):
                result.append(matrix[bottom][i])
            bottom -= 1
        if left <= right:
            for i in range(bottom, top - 1, -1):
                result.append(matrix[i][left])
            left += 1
    return ''.join(result)

def route_cipher_decrypt(ciphertext: str, rows: int, cols: int) -> str:
    matrix = [[None] * cols for _ in range(rows)]
    index = 0
    top, bottom = 0, rows - 1
    left, right = 0, cols - 1
    while top <= bottom and left <= right:
        for i in range(left, right + 1):
            matrix[top][i] = ciphertext[index]
            index += 1
        top += 1
        for i in range(top, bottom + 1):
            matrix[i][right] = ciphertext[index]
            index += 1
        right -= 1
        if top <= bottom:
            for i in range(right, left - 1, -1):
                matrix[bottom][i] = ciphertext[index]
                index += 1
            bottom -= 1
        if left <= right:
            for i in range(bottom, top - 1, -1):
                matrix[i][left] = ciphertext[index]
                index += 1
            left += 1
    # Read row-wise
    plain = ''.join(''.join(row) for row in matrix)
    return plain

# ---------------- Columnar Transposition Cipher ----------------
def columnar_transposition_encrypt(plaintext: str, key: str) -> str:
    num_cols = len(key)
    num_rows = (len(plaintext) + num_cols - 1) // num_cols
    total = num_rows * num_cols
    plaintext = plaintext.ljust(total, 'X')
    matrix = []
    index = 0
    for _ in range(num_rows):
        matrix.append([plaintext[index + j] for j in range(num_cols)])
        index += num_cols

    order = sorted(list(enumerate(key)), key=lambda x: (x[1], x[0]))
    result = []
    for col_index, _ in order:
        for row in matrix:
            result.append(row[col_index])
    return ''.join(result)

def columnar_transposition_decrypt(ciphertext: str, key: str) -> str:
    num_cols = len(key)
    num_rows = len(ciphertext) // num_cols
    order = sorted(list(enumerate(key)), key=lambda x: (x[1], x[0]))
    matrix = [[''] * num_cols for _ in range(num_rows)]
    index = 0
    for col_index, _ in order:
        for r in range(num_rows):
            matrix[r][col_index] = ciphertext[index]
            index += 1
    result = []
    for row in matrix:
        result.extend(row)
    return ''.join(result).rstrip('X')

# ---------------- Double Transposition Cipher ----------------
def double_transposition_encrypt(plaintext: str, key1: str, key2: str) -> str:
    first_pass = columnar_transposition_encrypt(plaintext, key1)
    return columnar_transposition_encrypt(first_pass, key2)

def double_transposition_decrypt(ciphertext: str, key1: str, key2: str) -> str:
    first_pass = columnar_transposition_decrypt(ciphertext, key2)
    return columnar_transposition_decrypt(first_pass, key1)

# ---------------- Myszkowski Transposition Cipher ----------------
def myszkowski_encrypt(plaintext: str, key: str) -> str:
    num_cols = len(key)
    num_rows = (len(plaintext) + num_cols - 1) // num_cols
    total = num_rows * num_cols
    plaintext = plaintext.ljust(total, 'X')
    matrix = []
    index = 0
    for _ in range(num_rows):
        matrix.append([plaintext[index + c] for c in range(num_cols)])
        index += num_cols

    groups = {}
    for idx, letter in enumerate(key):
        groups.setdefault(letter, []).append(idx)
    
    result = []
    for letter in sorted(groups.keys()):
        cols = groups[letter]
        if len(cols) == 1:
            col = cols[0]
            for r in range(num_rows):
                result.append(matrix[r][col])
        else:
            for r in range(num_rows):
                for col in cols:
                    result.append(matrix[r][col])
    return ''.join(result)

def myszkowski_decrypt(ciphertext: str, key: str) -> str:
    num_cols = len(key)
    num_rows = len(ciphertext) // num_cols
    groups = {}
    for idx, letter in enumerate(key):
        groups.setdefault(letter, []).append(idx)
    
    group_cipher = {}
    cipher_remainder = ciphertext
    for letter in sorted(groups.keys()):
        cols = groups[letter]
        if len(cols) == 1:
            length = num_rows
            group_cipher[letter] = cipher_remainder[:length]
            cipher_remainder = cipher_remainder[length:]
        else:
            length = num_rows * len(cols)
            group_cipher[letter] = cipher_remainder[:length]
            cipher_remainder = cipher_remainder[length:]
    
    matrix = [[''] * num_cols for _ in range(num_rows)]
    for letter in sorted(groups.keys()):
        cols = groups[letter]
        if len(cols) == 1:
            col = cols[0]
            text = group_cipher[letter]
            for r in range(num_rows):
                matrix[r][col] = text[r]
        else:
            text = group_cipher[letter]
            chunk_size = len(cols)
            for r in range(num_rows):
                chunk = text[r * chunk_size: (r + 1) * chunk_size]
                for j, col in enumerate(cols):
                    matrix[r][col] = chunk[j]
    plaintext = ''.join(''.join(row) for row in matrix)
    return plaintext.rstrip('X')

# ---------------- Disruptive Transposition Cipher ----------------
def disruptive_transposition_encrypt(text: str, key: str) -> str:
    """
    This implementation uses the key to create a pseudo-random permutation
    of the indices of the text.
    """
    seed = sum(ord(c) for c in key)
    perm = list(range(len(text)))
    rnd = random.Random(seed)
    rnd.shuffle(perm)
    ciphertext_chars = [''] * len(text)
    for i, char in enumerate(text):
        ciphertext_chars[perm[i]] = char
    return ''.join(ciphertext_chars)

def disruptive_transposition_decrypt(ciphertext: str, key: str) -> str:
    seed = sum(ord(c) for c in key)
    perm = list(range(len(ciphertext)))
    rnd = random.Random(seed)
    rnd.shuffle(perm)
    inv_perm = [0] * len(ciphertext)
    for i, p in enumerate(perm):
        inv_perm[p] = i
    plaintext_chars = [''] * len(ciphertext)
    for i, char in enumerate(ciphertext):
        plaintext_chars[inv_perm[i]] = char
    return ''.join(plaintext_chars)

# ======================= SUBSTITUTION CIPHERS ===========================

# ---------------- Additive (Shift) Cipher ----------------
def additive_encrypt(text: str, key: int) -> str:
    text = text.upper()
    result = ""
    for char in text:
        if 'A' <= char <= 'Z':
            result += chr(((ord(char) - ord('A') + key) % 26) + ord('A'))
        else:
            result += char
    return result

def additive_decrypt(text: str, key: int) -> str:
    return additive_encrypt(text, -key)

# ---------------- Multiplicative Cipher ----------------
def multiplicative_encrypt(text: str, key: int) -> str:
    if math.gcd(key, 26) != 1:
        print("Error: The key must be coprime with 26.")
        return ""
    text = text.upper()
    result = ""
    for char in text:
        if 'A' <= char <= 'Z':
            result += chr((((ord(char) - ord('A')) * key) % 26) + ord('A'))
        else:
            result += char
    return result

def multiplicative_decrypt(text: str, key: int) -> str:
    if math.gcd(key, 26) != 1:
        print("Error: The key must be coprime with 26.")
        return ""
    inverse = mod_inv(key, 26)
    if inverse is None:
        print("Error: No modular inverse for this key!")
        return ""
    text = text.upper()
    result = ""
    for char in text:
        if 'A' <= char <= 'Z':
            result += chr((((ord(char) - ord('A')) * inverse) % 26) + ord('A'))
        else:
            result += char
    return result

# ---------------- Affine Cipher ----------------
def affine_encrypt(text: str, a: int, b: int) -> str:
    if math.gcd(a, 26) != 1:
        print("Error: Key 'a' must be coprime with 26.")
        return ""
    text = text.upper()
    result = ""
    for char in text:
        if 'A' <= char <= 'Z':
            result += chr(((a * (ord(char) - 65) + b) % 26) + 65)
        else:
            result += char
    return result

def affine_decrypt(text: str, a: int, b: int) -> str:
    if math.gcd(a, 26) != 1:
        print("Error: Key 'a' must be coprime with 26.")
        return ""
    inverse = mod_inv(a, 26)
    if inverse is None:
        print("Error: No modular inverse found for 'a'.")
        return ""
    text = text.upper()
    result = ""
    for char in text:
        if 'A' <= char <= 'Z':
            result += chr((inverse * ((ord(char) - 65) - b) % 26) + 65)
        else:
            result += char
    return result

# ---------------- Playfair Cipher ----------------
def generate_key_table(key: str) -> list:
    key = key.lower().replace('j', 'i')
    seen = set()
    table = []
    for char in key:
        if char.isalpha() and char not in seen:
            seen.add(char)
            table.append(char)
    for char in "abcdefghiklmnopqrstuvwxyz":  # note: no 'j'
        if char not in seen:
            table.append(char)
    return [table[i*5:(i+1)*5] for i in range(5)]

def find_position(letter: str, table: list) -> tuple:
    letter = letter.lower().replace('j', 'i')
    for i, row in enumerate(table):
        if letter in row:
            return (i, row.index(letter))
    return None

def playfair_encrypt(plaintext: str, key: str) -> str:
    table = generate_key_table(key)
    plaintext = plaintext.lower().replace('j', 'i')
    plaintext = "".join(c for c in plaintext if c.isalpha())
    digraphs = []
    i = 0
    while i < len(plaintext):
        a = plaintext[i]
        if i+1 < len(plaintext):
            b = plaintext[i+1]
            if a == b:
                digraphs.append(a + 'x')
                i += 1
            else:
                digraphs.append(a + b)
                i += 2
        else:
            digraphs.append(a + 'x')
            i += 1
    result = ""
    for pair in digraphs:
        a, b = pair[0], pair[1]
        row1, col1 = find_position(a, table)
        row2, col2 = find_position(b, table)
        if row1 == row2:
            result += table[row1][(col1 + 1) % 5]
            result += table[row2][(col2 + 1) % 5]
        elif col1 == col2:
            result += table[(row1 + 1) % 5][col1]
            result += table[(row2 + 1) % 5][col2]
        else:
            result += table[row1][col2]
            result += table[row2][col1]
    return result.upper()

def playfair_decrypt(ciphertext: str, key: str) -> str:
    table = generate_key_table(key)
    ciphertext = ciphertext.lower().replace('j', 'i')
    ciphertext = "".join(c for c in ciphertext if c.isalpha())
    digraphs = [ciphertext[i:i+2] for i in range(0, len(ciphertext), 2)]
    result = ""
    for pair in digraphs:
        a, b = pair[0], pair[1]
        row1, col1 = find_position(a, table)
        row2, col2 = find_position(b, table)
        if row1 == row2:
            result += table[row1][(col1 - 1) % 5]
            result += table[row2][(col2 - 1) % 5]
        elif col1 == col2:
            result += table[(row1 - 1) % 5][col1]
            result += table[(row2 - 1) % 5][col2]
        else:
            result += table[row1][col2]
            result += table[row2][col1]
    return result.upper()

# ---------------- Hill Cipher (2x2 Key Matrix) ----------------
def hill_encrypt(plaintext: str, key_matrix: list) -> str:
    text = "".join(c for c in plaintext.upper() if c.isalpha())
    if len(text) % 2 != 0:
        text += "X"
    result = ""
    for i in range(0, len(text), 2):
        pair = text[i:i+2]
        vector = [ord(pair[0]) - 65, ord(pair[1]) - 65]
        num1 = (key_matrix[0][0]*vector[0] + key_matrix[0][1]*vector[1]) % 26
        num2 = (key_matrix[1][0]*vector[0] + key_matrix[1][1]*vector[1]) % 26
        result += chr(num1 + 65) + chr(num2 + 65)
    return result

def hill_decrypt(ciphertext: str, key_matrix: list) -> str:
    det = key_matrix[0][0]*key_matrix[1][1] - key_matrix[0][1]*key_matrix[1][0]
    det %= 26
    inv_det = mod_inv(det, 26)
    if inv_det is None:
        print("Error: Key matrix is not invertible modulo 26!")
        return ""
    inv_matrix = [
        [(key_matrix[1][1] * inv_det) % 26, (-key_matrix[0][1] * inv_det) % 26],
        [(-key_matrix[1][0] * inv_det) % 26, (key_matrix[0][0] * inv_det) % 26]
    ]
    text = "".join(c for c in ciphertext.upper() if c.isalpha())
    result = ""
    for i in range(0, len(text), 2):
        pair = text[i:i+2]
        vector = [ord(pair[0]) - 65, ord(pair[1]) - 65]
        num1 = (inv_matrix[0][0]*vector[0] + inv_matrix[0][1]*vector[1]) % 26
        num2 = (inv_matrix[1][0]*vector[0] + inv_matrix[1][1]*vector[1]) % 26
        result += chr(num1 + 65) + chr(num2 + 65)
    return result

# ############################### mENU
def main():
    while True:
        print("\n=== Assignment Cryptography Menu ===")
        print("1: Rail-Fence Transposition Cipher") # givenn key row write diagonal read stret 12 key 12 row 
        print("2: Route (Spiral) Transposition Cipher") # givenn row write top down read top right wede colck wise 
        print("3: Columnar Transposition Cipher") # givven key word ASSING NUMBER ASSENDING ORDER on the top of becolom lik new 
        print("4: Double Transposition Cipher") # Columnar Transposition double
        print("5: Myszkowski Transposition Cipher") # Same as Double but use double key word
        print("6: Disruptive Transposition Cipher") # GIVEN columen number eg 4 then write the text in 4 columen then me order by columen
        print("7: Additive (Shift) Cipher") # 
        print("8: Multiplicative Cipher")
        print("9: Affine Cipher")
        print("10: Playfair Cipher") 
        print("11: Hill Cipher (2x2 Key Matrix)")
        print("Type 'exit' to quit.")

        choice = input("Enter your choice (1-11 or 'exit'): ").strip().lower()
        if choice == 'exit':
            print("Goodbye!")
            break
        if choice not in {str(i) for i in range(1, 12)}:
            print("Invalid selection. Please try again.")
            continue

        mode = input("Enter 'E' for Encryption or 'D' for Decryption: ").strip().upper()
        if mode not in {'E', 'D'}:
            print("Invalid mode selected.")
            continue

        # ---------------- Transposition Cipher Options ----------------
        if choice == '1':  # Rail-Fence
            try:
                num_rails = int(input("Enter the number of rails (integer): "))
            except ValueError:
                print("Number of rails must be an integer.")
                continue
            text = input("Enter the text: ")
            result = rail_fence_encrypt(text, num_rails) if mode == 'E' else rail_fence_decrypt(text, num_rails)
            print("Result:", result)

        elif choice == '2':  # Route (Spiral)
            try:
                rows = int(input("Enter the number of rows (integer): "))
                cols = int(input("Enter the number of columns (integer): "))
            except ValueError:
                print("Rows and columns must be integers.")
                continue
            text = input("Enter the text: ")
            result = route_cipher_encrypt(text, rows, cols) if mode == 'E' else route_cipher_decrypt(text, rows, cols)
            print("Result:", result)

        elif choice == '3':  # Columnar Transposition
            key = input("Enter the key (a word or sequence): ")
            text = input("Enter the text: ")
            result = columnar_transposition_encrypt(text, key) if mode == 'E' else columnar_transposition_decrypt(text, key)
            print("Result:", result)

        elif choice == '4':  # Double Transposition
            key1 = input("Enter the first key: ")
            key2 = input("Enter the second key: ")
            text = input("Enter the text: ")
            result = double_transposition_encrypt(text, key1, key2) if mode == 'E' else double_transposition_decrypt(text, key1, key2)
            print("Result:", result)

        elif choice == '5':  # Myszkowski Transposition
            key = input("Enter the key (repeated characters allowed): ")
            text = input("Enter the text: ")
            result = myszkowski_encrypt(text, key) if mode == 'E' else myszkowski_decrypt(text, key)
            print("Result:", result)

        elif choice == '6':  # Disruptive Transposition
            key = input("Enter the key for disruptive cipher: ")
            text = input("Enter the text: ")
            result = disruptive_transposition_encrypt(text, key) if mode == 'E' else disruptive_transposition_decrypt(text, key)
            print("Result:", result)

        ########################################################################################


        elif choice == '7':  # Additive Cipher
            try:
                key = int(input("Enter the additive key (integer): "))
            except ValueError:
                print("Key must be an integer.")
                continue
            text = input("Enter the text: ")
            result = additive_encrypt(text, key) if mode == 'E' else additive_decrypt(text, key)
            print("Result:", result)

        elif choice == '8':  # Multiplicative Cipher
            try:
                key = int(input("Enter the multiplicative key (integer): "))
            except ValueError:
                print("Key must be an integer.")
                continue
            text = input("Enter the text: ")
            result = multiplicative_encrypt(text, key) if mode == 'E' else multiplicative_decrypt(text, key)
            print("Result:", result)

        elif choice == '9':  # Affine Cipher
            try:
                a = int(input("Enter key 'a' (must be coprime with 26): "))
                b = int(input("Enter key 'b' (integer): "))
            except ValueError:
                print("Keys must be integers.")
                continue
            text = input("Enter the text: ")
            result = affine_encrypt(text, a, b) if mode == 'E' else affine_decrypt(text, a, b)
            print("Result:", result)

        elif choice == '10':  # Playfair Cipher
            key_word = input("Enter the Playfair key (keyword): ")
            text = input("Enter the text: ")
            result = playfair_encrypt(text, key_word) if mode == 'E' else playfair_decrypt(text, key_word)
            print("Result:", result)

        elif choice == '11':  # Hill Cipher
            key_input = input("Enter 4 numbers for the 2x2 key matrix (separated by spaces): ")
            parts = key_input.split()
            if len(parts) != 4:
                print("You must enter exactly 4 numbers.")
                continue
            try:
                nums = [int(x) for x in parts]
            except ValueError:
                print("All key values must be integers.")
                continue
            key_matrix = [[nums[0], nums[1]], [nums[2], nums[3]]]
            text = input("Enter the text: ")
            result = hill_encrypt(text, key_matrix) if mode == 'E' else hill_decrypt(text, key_matrix)
            print("Result:", result)

        # After an operation, ask to continue or exit.
        cont = input("\nPress Enter to return to the main menu or type 'exit' to quit: ").strip().lower()
        if cont == 'exit':
            print("Goodbye!")
            break

if __name__ == '__main__':
    main()