
def vigenere_cipher_ascii(text, key):
    key_extended = (key + text)[:len(text)]
    ciphertext = []

    for i in range(len(text)):
        char = text[i]
        shift = ord(key_extended[i])
        shifted_index = (ord(char) + shift) % 256
        ciphertext.append(chr(shifted_index))

    return ''.join(ciphertext)

def vigenere_decipher_ascii(ciphertext, key):
    key_extended = key  # Initialize the key with the original key
    plaintext = []

    for i in range(len(ciphertext)):
        char = ciphertext[i]
        shift = ord(key_extended[i])
        shifted_index = (ord(char) - shift) % 256
        decrypted_char = chr(shifted_index)
        plaintext.append(decrypted_char)
        key_extended += decrypted_char  # Add the decrypted character to the key

    return ''.join(plaintext)




def invert_key(key):
    inverted_key = [''] * len(key)
    for i, k in enumerate(key):   # create the inverted key for decryption
        inverted_key[int(k) - 1] = str(i + 1)
    return ''.join(inverted_key)


def transposition_cipher_ascii(text, key):

    matrix = []

    # Fills the matrix with the text in a row-wise manner, adding random characters at the end if necessary
    for i in range(0, len(text), len(key)):
        row = list(text[i:i + len(key)])
        if len(row) < len(key):
            row.extend('x' for _ in range(len(key) - len(row)))  # Fills the remaining characters with 'x'
                                                                # to better evaluate the avalanche effect

            # random characters is a better choice in real scenarios
            # row.extend(random.choice(string.ascii_lowercase) for _ in range(len(key) - len(row)))
        matrix.append(row)

    # Transpose the matrix based on the key
    transposed_matrix = [''] * len(key)
    for i in range(len(key)):
        for row in matrix:
            transposed_matrix[int(key[i]) - 1] += row[i]

    ciphertext = ''.join(transposed_matrix)

    return ciphertext


def transposition_decipher_ascii(ciphertext, key):
    num_rows = len(ciphertext) // len(key)
    key = invert_key(key)
    matrix = [''] * num_rows
    index = 0
    for i in range(len(key)):
        col_len = num_rows
        for j in range(col_len):
            matrix[j] += ciphertext[index]
            index += 1

    plaintext = [''] * len(ciphertext)
    for i, char in enumerate(key):
        col_index = int(char) - 1
        for j in range(num_rows):
            plaintext[col_index + j * len(key)] = matrix[j][i]

    return ''.join(plaintext).rstrip('x')  # Remove any padding



def xor_blocks(block1, block2):
    return ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(block1, block2))



def encrypt_cbc(message, transpose_key, vigenere_key):
    block_size = 2*len(transpose_key)
    padded_message = message.ljust((len(message) + block_size - 1) // block_size * block_size)
    blocks = [padded_message[i:i + block_size] for i in range(0, len(padded_message), block_size)]

    previous_block = '\x00' * block_size  # initial padding block for CBC
    encrypted_blocks = []

    for block in blocks:
        transposed_block = transposition_cipher_ascii(block, transpose_key)
        vigenere_block = vigenere_cipher_ascii(transposed_block, vigenere_key)
        encrypted_block = xor_blocks(vigenere_block, previous_block)
        encrypted_blocks.append(encrypted_block)
        previous_block = encrypted_block

    return ''.join(encrypted_blocks)


def decrypt_cbc(encrypted_message, transpose_key, vigenere_key):
    block_size = 2 * len(transpose_key)
    blocks = [encrypted_message[i:i + block_size] for i in range(0, len(encrypted_message), block_size)]

    previous_block = '\x00' * block_size  # initial padding block for CBC
    decrypted_blocks = []

    for block in blocks:
        vigenere_block = xor_blocks(block, previous_block)
        transposed_block = vigenere_decipher_ascii(vigenere_block, vigenere_key)
        decrypted_block = transposition_decipher_ascii(transposed_block, transpose_key)
        decrypted_blocks.append(decrypted_block)
        previous_block = block

    decrypted_message = ''.join(decrypted_blocks)
    return decrypted_message.rstrip()  # Remove any padding