import hashlib

BLOCK_SIZE = 64

def xor_hash(data):
    """Function to perform XOR hash (simple XOR of all bytes)"""
    result = 0
    for byte in data:
        result ^= byte
    return bytes([result])

def hmac_xor(key, message):
    """HMAC implementation using XOR as the hash function"""
    if len(key) > BLOCK_SIZE:
        key = xor_hash(key)
    if len(key) < BLOCK_SIZE:
        key = key.ljust(BLOCK_SIZE, b'\x00')

    ipad = bytes([0x36] * BLOCK_SIZE)
    opad = bytes([0x5C] * BLOCK_SIZE)

    key_xor_ipad = bytes([k ^ i for k, i in zip(key, ipad)])
    key_xor_opad = bytes([k ^ o for k, o in zip(key, opad)])

    inner_hash = xor_hash(key_xor_ipad + message)
    hmac_result = xor_hash(key_xor_opad + inner_hash)

    return hmac_result

def demonstrate_collision():
    """Demonstrate collision vulnerability of XOR-based HMAC"""
    message1 = b"Hello, World!"
    message2 = b"Olleh, Dlrow!"
    key = b"secret_key"

    hmac1 = hmac_xor(key, message1)
    hmac2 = hmac_xor(key, message2)

    print("Demonstration 1: Collision vulnerability")
    print(f"HMAC for '{message1}': {hmac1.hex()}")
    print(f"HMAC for '{message2}': {hmac2.hex()}")
    print(f"HMACs are the same: {hmac1 == hmac2}\n")


def demonstrate_length_extension():
    """Demonstrate length extension attack on XOR-based HMAC"""
    key = b"secret_key"
    original_message = b"Legitimate message"
    extension = b"Malicious extension"

    original_hmac = hmac_xor(key, original_message)

    extended_message = original_message + extension
    extended_hmac = hmac_xor(key, extended_message)

    # Attacker's attempt to forge HMAC for extended message
    forged_hmac = xor_hash(original_hmac + extension)

    print("Demonstration 2: Length extension attack")
    print(f"Original HMAC: {original_hmac.hex()}")
    print(f"Extended HMAC: {extended_hmac.hex()}")
    print(f"Forged HMAC:   {forged_hmac.hex()}")
    print(f"Forged HMAC matches extended HMAC: {forged_hmac == extended_hmac}")

def hmac_sha256(key, message):
    """Create an HMAC-SHA256 for the provided message using the specified key."""
    block_size = 64

    if len(key) > block_size:
        key = hashlib.sha256(key).digest()
    if len(key) < block_size:
        key = key.ljust(block_size, b'\x00')

    ipad = bytes([0x36] * block_size)
    opad = bytes([0x5C] * block_size)

    key_xor_ipad = bytes([k ^ i for k, i in zip(key, ipad)])
    key_xor_opad = bytes([k ^ o for k, o in zip(key, opad)])

    inner_hash = hashlib.sha256(key_xor_ipad + message).digest()
    hmac_result = hashlib.sha256(key_xor_opad + inner_hash).digest()

    return hmac_result
