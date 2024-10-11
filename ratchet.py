import hashlib
from hmac_ import hmac_sha256
from diffie_hellman import (
    alice_generate_keys,
    bob_generate_keys,
    bob_compute_shared_secret,
    alice_compute_shared_secret,
    generate_vigenere_key,
    generate_transposition_key
)
from ciphers import encrypt_cbc, decrypt_cbc

BLOCK_SIZE = 64

# 1536-bit MODP Group Prime (from RFC 3526)
p = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
             "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
             "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
             "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
             "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
             "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
             "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
             "670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF", 16)
g = 2  # Generator for this group


def ratchet_chain_key(chain_key):
    """
    Updates the Chain Key using HMAC with the label 'ratchet'.
    """
    new_chain_key = hmac_sha256(chain_key, b'ratchet')
    # Ensure the new Chain Key is BLOCK_SIZE bytes
    if len(new_chain_key) > BLOCK_SIZE:
        new_chain_key = xor_hash(new_chain_key)
    elif len(new_chain_key) < BLOCK_SIZE:
        new_chain_key = new_chain_key.ljust(BLOCK_SIZE, b'\x00')
    return new_chain_key


def derive_message_key(chain_key):
    """
    Derives the Message Key from the Chain Key using HMAC with the label 'message'.
    """
    message_key = hmac_sha256(chain_key, b'message')
    return message_key


def generate_hmac(key, message):
    """
    Generates the HMAC for the message using the specified key.
    """
    return hmac_sha256(key, message)


def verify_hmac(key, message, hmac_received):
    """
    Verifies if the received HMAC matches the one computed on the message.
    """
    computed_hmac = generate_hmac(key, message)
    return computed_hmac == hmac_received


def xor_hash(data):
    """
    XOR-based hash function that produces an output of BLOCK_SIZE bytes.
    Splits the input into segments and applies XOR to each segment.
    """
    result = bytearray(BLOCK_SIZE)
    for i in range(len(data)):
        result[i % BLOCK_SIZE] ^= data[i]
    return bytes(result)


class Participant:
    def __init__(self, name):
        self.name = name
        self.root_key = None
        self.chain_key = None
        self.message_number = 0
        self.transposition = None
        self.vigenere = None

    def send_message(self, message_str):
        """
        Sends a message: ratchets the Chain Key, derives a Message Key,
        generates the HMAC, concatenates the message with the HMAC, encrypts the message,
        and returns the ciphertext and HMAC.
        """
        self.chain_key = ratchet_chain_key(self.chain_key)
        message_key = derive_message_key(self.chain_key)
        message_key_int = int.from_bytes(message_key, byteorder='big')
        self.transposition = generate_transposition_key(message_key_int)
        self.vigenere = generate_vigenere_key(message_key_int)
        message = message_str.encode('utf-8')

        # Generate the HMAC on the plaintext
        hmac_tag = generate_hmac(message_key, message).hex()

        # Concatenate the ciphertext and HMAC as a string
        concatenated_message = f"{message.hex()}||{hmac_tag}"
        # Encrypt the message
        ciphertext = encrypt_cbc(concatenated_message, self.transposition, self.vigenere)
        self.message_number += 1
        return ciphertext

    def receive_message(self, ciphertext):
        """
        Receives a message: derives message key, decrypts the message,
        separates the message and HMAC,
        verifies the HMAC and updates the Chain Key.
        """
        self.chain_key = ratchet_chain_key(self.chain_key)
        message_key = derive_message_key(self.chain_key)
        message_key_int = int.from_bytes(message_key, byteorder='big')
        self.transposition = generate_transposition_key(message_key_int)
        self.vigenere = generate_vigenere_key(message_key_int)

        # Decrypt the message
        decrypted_text = decrypt_cbc(ciphertext, self.transposition, self.vigenere)
        try:  # Split using the last delimiter in the message (if more than one delimiter is present)
            decrypted_message_hex, hmac_hex = decrypted_text.rsplit("||", 1)
        except ValueError:
            print(f"{self.name}: Error in message format. '||' delimiter is missing.")
            return False, None

        try:
            message = bytes.fromhex(decrypted_message_hex)
        except ValueError:
            print(f"{self.name}: Error in converting message from hexadecimal.")
            return False, None

        try:
            received_hmac = bytes.fromhex(hmac_hex)
        except ValueError:
            print(f"{self.name}: Error in converting HMAC from hexadecimal.")
            return False, None

        # Verify the HMAC on the plaintext
        is_valid = verify_hmac(message_key, message, received_hmac)

        if is_valid:
            try:
                plaintext = message.decode('utf-8')
            except UnicodeDecodeError:
                print(f"{self.name}: Error in decoding the message.")
                return False, None
            self.message_number += 1
            return True, plaintext
        else:
            self.message_number += 1
            print(f"{self.name}: HMAC verification failed. The message might have been tampered with or is not authentic.")
            return False, None


def simulate_conversation_single_ratchet():
    """Simulates a conversation between Alice and Bob using a single ratchet."""
    alice = Participant("Alice")
    bob = Participant("Bob")
    print("Performing Diffie-Hellman Key Exchange...\n")
    alice_private, alice_public = alice_generate_keys(p, g)
    bob_private, bob_public = bob_generate_keys(p, g)

    # Compute shared secret and keys for encryption
    alice_shared_secret = alice_compute_shared_secret(alice_private, bob_public, p)
    bob_shared_secret = bob_compute_shared_secret(bob_private, alice_public, p)
    alice.vigenere = generate_vigenere_key(alice_shared_secret)
    alice.transposition = generate_transposition_key(alice_shared_secret)
    bob.vigenere = generate_vigenere_key(bob_shared_secret)
    bob.transposition = generate_transposition_key(bob_shared_secret)

    assert alice_shared_secret == bob_shared_secret, "Error in Diffie-Hellman exchange."

    # Initialize shared Chain Key
    print("Deriving HMAC key from shared secret...")
    shared_secret_bytes = alice_shared_secret.to_bytes((alice_shared_secret.bit_length() + 7) // 8, byteorder='big')
    hmac_key = hashlib.sha256(shared_secret_bytes).digest()
    print(f"Derived HMAC key: {hmac_key.hex()}\n")
    alice.chain_key = hmac_key
    bob.chain_key = hmac_key

    print("Chain Key initialization for Alice and Bob completed.")
    print(f"Alice's Chain Key: {alice.chain_key.hex()}")
    print(f"Bob's Chain Key:   {bob.chain_key.hex()}\n")

    # Simulate message exchange
    messages = [
        ("Alice", "Hi Bob, how are you?"),
        ("Bob", "Hi Alice, I'm fine, thanks! And you?"),
        ("Alice", "I'm doing well too. Would you like to eat pizza tonight?"),
        ("Bob", "Yes, sure. At what time we meet?"),
        ("Alice", "Let's meet at 8 PM downtown.")
    ]

    for sender_name, message in messages:
        sender = alice if sender_name == "Alice" else bob
        receiver = bob if sender_name == "Alice" else alice

        print(f"\n{sender.name} sends: {message}")
        concatenated_message = sender.send_message(message)
        print(f"Concatenated Message:\n {concatenated_message}\n")

        print(f"{receiver.name} receives:\n {concatenated_message}")
        is_valid, decrypted_message = receiver.receive_message(concatenated_message)
        print(f"Valid HMAC: {is_valid}")
        if is_valid:
            print(f"Decrypted message: {decrypted_message}\n")
        else:
            print(
                f"{receiver.name}: HMAC verification failed. The message might have been tampered with or is not authentic.\n")

        print(f"{sender.name}'s Chain Key after sending: {sender.chain_key.hex()}")
        print(f"{receiver.name}'s Chain Key after receiving: {receiver.chain_key.hex()}\n")




def simulate_conversation_double_ratchet():
    """Simulates a conversation between Alice and Bob using double ratchet."""
    alice = Participant("Alice")
    bob = Participant("Bob")
    print("Performing Diffie-Hellman Key Exchange...\n")
    alice_private, alice_public = alice_generate_keys(p, g)
    bob_private, bob_public = bob_generate_keys(p, g)

    # Compute shared secret and keys for encryption
    alice_shared_secret = alice_compute_shared_secret(alice_private, bob_public, p)
    bob_shared_secret = bob_compute_shared_secret(bob_private, alice_public, p)
    print(f"Shared secret:\n{alice_shared_secret}")
    alice.vigenere = generate_vigenere_key(alice_shared_secret)
    alice.transposition = generate_transposition_key(alice_shared_secret)
    bob.vigenere = generate_vigenere_key(bob_shared_secret)
    bob.transposition = generate_transposition_key(bob_shared_secret)

    assert alice_shared_secret == bob_shared_secret, "Error in Diffie-Hellman exchange."

    # Initialize shared Chain Key
    print("Deriving HMAC key from shared secret...")
    shared_secret_bytes = alice_shared_secret.to_bytes((alice_shared_secret.bit_length() + 7) // 8, byteorder='big')
    hmac_key = hashlib.sha256(shared_secret_bytes).digest()
    print(f"Derived HMAC key: {hmac_key.hex()}\n")
    alice.chain_key = hmac_key
    bob.chain_key = hmac_key
    alice.root_key = hmac_key
    bob.root_key = hmac_key

    print("Chain Key initialization for Alice and Bob completed.")
    print(f"Alice's Chain Key: {alice.chain_key.hex()}")
    print(f"Bob's Chain Key:   {bob.chain_key.hex()}\n")

    # Simulate message exchange
    messages = [
        ("Alice", "Hi Bob, how are you?"),
        ("Bob", "Hi Alice, I'm fine, thanks! And you?"),
        ("Alice", "I'm doing well too. Would you like to eat pizza tonight?"),
        ("Bob", "Yes, sure. At what time we meet?"),
        ("Alice", "Let's meet at 8 PM downtown.")
    ]

    RATCHET_INTERVAL = 3  # Number of messages before doing a new DH

    for idx, (sender_name, message) in enumerate(messages, 1):
        sender = alice if sender_name == "Alice" else bob
        receiver = bob if sender_name == "Alice" else alice

        print(f"\n{sender.name} sends: {message}")
        concatenated_message = sender.send_message(message)
        print(f"Concatenated Message:\n {concatenated_message}\n")

        print(f"{receiver.name} receives:\n {concatenated_message}")
        is_valid, decrypted_message = receiver.receive_message(concatenated_message)
        print(f"Valid HMAC: {is_valid}")
        if is_valid:
            print(f"Decrypted message: {decrypted_message}\n")
        else:
            print(f"{receiver.name}: HMAC verification failed. The message might have been tampered with or is not authentic.\n")

        print(f"{sender.name}'s Chain Key after sending: {sender.chain_key.hex()}")
        print(f"{receiver.name}'s Chain Key after receiving: {receiver.chain_key.hex()}\n")

        if idx % RATCHET_INTERVAL == 0:
            print(f"\nReached the {RATCHET_INTERVAL}-message interval, performing DH Ratchet...\n")

            alice_private, alice_public = alice_generate_keys(p, g)
            bob_private, bob_public = bob_generate_keys(p, g)

            # Compute new shared secret and keys for encryption
            alice_shared_secret = alice_compute_shared_secret(alice_private, bob_public, p)
            bob_shared_secret = bob_compute_shared_secret(bob_private, alice_public, p)
            alice.vigenere = generate_vigenere_key(alice_shared_secret)
            alice.transposition = generate_transposition_key(alice_shared_secret)
            bob.vigenere = generate_vigenere_key(bob_shared_secret)
            bob.transposition = generate_transposition_key(bob_shared_secret)

            assert alice_shared_secret == bob_shared_secret, "Error in Diffie-Hellman exchange during Ratchet."

            # Update root key and chain key for both participants
            new_shared_secret_bytes = alice_shared_secret.to_bytes((alice_shared_secret.bit_length() + 7) // 8, byteorder='big')
            new_root_key = hmac_sha256(alice.root_key, new_shared_secret_bytes)

            if len(new_root_key) > BLOCK_SIZE:
                new_root_key = xor_hash(new_root_key)
            elif len(new_root_key) < BLOCK_SIZE:
                new_root_key = new_root_key.ljust(BLOCK_SIZE, b'\x00')

            alice.root_key = new_root_key
            bob.root_key = new_root_key
            alice.chain_key = new_root_key
            bob.chain_key = new_root_key

            print(f"New Root Key Alice: {alice.root_key.hex()}")
            print(f"New Chain Key Alice: {alice.chain_key.hex()}")
            print(f"New Root Key Bob:   {bob.root_key.hex()}")
            print(f"New Chain Key Bob:   {bob.chain_key.hex()}\n")


