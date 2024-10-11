import hashlib
import secrets

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



def alice_generate_keys(p, g):
    """ Function for Alice to generate her private and public keys"""
    a = secrets.randbelow(p - 1)  # Alice's private key
    A = pow(g, a, p)  # Alice's public key (g^a mod p)
    return a, A



def bob_generate_keys(p, g):
    """ Function for Bob to generate his private and public keys"""
    b = secrets.randbelow(p - 1)  # Bob's private key
    B = pow(g, b, p)  # Bob's public key (g^b mod p)
    return b, B


def alice_compute_shared_secret(a, B, p):
    """ Function for Alice to compute the shared secret using Bob's public key"""
    shared_secret = pow(B, a, p)  # (B^a mod p)
    return shared_secret



def bob_compute_shared_secret(b, A, p):
    """ Function for Bob to compute the shared secret using Alice's public key"""
    shared_secret = pow(A, b, p)  # (A^b mod p)
    return shared_secret

def generate_vigenere_key(shared_secret, length=8):
    """ Function to generate Vigenère key from shared secret"""
    shared_secret_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, 'big')
    hashed_secret = hashlib.sha256(shared_secret_bytes).hexdigest()
    vigenere_key = ''.join(filter(str.isalpha, hashed_secret))[:length]  # Only alphabetic characters
    return vigenere_key.upper()


def generate_transposition_key(shared_secret):
    """ Function to generate transposition key from shared secret"""
    shared_secret_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, 'big')
    hashed_secret = hashlib.sha256(shared_secret_bytes).hexdigest()
    # Generate a permutation of [1, 2, 3, 4, 5] based on the hash
    numbers = [1, 2, 3, 4, 5]
    transposition_key = []
    index = 0
    for _ in range(5):
        idx = int(hashed_secret[index], 16) % len(numbers)
        transposition_key.append(str(numbers.pop(idx)))
        index += 1
    return ''.join(transposition_key)

