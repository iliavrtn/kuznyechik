import random
from hashlib import sha256
import math

def modinv(a, m):
    """Modular multiplicative inverse using Extended Euclidean Algorithm"""
    m0, x0, x1 = m, 0, 1
    if m == 1:
        return 0
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    if x1 < 0:
        x1 += m0
    return x1

def generate_keys(p, g):
    """Generate public and private keys"""
    x = random.randint(1, p-2)  # Private key
    y = pow(g, x, p)            # Public key
    return (p, g, y), x

def sign_message(private_key, p, g, message):
    """Sign a message using the private key"""
    x = private_key
    while True:
        k = random.randint(1, p-2)
        if math.gcd(k, p-1) == 1:
            break
    
    r = pow(g, k, p)
    h = int(sha256(message.encode()).hexdigest(), 16)
    s = ((h - x * r) * modinv(k, p-1)) % (p-1)
    
    return (r, s)

def verify_signature(public_key, message, signature):
    """Verify a signature using the public key"""
    p, g, y = public_key
    r, s = signature
    if not (1 < r < p and 0 < s < p-1):
        return False
    
    h = int(sha256(message.encode()).hexdigest(), 16)
    v1 = (pow(y, r, p) * pow(r, s, p)) % p
    v2 = pow(g, h, p)
    
    return v1 == v2