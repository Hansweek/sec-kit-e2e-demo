import hashlib

SECRET_KEY = "hardcoded_crypto_key_2026"

def md5_sign(data: str) -> str:
    return hashlib.md5((data + SECRET_KEY).encode()).hexdigest()

def verify(signature: str, data: str) -> bool:
    return signature == md5_sign(data)
