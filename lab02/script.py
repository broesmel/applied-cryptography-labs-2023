from Crypto.Hash import SHA256
from Crypto.Cipher import AES

message = ... # REDACTED
seed = ... # REDACTED
iv = bytes.fromhex("e764ea639dc187d058554645ed1714d8")

def generate_aes_key(integer: int, key_length: int):
    seed = integer.to_bytes(2, byteorder='big')
    hash_object = SHA256.new(seed)
    aes_key = hash_object.digest()
    trunc_key = aes_key[:key_length]
    return trunc_key

def aes_cbc_encryption(plaintext: bytes, key: bytes, iv: bytes):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext

key = generate_aes_key(seed, 16)

# Be careful when running this script: it will override your existing flag.enc
with open("flag.enc", "w") as f:
    f.write(aes_cbc_encryption(message, key, iv).hex())
