from hashlib import sha256
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import math
import os
import argparse
from datetime import datetime
from secretsharing import SecretSharer, HexToHexSecretSharer
from database import database_operations
import random

# Encoding method, AES CBC, takes plaintext and encodes it with a password
def encodeWithPadding(plaintext, password):
        salt = get_random_bytes(16)
        iv = get_random_bytes(16)
        key = PBKDF2(password, salt, 16, count=1000000, hmac_hash_module=SHA256)
        encrypt_cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = encrypt_cipher.encrypt(pad(plaintext, 16))
        return ciphertext + salt + iv

    # Decoding method, takes the encrypted data and decrypts it using a password
def decodeWithPadding(data, password):
        salt = data[-32:-16]
        key = PBKDF2(password, salt, 16, count=1000000, hmac_hash_module=SHA256)
        iv = data[-16:]
        decrypt_cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = data[:-32]
        message = decrypt_cipher.decrypt(ciphertext)
        print(message)
        try:
            return unpad(message, 16)
        except:
            ValueError("Padding is incorrect")
            return ("Oops, are you sure you introduced the correct password?")
        
# print(encodeWithPadding(b'hello world', b'hello world'))
# print(decodeWithPadding(b')\xd9o\x12\xda%f\xd5\x1e^\x04<M\xab\xdbW\xd1W\xf8\x8d\x06[\xa4\xa8\x1d\x95\xe5\xf3\xaa\x83C\xc9\x08\xab\x90TJ\xba\x9c\xb5\xd0\xa2\x1b]\xa39\xfdf', b'hello world'))
print(SecretSharer.split_secret('12288888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888657474674744747837483888888888888888888888888888888888888', 3, 5))
print(len('122888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888886574746747447478374838888888888888888888888888888888888888'))