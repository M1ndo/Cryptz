#!/usr/bin/python3
from Cryptodome.Cipher import AES
key= b'rOiCbWKyYqFjYf7W'
tag = b"\x88\xdd\x11\xa4My\x1bS\x96P\t+O\xfau\xbc"
ciphertext = b"\xd3l\xd7X6\xb1G\x7f(\xb4;"
nonce = b"6\xe9p\x1a}P/\x1c\x12c\x83w\x85A\x15|"
cipher = AES.new(key, AES.MODE_EAX, nonce)
data = cipher.decrypt_and_verify(ciphertext, tag)
print(data)
