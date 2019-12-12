from Crypto.Cipher import AES
import base64
import os
def decryption():
	encryptedString = raw_input("Enter The Encrypted String: ")
	# encryptedString = 'bKwlWuuDBjtBRVOnuStj4g=='
	PADDING = '{'
	DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)
	encryption = encryptedString
	key = raw_input("enter the key: ")
	# key = 'Q21PPTxf1PYsR1pg'
	cipher = AES.new(key)
	decoded = DecodeAES(cipher, encryption)
	print decoded
decryption()
