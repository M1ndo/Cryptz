#!/usr/bin/env python3
# Created By r2dr0dn
# Updated At 02/12/2019
# Don't Copy The Code Without Giving Me The Credits Nerds !!!
try:
    import pybase64
    import sqlite3
    import re
    import os
    import sys
    import string
    import random
    import datetime
    from time import sleep as sl
    from Crypto.PublicKey import RSA
    from Crypto import Random
    from Crypto.Cipher import PKCS1_OAEP
    from Cryptodome.Cipher import AES
    from Crypto.Cipher import AES as AES2
    from cryptography.fernet import Fernet
    import binascii
    import base64
except ImportError:
    print(Red + "You Don't Have Some Required Packages Please Install them manually or use requirments.txt to install them for you!")
    exit(1)


def clear():
    os.system('clear || cls')


clear()
## Set Date ####
now = datetime.datetime.now()
hour = now.hour
min = now.minute
sec = now.second
timenow = "{}:{}:{}".format(hour, min, sec)
#######Colors###########
Green = "\033[1;33m"
Blue = "\033[1;34m"
Grey = "\033[1;30m"
Reset = "\033[0m"
yellow = "\033[1;36m"
Red = "\033[1;31m"
purple = "\033[35m"
Light = "\033[95m"
cyan = "\033[96m"
stong = "\033[39m"
unknown = "\033[38;5;82m"
unknown2 = "\033[38;5;198m"
unknown3 = "\033[38;5;208m"
unknown4 = "\033[38;5;167m"
unknown5 = "\033[38;5;91m"
unknown6 = "\033[38;5;210m"
unknown7 = "\033[38;5;165m"
unknown8 = "\033[38;5;49m"
unknown9 = "\033[38;5;160m"
unknown10 = "\033[38;5;51m"
unknown11 = "\033[38;5;13m"
unknown12 = "\033[38;5;162m"
unknown13 = "\033[38;5;203m"
unknown14 = "\033[38;5;113m"
unknown15 = "\033[38;5;14m"
##########################
# Used Strings #
strings = "1h3sgj5ks3erhg3h5dh23455wer32cfewjkfwerweh"
# banner


def banner():
    print(unknown2 + "\n  https://github.com/r2dr0dn\n")
    print(unknown15 + "   ####   #####   #   #  #####   #####  ###### ")
    print(unknown15 + "  #    #  #    #   # #   #    #    #        # ")
    print(unknown15 + "  #       #    #    #    #    #    #       # ")
    print(unknown15 + "  #       #####     #    #####     #      # ")
    print(unknown15 + "  #    #  #   #     #    #         #     # ")
    print(unknown15 +
          "   ####   #    #    #    #         #    ######  \033[31m" + "v3.0" + "\033[0m \n")
    print(unknown15 + "  made by: " + Red + "r2dr0dn\n" + Reset)
# base64 Functions:


def reverse_char(s):
    return s[::-1]


def unreversed_char(s):
    return s[::-1]


def add_string(s):
    return s[:5] + strings + s[5:]


def rem_string(text, char):
    resul = ""
    for c in text:
        if c != char:
            resul += c
    return text.replace(char, "")
# base64 encryption


def encrypted_base():
    clear()
    banner()
    data = input(unknown10 + "Enter Your Plain Text Message: ")
    # print("\n")
    data = data + strings
    data = add_string(data)
    data = reverse_char(data)
    data = str.encode(data)
    encode1 = pybase64._pybase64.b64encode(data)
    encode1 = bytes.decode(encode1)
    print("\n" + Red + encode1 + Reset + "\n")
    # print("\n")
# Base64 Decryption


def decrypted_base():
    clear()
    banner()
    data = input(unknown10 + "Enter Your Encrypted Form: ")
    # print("\n")
    data = str.encode(data)
    dec = pybase64._pybase64.b64decode(data)
    dec = bytes.decode(dec)
    dec = rem_string(dec, strings)
    dec = unreversed_char(dec)
    dec = rem_string(dec, strings)
    print("\n" + Red + dec + Reset + "\n")
    # print("\n")
# UU encryption


def uu_encrypt():
    clear()
    banner()
    data = input(Red + "Enter Your Plain Text Message: ")
    data = data.encode('utf-8')
    enc = binascii.b2a_uu(data)
    enc = enc.strip()
    enc = enc.decode('utf-8')
    print("\n" + Red + enc + Reset + "\n")
# UU Decryption


def uu_decrypt():
    clear()
    banner()
    data = input(Red + "Enter Your Encrypted Form: ")
    # data = data.encode('utf-8')
    dec = binascii.a2b_uu(data)
    dec = dec.decode('utf-8')
    print("\n" + Red + dec + Reset + "\n")
# Hex Encryption


def hex_encrypt():
    clear()
    banner()
    data = input(Red + "Enter Your Plain Text Message: ")
    data = data.encode('utf-8')
    enc = binascii.hexlify(data)
    enc = enc.decode('utf-8')
    print("\n" + Red + enc + Reset + "\n")
# Hex Decryption


def hex_decrypt():
    clear()
    banner()
    data = input(Red + "Enter Your Encrypted Form: ")
    data = data.encode('utf-8')
    dec = binascii.unhexlify(data)
    dec = dec.decode('utf-8')
    print("\n" + Red + dec + Reset + "\n")
# BinHex4 encryption


def hqx_encryption():
    clear()
    banner()
    data = input(Green + "Enter Your Plain Text Message: ")
    data = data.encode('utf-8')
    enc = binascii.b2a_hqx(data)
    enc = enc.decode('utf-8')
    print("\n" + cyan + enc + Reset + "\n")
# BinHex4 Decryption


# def hqx_decryption():
#     clear()
#     banner()
#     data = input(Red + "Enter Your Encrypted Form: ")
#     data = str.encode(data)
#     # data = '-6)c0M8h1$PaGf9PFR)'
#     dec = binascii.a2b_hqx(data)
#     dec = dec.decode('utf-8')
#     print("\n" + purple + dec + Reset + "\n")
# Symmetric Encryption
def symmet_encryption():
    clear()
    banner()
    data = input(unknown9 + "Enter Your Plain Text Message: ")
    data = data.encode()
    key = Fernet.generate_key()
    e = Fernet(key)
    encry = e.encrypt(data)
    encry = encry.decode()
    key = key.decode()
    print(Red + "Your Decryption password: [%s]" %key)
    print( "\n" + Green + "Encryption Value [%s]" %encry + "\n")
# Symmetric decryption
def symmet_decryption():
    clear()
    banner()
    password = input(Red + "Enter Decryption Password: ")
    password = password.encode()
    encr = input(Green + "Enter Encryption Value: ")
    encr = encr.encode()
    D = Fernet(password)
    decr = D.decrypt(encr)
    decr = decr.decode()
    print("\n" + Red + "Decrypted Value: [%s]" %decr + "\n")
# Base64 Standart encryption
def base64_encryption():
    clear()
    banner()
    data = input(unknown2 + "Enter Your Plain Text Message: ")
    data = data.encode('utf-8')
    enc = pybase64._pybase64.b64encode(data)
    enc = enc.decode('utf-8')
    print("\n" + yellow + enc + Reset + "\n")
# base64 Standart decryption


def base64_decryption():
    clear()
    banner()
    data = input(unknown10 + "Enter Your Encrypted Form: ")
    data = data.encode('utf-8')
    dec = pybase64._pybase64.b64decode(data)
    dec = dec.decode('utf-8')
    print("\n" + unknown8 + dec + Reset + "\n")
# keypass generator


def ran_generator():
    chars = string.ascii_uppercase + string.ascii_lowercase + string.digits
    size = 4
    keypass = ''.join(random.choice(chars) for x in range(size, 20))
    return keypass
# AES Manually Encryption


def aes_encrypt_m():
    clear()
    banner()
    keypass = ran_generator()
    keypass2 = keypass
    data = input(unknown2 + "Enter Your Plain Text Message: ")
    data = data.encode('utf-8')
    keypass = keypass.encode('utf-8')
    cipher = AES.new(keypass, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    print(Green + "\n" + "Encryption Password: {}".format(keypass2))
    print(Blue + '\n' + "Your Encryption: Ciphertext: {}\nTag: {}\nNonce: {}\nPlease Save Them All Somewhere Safe".format(
        ciphertext, tag, cipher.nonce) + Reset + '\n')
# AES Manually Decryption
# def aes_decrypt_m():
#     try:
#         keypass = input(unknown9 + "Enter Your Decryption Password: ")
#         keypass = keypass.encode('utf-8')
#         tag = input('Enter Tag: ')
#         # tag = tag.encode('utf-8')
#         tag = str.encode(tag)
#         ciphertext = input("Enter CipherText: ")
#         # ciphertext = ciphertext.encode('utf-8')
#         ciphertext = str.encode(ciphertext)
#         nonce = input("Enter Nonce: ")
#         # nonce = nonce.encode('utf-8')
#         nonce = str.encode(nonce)
#         cipher = AES.new(keypass, AES.MODE_EAX, nonce)
#         data = cipher.decrypt_and_verify(ciphertext, tag)
#         data = data.decode('utf-8')
#         print("\n" + unknown8 + data + Reset + "\n")
#     except ValueError:
#         print("Unmatched Value!!!")
#         exit(1)
# RSA manual Encryption


def rsa_enc():
    clear()
    banner()
    data = input(unknown6 + "Enter Your Plain Text Message: ")
    BLOCK_SIZE = 16
    PADDING = '{'
    pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
    EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
    secret = ran_generator()
    passphrase = secret
    secret = str.encode(secret)
    cipher = AES2.new(secret)
    encoded = EncodeAES(cipher, data)
    encoded = bytes.decode(encoded)
    print(unknown15 + "\n" + 'encryption key:' + passphrase + "\n")
    print(Grey + 'Encrypted Data: ', encoded + "\n")
# AES Auth encryption


def aes_encrypt_a():
    clear()
    banner()
    data = input(unknown2 + "Enter Your Plain Text Message: ")
    data = data.encode('utf-8')
    filename = input(
        unknown3 + "Enter FileName To Encrypted Data Be Saved In: ")
    keypass = ran_generator()
    keypass2 = keypass
    keypass = keypass.encode('utf-8')
    cipher = AES.new(keypass, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    file_out = open(filename + ".enc", "wb")
    [file_out.write(x) for x in (cipher.nonce, tag, ciphertext)]
    saved_pass = open(filename + ".txt", "w")
    saved_pass.write(keypass2 + '\n')
    saved_pass.close()
    print(unknown + "\nUse " + Red + f"[{keypass2}] " + Grey +
          "To Decrypt Your Data")
    print(Green + "Data Has Been Saved In" + Red + "[%s.enc] \n" % (filename))
# AES Auth Decryption:


def aes_decrypt_a():
    clear()
    banner()
    filename = input(
        Red + "Enter Encrypted Data File (make sure it on the same path): ")
    file_in = open(filename, "rb")
    keypass = input(unknown13 + "Enter Decryption Password: ")
    keypass = keypass.encode('utf-8')
    nonce, tag, ciphertext = [file_in.read(x) for x in (16, 16, -1)]
    cipher = AES.new(keypass, AES.MODE_EAX, nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    data = data.decode('utf-8')
    print(unknown12 + "\n" + "Decrypted: " + data + Reset + "\n")
# Main Function


def main():
    try:
        for i in range(1):
            banner()
            password = input(unknown7 + "  Enter License Key: ")
            with sqlite3.connect('store.db') as db:
                connect1 = db.cursor()
            catch_pass = ("SELECT * FROM passman WHERE licensekey = ?")
            connect1.execute(catch_pass, [(password)])
            result = connect1.fetchall()
            if result:
                for i in result:
                    print(unknown + "\n  Access Granted!!!")
                    sl(3)
                    print("  Started At {}".format(now))
                    sl(0.10)
                    print("  Loading Resources...[0%]")
                    sl(0.10)
                    print("  Loading Resources...[10%]")
                    sl(0.10)
                    print("  Loading Resources...[20%]")
                    sl(0.10)
                    print("  Loading Resources...[30%]")
                    sl(0.10)
                    print("  Loading Resources...[40%]")
                    sl(0.10)
                    print("  Loading Resources...[50%]")
                    sl(0.10)
                    print("  Loading Resources...[60%]")
                    sl(0.10)
                    print("  Loading Resources...[70%]")
                    sl(0.10)
                    print("  Loading Resources...[80%]")
                    sl(0.10)
                    print("  Loading Resources...[90%]")
                    sl(0.10)
                    print("  Loading Resources...[1000000000000%]")
                    sl(1)
                    print("  CRYPTZ is starting!!")
                    print(unknown3+"""
                    Welcome To CRYPTZ The Unbreakable Tool
                    """)
                    sl(3)
                    clear()
                    banner()

                    def menu():
                        print(unknown7 + '  1.  Base64 Hard Encryption: ')
                        print(unknown3 + '  2.  Base64 Hard Decryption: ')
                        print(unknown2 + '  3.  Hex Encryption: ')
                        print(unknown2 + '  4.  Hex Decryption: ')
                        print(unknown2 + '  5.  Binhex4 Encryption: ')
                        print(unknown2 + '  6.  Symmetric Encryption: ')
                        print(unknown2 + '  7.  Symmetric Decryption: ')
                        print(unknown2 + '  8.  UU Encryption: ')
                        print(unknown2 + '  9.  UU Decryption: ')
                        print(unknown2 + '  10.  Base64 Normal Encryption: ')
                        print(unknown2 + '  11. Base64 Normal Decryption: ')
                        print(unknown3 + "  12. AES Manual Encryption: ")
                        print(unknown3 + "  13. RSA Manual Decryption: ")
                        print(unknown3 + "  14. AES Auth Decryption: ")
                        print(unknown3 + "  15. AES Auth Decryption: ")
                        print(unknown2 + '  16. Exit')
                        choice = input(unknown15 + "  CRYPTZ -> " + Reset)
                        if choice in ["1"]:
                            encrypted_base()
                            menu()
                        elif choice in ["2"]:
                            decrypted_base()
                            menu()
                        elif choice in ["3"]:
                            hex_encrypt()
                            menu()
                        elif choice in ["4"]:
                            hex_decrypt()
                            menu()
                        elif choice in ["5"]:
                            hqx_encryption()
                            menu()
                        elif choice in ["6"]:
                            symmet_encryption()
                            menu()
                        elif choice in ["7"]:
                            symmet_decryption()
                            menu()
                        elif choice in ['8']:
                            uu_encrypt()
                            menu()
                        elif choice in ['9']:
                            uu_decrypt()
                            menu()
                        elif choice in ['10']:
                            base64_encryption()
                            menu()
                        elif choice in ['11']:
                            base64_decryption()
                            menu()
                        elif choice in ['12']:
                            aes_encrypt_m()
                            menu()
                        elif choice in ['13']:
                            rsa_enc()
                            menu()
                        elif choice in ['14']:
                            aes_encrypt_a()
                            menu()
                        elif choice in ['15']:
                            aes_decrypt_a()
                            menu()
                        elif choice in ["16"]:
                            print(Red + """\n  Quiting... """ + Reset)
                            exit(1)
                        else:
                            print(Red + """  Unknown Option Quiting... \n""" + Reset)
                            exit(1)
                    menu()
            else:
                print(
                    "  Unauthorized Access !!\n  To get a License Key you will need to contact creators for one")
                exit(1)
    except KeyboardInterrupt:
        print(unknown15 + "\nCtrl + c Detected!!")
        print(Red + "Quiting ..\n" + stong + "Have A Nice Day :)")
        exit(1)


if __name__ == '__main__':
    main()
