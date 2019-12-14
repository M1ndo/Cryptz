#!/usr/bin/env python3
# Created By r2dr0dn
# Improvements by Haxys
# Updated 2019.12.04

import base64
import binascii
import datetime
import random
import string

try:
    from colorama import Fore, Style, init
    import pybase64
    from Crypto.PublicKey import RSA
    from Crypto import Random
    from Crypto.Cipher import PKCS1_OAEP, AES
    from cryptography.fernet import Fernet
except ImportError:
    print(
        "[!] Missing Python libraries.\n"
        " |_ Run: pip install -r requirements.txt"
    )
    exit(1)


init()
print(f"""{Fore.MAGENTA}
https://github.com/r2dr0dn
{Fore.CYAN}
 ####   #####   #   #  #####   #####  ######
#    #  #    #   # #   #    #    #        #
#       #    #    #    #    #    #       #
#       #####     #    #####     #      #
#    #  #   #     #    #         #     #
 ####   #    #    #    #         #    ######  {Fore.RED}v3.0{Style.RESET_ALL}
{Fore.CYAN}
made by: {Fore.RED}r2dr0dn{Style.RESET_ALL}
""")

# Used Strings #
strings = "1h3sgj5ks3erhg3h5dh23455wer32cfewjkfwerweh"


# base64 Functions:


def reverse_char(s):
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
    data = input(Fore.RED + "Enter Your Plain Text Message: ")
    # print("\n")
    data = data + strings
    data = add_string(data)
    data = reverse_char(data)
    data = str.encode(data)
    encode1 = pybase64._pybase64.b64encode(data)
    encode1 = bytes.decode(encode1)
    print("\n" + Fore.RED + encode1 + Style.RESET_ALL + "\n")
    # print("\n")


# Base64 Decryption


def decrypted_base():
    data = input(Fore.RED + "Enter Your Encrypted Form: ")
    # print("\n")
    data = str.encode(data)
    dec = pybase64._pybase64.b64decode(data)
    dec = bytes.decode(dec)
    dec = rem_string(dec, strings)
    dec = reverse_char(dec)
    dec = rem_string(dec, strings)
    print("\n" + Fore.RED + dec + Style.RESET_ALL + "\n")
    # print("\n")


# UU encryption


def uu_encrypt():
    data = input(Fore.RED + "Enter Your Plain Text Message: ")
    data = data.encode("utf-8")
    enc = binascii.b2a_uu(data)
    enc = enc.strip()
    enc = enc.decode("utf-8")
    print("\n" + Fore.RED + enc + Style.RESET_ALL + "\n")


# UU Decryption


def uu_decrypt():
    data = input(Fore.RED + "Enter Your Encrypted Form: ")
    # data = data.encode('utf-8')
    dec = binascii.a2b_uu(data)
    dec = dec.decode("utf-8")
    print("\n" + Fore.RED + dec + Style.RESET_ALL + "\n")


# Hex Encryption


def hex_encrypt():
    data = input(Fore.RED + "Enter Your Plain Text Message: ")
    data = data.encode("utf-8")
    enc = binascii.hexlify(data)
    enc = enc.decode("utf-8")
    print("\n" + Fore.RED + enc + Style.RESET_ALL + "\n")


# Hex Decryption


def hex_decrypt():
    data = input(Fore.RED + "Enter Your Encrypted Form: ")
    data = data.encode("utf-8")
    dec = binascii.unhexlify(data)
    dec = dec.decode("utf-8")
    print("\n" + Fore.RED + dec + Style.RESET_ALL + "\n")


# BinHex4 encryption


def hqx_encryption():
    data = input(Fore.GREEN + "Enter Your Plain Text Message: ")
    data = data.encode("utf-8")
    enc = binascii.b2a_hqx(data)
    enc = enc.decode("utf-8")
    print("\n" + Fore.CYAN + enc + Style.RESET_ALL + "\n")


# BinHex4 Decryption


# def hqx_decryption():
#     data = input(Fore.RED + "Enter Your Encrypted Form: ")
#     data = str.encode(data)
#     # data = '-6)c0M8h1$PaGf9PFR)'
#     dec = binascii.a2b_hqx(data)
#     dec = dec.decode('utf-8')
#     print("\n" + Fore.MAGENTA + Style.DIM + dec + Style.RESET_ALL + "\n")
# Symmetric Encryption
def symmet_encryption():
    data = input(Fore.RED + "Enter Your Plain Text Message: ")
    data = data.encode()
    key = Fernet.generate_key()
    e = Fernet(key)
    encry = e.encrypt(data)
    encry = encry.decode()
    key = key.decode()
    print(Fore.RED + "Your Decryption password: [%s]" % key)
    print("\n" + Fore.GREEN + "Encryption Value [%s]" % encry + "\n")


# Symmetric decryption
def symmet_decryption():
    password = input(Fore.RED + "Enter Decryption Password: ")
    password = password.encode()
    encr = input(Fore.GREEN + "Enter Encryption Value: ")
    encr = encr.encode()
    D = Fernet(password)
    decr = D.decrypt(encr)
    decr = decr.decode()
    print("\n" + Fore.RED + "Decrypted Value: [%s]" % decr + "\n")


# Base64 Standart encryption
def base64_encryption():
    data = input(Fore.MAGENTA + "Enter Your Plain Text Message: ")
    data = data.encode("utf-8")
    enc = pybase64._pybase64.b64encode(data)
    enc = enc.decode("utf-8")
    print("\n" + Fore.YELLOW + enc + Style.RESET_ALL + "\n")


# base64 Standart decryption


def base64_decryption():
    data = input(Fore.RED + "Enter Your Encrypted Form: ")
    data = data.encode("utf-8")
    dec = pybase64._pybase64.b64decode(data)
    dec = dec.decode("utf-8")
    print("\n" + Fore.RED + dec + Style.RESET_ALL + "\n")


# keypass generator


def ran_generator():
    chars = string.ascii_uppercase + string.ascii_lowercase + string.digits
    size = 4
    keypass = "".join(random.choice(chars) for x in range(size, 20))
    return keypass


# AES Manually Encryption


def aes_encrypt_m():
    keypass = ran_generator()
    keypass2 = keypass
    data = input(Fore.MAGENTA + "Enter Your Plain Text Message: ")
    data = data.encode("utf-8")
    keypass = keypass.encode("utf-8")
    cipher = AES.new(keypass, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    print(Fore.GREEN + "\n" + "Encryption Password: {}".format(keypass2))
    print(
        Fore.BLUE
        + "\n"
        + "Your Encryption: Ciphertext: {}\nTag: {}\nNonce: {}\nPlease Save Them All Somewhere Safe".format(
            ciphertext, tag, cipher.nonce
        )
        + Style.RESET_ALL
        + "\n"
    )


# AES Manually Decryption
# def aes_decrypt_m():
#     try:
#         keypass = input(Fore.RED + "Enter Your Decryption Password: ")
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
#         print("\n" + Fore.RED + data + Style.RESET_ALL + "\n")
#     except ValueError:
#         print("Unmatched Value!!!")
#         exit(1)
# RSA manual Encryption


def rsa_enc():
    data = input(Fore.RED + Style.BRIGHT + "Enter Your Plain Text Message: ")
    BLOCK_SIZE = 16
    PADDING = "{"
    pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
    EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
    secret = ran_generator()
    passphrase = secret
    secret = str.encode(secret)
    cipher = AES.new(secret)
    encoded = EncodeAES(cipher, data)
    encoded = bytes.decode(encoded)
    print(Fore.CYAN + "\n" + "encryption key:" + passphrase + "\n")
    print(
        Fore.WHITE + Style.DIM + "Encrypted Data: ",
        encoded + "\n" + Style.RESET_ALL,
    )


# AES Auth encryption


def aes_encrypt_a():
    data = input(Fore.MAGENTA + "Enter Your Plain Text Message: ")
    data = data.encode("utf-8")
    filename = input(
        Fore.YELLOW + "Enter FileName To Encrypted Data Be Saved In: "
    )
    keypass = ran_generator()
    keypass2 = keypass
    keypass = keypass.encode("utf-8")
    cipher = AES.new(keypass, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    file_out = open(filename + ".enc", "wb")
    [file_out.write(x) for x in (cipher.nonce, tag, ciphertext)]
    saved_pass = open(filename + ".txt", "w")
    saved_pass.write(keypass2 + "\n")
    saved_pass.close()
    print(
        Fore.WHITE
        + Style.DIM
        + "\nUse "
        + Style.NORMAL
        + Fore.RED
        + f"[{keypass2}] "
        + Fore.WHITE
        + Style.DIM
        + "To Decrypt Your Data"
        + Style.RESET_ALL
    )
    print(
        Fore.GREEN
        + "Data Has Been Saved In"
        + Fore.RED
        + "[%s.enc] \n" % (filename)
    )


# AES Auth Decryption:


def aes_decrypt_a():
    filename = input(
        Fore.RED
        + "Enter Encrypted Data File (make sure it on the same path): "
    )
    file_in = open(filename, "rb")
    keypass = input(Fore.RED + "Enter Decryption Password: ")
    keypass = keypass.encode("utf-8")
    nonce, tag, ciphertext = [file_in.read(x) for x in (16, 16, -1)]
    cipher = AES.new(keypass, AES.MODE_EAX, nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    data = data.decode("utf-8")
    print(Fore.MAGENTA + "\n" + "Decrypted: " + data + Style.RESET_ALL + "\n")


# Main Function


def main():
    try:
        def menu():
            print(Fore.MAGENTA + "  1.  Base64 Hard Encryption: ")
            print(Fore.YELLOW + "  2.  Base64 Hard Decryption: ")
            print(Fore.MAGENTA + "  3.  Hex Encryption: ")
            print(Fore.MAGENTA + "  4.  Hex Decryption: ")
            print(Fore.MAGENTA + "  5.  Binhex4 Encryption: ")
            print(Fore.MAGENTA + "  6.  Symmetric Encryption: ")
            print(Fore.MAGENTA + "  7.  Symmetric Decryption: ")
            print(Fore.MAGENTA + "  8.  UU Encryption: ")
            print(Fore.MAGENTA + "  9.  UU Decryption: ")
            print(Fore.MAGENTA + "  10.  Base64 Normal Encryption: ")
            print(Fore.MAGENTA + "  11. Base64 Normal Decryption: ")
            print(Fore.YELLOW + "  12. AES Manual Encryption: ")
            print(Fore.YELLOW + "  13. RSA Manual Decryption: ")
            print(Fore.YELLOW + "  14. AES Auth Decryption: ")
            print(Fore.YELLOW + "  15. AES Auth Decryption: ")
            print(Fore.MAGENTA + "  16. Exit")
            choice = input(Fore.CYAN + "  CRYPTZ -> " + Style.RESET_ALL)
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
            elif choice in ["8"]:
                uu_encrypt()
                menu()
            elif choice in ["9"]:
                uu_decrypt()
                menu()
            elif choice in ["10"]:
                base64_encryption()
                menu()
            elif choice in ["11"]:
                base64_decryption()
                menu()
            elif choice in ["12"]:
                aes_encrypt_m()
                menu()
            elif choice in ["13"]:
                rsa_enc()
                menu()
            elif choice in ["14"]:
                aes_encrypt_a()
                menu()
            elif choice in ["15"]:
                aes_decrypt_a()
                menu()
            elif choice in ["16"]:
                print(Fore.RED + """\n  Quiting... """ + Style.RESET_ALL)
                exit(1)
            else:
                print(
                    Fore.RED
                    + """  Unknown Option Quiting... \n"""
                    + Style.RESET_ALL
                )
                exit(1)

        menu()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}Program terminated. "
              f"{Fore.WHITE}{Style.BRIGHT}Have a nice day!"
              f"{Style.RESET_ALL}")
        exit(1)


if __name__ == "__main__":
    main()
