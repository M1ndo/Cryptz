#!/usr/bin/env python3
"""
Provides a number of encoders, decoders, encryptors and decryptors.

Created By r2dr0dn.
Improvements by Haxys.
Updated 2019.12.04.
"""

import base64
import binascii
import binhex
import datetime
import os
import string
from tempfile import NamedTemporaryFile

try:
    from colorama import Fore, Style, init
    from Crypto.Cipher import AES
    from Crypto.Random import random
    from cryptography.fernet import Fernet
except ImportError:
    print(
        "ERROR: Missing required libraries.\n"
        "Install dependencies with: pip install -r requirements.txt"
    )
    exit(1)


init()
print(
    f"""{Fore.MAGENTA}
https://github.com/r2dr0dn
{Fore.CYAN}
 ####   #####   #   #  #####   #####  ######
#    #  #    #   # #   #    #    #        #
#       #    #    #    #    #    #       #
#       #####     #    #####     #      #
#    #  #   #     #    #         #     #
 ####   #    #    #    #         #    ######  {Fore.RED}v5.0{Style.RESET_ALL}
{Fore.CYAN}
made by: {Fore.RED}r2dr0dn{Style.RESET_ALL}
"""
)

# Global Variables
MENU_OPTIONS = list()


def get(type):
    try:
        (color, message) = {
            "plaintext": (Fore.GREEN, "Enter plaintext message"),
            "encoded": (Fore.YELLOW, "Enter encoded message"),
            "encrypted": (Fore.YELLOW, "Enter encrypted message"),
            "filename": (Fore.MAGENTA, "Specify filename"),
            "password": (Fore.RED, "Enter encryption password"),
        }[type]
    except KeyError:
        color = Fore.CYAN
        message = type
    return input(f"{color}{message}: {Style.RESET_ALL}").encode()


def show(type, output):
    try:
        (color, message) = {
            "filename": (Fore.MAGENTA, "Output saved as"),
            "encoded": (Fore.YELLOW, "Encoded message"),
            "encrypted": (Fore.YELLOW, "Encrypted message"),
            "plaintext": (Fore.GREEN, "Plaintext"),
            "password": (Fore.RED, "Encryption password"),
        }[type]
    except KeyError:
        color = Fore.CYAN
        message = type
    print(f"{color}{message}:{Style.RESET_ALL}\n{output}")


def random_key(length):
    chars = string.ascii_letters + string.digits
    keypass = "".join(random.choice(chars) for x in range(length))
    return keypass


def hex_enc():
    """Encode to Hexadecimal."""
    plaintext = get("plaintext")
    output = binascii.hexlify(plaintext).decode()
    show("encoded", output)
MENU_OPTIONS.append(hex_enc)


def hex_dec():
    """Decode from Hexadecimal."""
    encoded_message = get("encoded")
    output = binascii.unhexlify(encoded_message).decode()
    show("plaintext", output)
MENU_OPTIONS.append(hex_dec)


def uu_enc():
    """Encode with uuencode."""
    plaintext = get("plaintext")
    output = binascii.b2a_uu(plaintext).decode()
    show("encoded", output)
MENU_OPTIONS.append(uu_enc)


def uu_dec():
    """Decode with uudecode."""
    encoded_message = get("encoded")
    output = binascii.a2b_uu(encoded_message).decode()
    show("plaintext", output)
MENU_OPTIONS.append(uu_dec)


def base64_enc():
    """Encode with Base64."""
    plaintext = get("plaintext")
    output = base64.b64encode(plaintext).decode()
    show("encoded", output)
MENU_OPTIONS.append(base64_enc)


def base64_dec():
    """Decode with Base64."""
    encoded_message = get("encoded")
    output = base64.b64decode(encoded_message).decode()
    show("plaintext", output)
MENU_OPTIONS.append(base64_dec)


def binhex_enc():
    """Encode with BinHex4."""
    temp_filename = f"temp_{random_key(32)}"
    with open(temp_filename, "wb") as outfile:
        outfile.write(get("plaintext"))
    dest_filename = get("filename").decode()
    binhex.binhex(temp_filename, dest_filename)
    os.unlink(temp_filename)
    show("outfile", dest_filename)
MENU_OPTIONS.append(binhex_enc)


def binhex_dec():
    """Decode with BinHex4."""
    temp_filename = f"temp_{random_key(32)}"
    binhex.hexbin(get("filename").decode(), temp_filename)
    with open(temp_filename, "rb") as infile:
        show("plaintext", infile.read().decode())
    os.unlink(temp_filename)
MENU_OPTIONS.append(binhex_dec)


def fernet_enc():
    """Encrypt with Fernet. (Symmetric)"""
    plaintext = get("plaintext")
    encryption_key = Fernet.generate_key()
    instance = Fernet(encryption_key)
    output = instance.encrypt(plaintext).decode()
    show("password", encryption_key.decode())
    show("encrypted", output)
MENU_OPTIONS.append(fernet_enc)


def fernet_dec():
    """Decrypt with Fernet. (Symmetric)"""
    encrypted_text = get("encrypted")
    password = get("password")
    instance = Fernet(password)
    decrypted_text = instance.decrypt(encrypted_text).decode()
    show("plaintext", decrypted_text)
MENU_OPTIONS.append(fernet_dec)


def aes_enc_manual():
    """Encrypt with AES. (Manual)"""
    keypass = random_key(16)
    data = get("plaintext")
    filename = get("filename").decode()
    cipher = AES.new(keypass.encode(), AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    try:
        show("password", keypass)
        show("Encryption tag", tag)
        show("Encryption nonce", cipher.nonce)
        with open(filename, "wb") as outfile:
            outfile.write(ciphertext)
        show("filename", filename)
    except Exception as e:
        print(e)
# Uncomment the following line once you have a working decryptor.
#MENU_OPTIONS.append(aes_enc_manual)


# def aes_dec_manual():
#     """Decrypt with AES. (Manual)"""
#     try:
#         keypass = get("password")
#         tag = input('Enter Tag: ')
#         # tag = tag.encode()
#         tag = str.encode(tag)
#         ciphertext = input("Enter CipherText: ")
#         # ciphertext = ciphertext.encode()
#         ciphertext = str.encode(ciphertext)
#         nonce = input("Enter Nonce: ")
#         # nonce = nonce.encode()
#         nonce = str.encode(nonce)
#         cipher = AES.new(keypass, AES.MODE_EAX, nonce)
#         data = cipher.decrypt_and_verify(ciphertext, tag)
#         data = data.decode()
#         print("\n" + Fore.RED + data + Style.RESET_ALL + "\n")
#     except ValueError:
#         print("Unmatched Value!!!")
#         exit(1)
# MENU_OPTIONS.append(aes_dec_manual)


#def rsa_enc_manual():
#    """Encrypt with RSA. (Manual)"""
#    data = get("plaintext")
#    BLOCK_SIZE = 16
#    PADDING = "{"
#    pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
#    EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
#    secret = random_key(4)
#    passphrase = secret
#    secret = str.encode(secret)
#    cipher = AES.new(secret)
#    encoded = EncodeAES(cipher, data)
#    encoded = bytes.decode(encoded)
#    print(Fore.CYAN + "\n" + "encryption key:" + passphrase + "\n")
#    print(
#        Fore.WHITE + Style.DIM + "Encrypted Data: ",
#        encoded + "\n" + Style.RESET_ALL,
#    )
# Uncomment the following line once you have a working decryptor.
# MENU_OPTIONS.append(rsa_enc_manual)


def aes_enc_auto():
    """Encrypt with AES. (Automatic)"""
    data = get("plaintext")
    data = data.encode()
    filename = get("filename")
    keypass = random_key(4)
    keypass2 = keypass
    keypass = keypass.encode()
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
#MENU_OPTIONS.append(aes_enc_auto)


def aes_dec_auto():
    """Decrypt with AES. (Automatic)"""
    filename = input(
        Fore.RED
        + "Enter Encrypted Data File (make sure it on the same path): "
    )
    file_in = open(filename, "rb")
    keypass = get("password")
    nonce, tag, ciphertext = [file_in.read(x) for x in (16, 16, -1)]
    cipher = AES.new(keypass, AES.MODE_EAX, nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    data = data.encode()
    print(Fore.MAGENTA + "\n" + "Decrypted: " + data + Style.RESET_ALL + "\n")
#MENU_OPTIONS.append(aes_dec_auto)


# Main Function
def main():
    try:
        while True:
            print(
                "\n" + Fore.CYAN
                + "Choose from the following options, or press Ctrl-C to quit:"
                + Style.RESET_ALL
            )
            for index in range(len(MENU_OPTIONS)):
                print(
                    f"{index + 1}. {' ' if index < 9 else ''}"
                    f"{MENU_OPTIONS[index].__doc__}"
                )
            choice = get("Selection")
            print()
            try:
                MENU_OPTIONS[int(choice) - 1]()
            except IndexError:
                print(Fore.RED + "Unknown option." + Style.RESET_ALL)
            except ValueError:
                print(Fore.RED + "Invalid input. Please enter the number of your selection." + Style.RESET_ALL)
    except KeyboardInterrupt:
        print(
            f"\n{Fore.RED}Program terminated. "
            f"{Fore.WHITE}{Style.BRIGHT}Have a nice day!"
            f"{Style.RESET_ALL}"
        )
        exit(1)


if __name__ == "__main__":
    main()
