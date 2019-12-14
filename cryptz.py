#!/usr/bin/env python3
"""
Provides a number of encoders, decoders, encryptors and decryptors.

Created By r2dr0dn.
Improvements by Haxys.
Updated 2019.12.04.
"""

import base64
import binascii
import datetime
import random
import string

try:
    from colorama import Fore, Style, init
    import pybase64
    from Crypto.Cipher import AES
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
 ####   #    #    #    #         #    ######  {Fore.RED}v3.0{Style.RESET_ALL}
{Fore.CYAN}
made by: {Fore.RED}r2dr0dn{Style.RESET_ALL}
"""
)

# Global Variables
MENU_OPTIONS = list()


def ran_generator():
    chars = string.ascii_uppercase + string.ascii_lowercase + string.digits
    size = 4
    keypass = "".join(random.choice(chars) for x in range(size, 20))
    return keypass


def hex_enc():
    """Encode to Hexadecimal."""
    data = input(Fore.RED + "Enter Your Plain Text Message: ")
    data = data.encode()
    enc = binascii.hexlify(data)
    enc = enc.decode()
    print("\n" + Fore.RED + enc + Style.RESET_ALL + "\n")


MENU_OPTIONS.append(hex_enc)


def hex_dec():
    """Decode from Hexadecimal."""
    data = input(Fore.RED + "Enter Your Encrypted Form: ")
    data = data.encode()
    dec = binascii.unhexlify(data)
    dec = dec.decode()
    print("\n" + Fore.RED + dec + Style.RESET_ALL + "\n")


MENU_OPTIONS.append(hex_dec)


def binhex4_enc():
    """Encrypt with BinHex4."""
    data = input(
        Fore.GREEN + "Enter Your Plain Text Message: " + Style.RESET_ALL
    )
    data = data.encode()
    enc = binascii.b2a_hqx(data)
    enc = enc.decode()
    print("\n" + Fore.CYAN + enc + Style.RESET_ALL + "\n")


# Uncomment the following line once you have a working decoder.
# MENU_OPTIONS.append(binhex4_enc)


# TODO: Fix this code.
# def binhex4_dec():
#     """Decrypt with BinHex4."""
#     data = input(Fore.RED + "Enter Your Encrypted Form: ")
#     data = data.encode()
#     # data = '-6)c0M8h1$PaGf9PFR)'
#     dec = binascii.a2b_hqx(data)
#     dec = dec.decode()
#     print("\n" + Fore.MAGENTA + Style.DIM + dec + Style.RESET_ALL + "\n")
# MENU_OPTIONS.append(binhex4_dec)


def fernet_enc():
    """Encrypt with Fernet. (Symmetric)"""
    data = input(Fore.RED + "Enter Your Plain Text Message: ")
    data = data.encode()
    key = Fernet.generate_key()
    e = Fernet(key)
    encry = e.encrypt(data)
    encry = encry.decode()
    key = key.decode()
    print(Fore.RED + "Your Decryption password: [%s]" % key)
    print("\n" + Fore.GREEN + "Encryption Value [%s]" % encry + "\n")


MENU_OPTIONS.append(fernet_enc)


def fernet_dec():
    """Decrypt with Fernet. (Symmetric)"""
    password = input(Fore.RED + "Enter Decryption Password: ")
    password = password.encode()
    encr = input(Fore.GREEN + "Enter Encryption Value: ")
    encr = encr.encode()
    D = Fernet(password)
    decr = D.decrypt(encr)
    decr = decr.decode()
    print("\n" + Fore.RED + "Decrypted Value: [%s]" % decr + "\n")


MENU_OPTIONS.append(fernet_dec)


def uu_enc():
    """Encode with uuencode."""
    data = input(Fore.RED + "Enter Your Plain Text Message: ")
    data = data.encode()
    enc = binascii.b2a_uu(data)
    enc = enc.encode()
    print("\n" + Fore.RED + enc + Style.RESET_ALL + "\n")


MENU_OPTIONS.append(uu_enc)


def uu_dec():
    """Decode with uudecode."""
    data = input(Fore.RED + "Enter Your Encrypted Form: ")
    dec = binascii.a2b_uu(data)
    dec = dec.encode()
    print("\n" + Fore.RED + dec + Style.RESET_ALL + "\n")


MENU_OPTIONS.append(uu_dec)


def base64_enc():
    """Encode with Base64."""
    data = input(Fore.MAGENTA + "Enter Your Plain Text Message: ").encode()
    enc = pybase64._pybase64.b64encode(data).decode()
    print("\n" + Fore.YELLOW + enc + Style.RESET_ALL + "\n")


MENU_OPTIONS.append(base64_enc)


def base64_dec():
    """Decode with Base64."""
    data = input(Fore.RED + "Enter Your Encrypted Form: ").encode()
    dec = pybase64._pybase64.b64decode(data).decode()
    print("\n" + Fore.RED + dec + Style.RESET_ALL + "\n")


MENU_OPTIONS.append(base64_dec)


def aes_enc_manual():
    """Encrypt with AES. (Manual)"""
    keypass = ran_generator()
    keypass2 = keypass
    data = input(Fore.MAGENTA + "Enter Your Plain Text Message: ")
    data = data.encode()
    keypass = keypass.encode()
    cipher = AES.new(keypass, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    print(Fore.GREEN + "\n" + "Encryption Password: {}".format(keypass2))
    print(
        Fore.BLUE
        + "\n"
        + f"Your Encryption: Ciphertext: {ciphertext}\n"
        + f"Tag: {tag}\nNonce: {cipher.nonce}\n"
        + f"Please Save Them All Somewhere Safe"
        + Style.RESET_ALL
        + "\n"
    )


# Uncomment the following line once you have a working decryptor.
# MENU_OPTIONS.append(aes_enc_manual)


# def aes_dec_manual():
#     """Decrypt with AES. (Manual)"""
#     try:
#         keypass = input(Fore.RED + "Enter Your Decryption Password: ")
#         keypass = keypass.encode()
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


def rsa_enc_manual():
    """Encrypt with RSA. (Manual)"""
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


# Uncomment the following line once you have a working decryptor.
# MENU_OPTIONS.append(rsa_enc_manual)


def aes_enc_auto():
    """Encrypt with AES. (Automatic)"""
    data = input(Fore.MAGENTA + "Enter Your Plain Text Message: ")
    data = data.encode()
    filename = input(
        Fore.YELLOW + "Enter FileName To Encrypted Data Be Saved In: "
    )
    keypass = ran_generator()
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


MENU_OPTIONS.append(aes_enc_auto)


# AES Auth Decryption:
def aes_dec_auto():
    """Decrypt with AES. (Automatic)"""
    filename = input(
        Fore.RED
        + "Enter Encrypted Data File (make sure it on the same path): "
    )
    file_in = open(filename, "rb")
    keypass = input(Fore.RED + "Enter Decryption Password: ")
    keypass = keypass.encode()
    nonce, tag, ciphertext = [file_in.read(x) for x in (16, 16, -1)]
    cipher = AES.new(keypass, AES.MODE_EAX, nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    data = data.encode()
    print(Fore.MAGENTA + "\n" + "Decrypted: " + data + Style.RESET_ALL + "\n")


MENU_OPTIONS.append(aes_dec_auto)


# Main Function
def main():
    try:
        while True:
            print(
                Fore.CYAN
                + "Choose from the following options, or press Ctrl-C to quit."
                + Style.RESET_ALL
            )
            for index in range(len(MENU_OPTIONS)):
                print(
                    f"{index + 1}. {' ' if index < 9 else ''}"
                    f"{MENU_OPTIONS[index].__doc__}"
                )
            choice = input(Fore.CYAN + "CRYPTZ -> " + Style.RESET_ALL)
            try:
                MENU_OPTIONS[int(choice) - 1]()
            except IndexError:
                print(Fore.RED + "Unknown option.")
    except KeyboardInterrupt:
        print(
            f"\n{Fore.RED}Program terminated. "
            f"{Fore.WHITE}{Style.BRIGHT}Have a nice day!"
            f"{Style.RESET_ALL}"
        )
        exit(1)


if __name__ == "__main__":
    main()
