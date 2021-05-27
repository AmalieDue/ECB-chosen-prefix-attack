"""Code for Exercise 2 on Exercise sheet 5."""
from random import randint
from typing import Callable
from base64 import b64decode
import json

# We use the python package `pycryptodome` for the following modules
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


def main():
    """Check whether the oracle works."""
    
    if randint(0, 1) == 0:
        mode = "ECB"
        print(mode)
        encrypt = lambda message: encrypt_with_ecb_or_cbc(message, False)
    else:
        mode = "CBC"
        print(mode)
        encrypt = lambda message: encrypt_with_ecb_or_cbc(message, True)

    guessed_mode = ecb_cbc_oracle(encrypt)

    assert guessed_mode == mode


def ecb_cbc_oracle(encrypt: Callable[[bytes], bytes]) -> str:
    """Determine whether `encrypt` uses ECB or CBC is used."""
    
    message1=bytes([0]*26)
    message2=bytes([0]*26)
    message=message1+message2
    
    C=encrypt(message)
    b=list(C)
    
    c1=b[16:32]
    c2=b[32:32+16]
    #print((c1))
    #print((c2))
    
    if c1==c2:
        print("ECB")
        return "ECB"
    else: 
        print("CBC")
        return "CBC"
   


def encrypt_with_ecb_or_cbc(plaintext: bytes, cbc: bool) -> bytes:
    """Encrypt a message with either ECB or CBC."""
    prefix = get_random_bytes(randint(5, 10))
    postfix = get_random_bytes(randint(5, 10))
    plaintext = pkcs7_pad(prefix + plaintext + postfix, 16)
    key = get_random_bytes(16)
    if cbc:
        iv = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC,IV=iv)
        ciphertext = cipher.encrypt(plaintext)
    else:
        cipher = AES.new(key, AES.MODE_ECB)
        ciphertext = cipher.encrypt(plaintext)
    return ciphertext


def pkcs7_pad(message: bytes, bytes_per_block: int) -> bytes:
    """Return the message padded to a multiple of `bytes_per_block`."""
    if bytes_per_block >= 256 or bytes_per_block < 1:
        raise Exception("Invalid padding modulus")
    remainder = len(message) % bytes_per_block
    padding_length = bytes_per_block - remainder
    padding = bytes([padding_length] * padding_length)
    return message + padding


if __name__ == "__main__":
    main()
