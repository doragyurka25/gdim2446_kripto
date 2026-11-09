import pytest
import base64
from tombtitkositok import (
    add_padding, delete_padding, 
    encrypt_vigenere, decrypt_vigenere,
    encrypt_AES, decrypt_AES,
    encrypt_ECB, decrypt_ECB,
    encrypt_CBC, decrypt_CBC,
    encrypt_CFB, decrypt_CFB,
    implement_OFB, implement_CTR
)

@pytest.fixture
def test_setup():
    key = b"my_secret_key_16"
    iv = b"iv_lightweight_12"
    plaintext = b"Comprehensive testing for all encryption modes, ciphers, and padding implementations!"
    blocksize = 16
    return key, iv, plaintext, blocksize

@pytest.mark.parametrize("padding_type", [0, 1, 2])
def test_all_paddings(test_setup, padding_type):
    _, _, plaintext, blocksize = test_setup
    data = bytearray(plaintext)
    padded = add_padding(data, blocksize, padding_type)
    assert len(padded) % blocksize == 0
    unpadded = delete_padding(padded, blocksize, padding_type)
    assert unpadded == plaintext

@pytest.mark.parametrize("cipher_name, enc_func, dec_func", [
    ("VIGENERE-BIN", encrypt_vigenere, decrypt_vigenere),
    ("AES-128", encrypt_AES, decrypt_AES)
])
@pytest.mark.parametrize("mode", ["ECB", "CBC", "CFB", "OFB", "CTR"])
def test_cipher_modes(test_setup, cipher_name, enc_func, dec_func, mode):
    key, iv, plaintext, blocksize = test_setup
    working_plaintext = bytearray(plaintext)
    
    needs_padding = mode in ["ECB", "CBC"]
    if needs_padding:
        working_plaintext = add_padding(working_plaintext, blocksize, 0)

    # Titkosítás
    if mode == "ECB":
        ciphertext = encrypt_ECB(working_plaintext, key, iv, blocksize, enc_func)
    elif mode == "CBC":
        ciphertext = encrypt_CBC(working_plaintext, key, iv, blocksize, enc_func)
    elif mode == "CFB":
        ciphertext = encrypt_CFB(working_plaintext, key, iv, blocksize, enc_func)
    elif mode == "OFB":
        ciphertext = implement_OFB(working_plaintext, key, iv, blocksize, enc_func)
    elif mode == "CTR":
        ciphertext = implement_CTR(working_plaintext, key, iv, blocksize, enc_func)

    # Dekódolás
    if mode == "ECB":
        decrypted = decrypt_ECB(ciphertext, key, iv, blocksize, dec_func)
    elif mode == "CBC":
        decrypted = decrypt_CBC(ciphertext, key, iv, blocksize, dec_func)
    elif mode == "CFB":
        decrypted = decrypt_CFB(ciphertext, key, iv, blocksize, enc_func)
    elif mode == "OFB":
        decrypted = implement_OFB(ciphertext, key, iv, blocksize, enc_func)
    elif mode == "CTR":
        decrypted = implement_CTR(ciphertext, key, iv, blocksize, enc_func)

    if needs_padding:
        decrypted = delete_padding(decrypted, blocksize, 0)

    assert decrypted == plaintext