from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import json
import base64

def add_padding(plaintext, blockSize, paddingType):
    remainder = len(plaintext) % blockSize 
    padding_len = blockSize if remainder == 0 else blockSize - remainder

    if paddingType == 0:
        plaintext.extend(b'\x00' * padding_len)
    elif paddingType == 1:
        plaintext.append(128)

        if padding_len > 1:
            plaintext.extend(b'\x00' * (padding_len - 1))
    elif paddingType == 2:
        plaintext.extend(bytes([padding_len] * padding_len))

 
    return plaintext

def delete_padding(plaintext, blockSize, paddingType):
        plaintext = bytearray(plaintext)

        if paddingType == 0:
            i = len(plaintext)
            while i > 0 and plaintext[-1] == 0:
                plaintext.pop()
        
        elif paddingType == 1:
            i = len(plaintext)
            while i > 0 and plaintext[-1] != 128:
                plaintext.pop()
            if len(plaintext) > 0:
                plaintext.pop()
        elif paddingType == 2:
            if len(plaintext) > 0:
                utolso_byte = plaintext[-1]
                plaintext = plaintext[:-utolso_byte]

        return bytes(plaintext)

def encrypt_vigenere(plaintext, keyword):
    
    key = bytearray()
    encrypted = bytearray()

    if len(keyword) == 0:
        raise ValueError("keyword erteke nem lehet 0")

    for i in range(len(plaintext)):
        key.append(keyword[i%len(keyword)])
    
    for i in range(len(plaintext)):
        encrypted.append((plaintext[i] + key[i])%256)
    
    return encrypted

def decrypt_vigenere(ciphertext, keyword):

    key = bytearray()
    decrypted = bytearray()

    if len(keyword) == 0:
        raise ValueError("keyword erteke nem lehet 0")


    for i in range(len(ciphertext)):
        key.append(keyword[i%len(keyword)])

    for i in range(len(ciphertext)):
            decrypted.append((ciphertext[i] - key[i])%256)
    return decrypted

def encrypt_AES(block, key):
    if len(block) < 16:
        block = block + b'\x00' * (16 - len(block))
    elif len(block) > 16:
        block = block[:16]

    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()

    return encryptor.update(block) + encryptor.finalize()

def decrypt_AES(block, key):
    if len(block) < 16:
        block = block + b'\x00' * (16 - len(block))
    elif len(block) > 16:
        block = block[:16]
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    decryptor = cipher.decryptor()

    return decryptor.update(block) + decryptor.finalize()

def encrypt_ECB(plaintext, keyword, IV_Block, blockSize, cipher_func):
    encrypted_text = bytearray()
    for i in range(0,len(plaintext),blockSize):
            current_block = plaintext[i:i+blockSize]

            encrypted_block = cipher_func(current_block, keyword)
            encrypted_text.extend(encrypted_block)
    return bytes(encrypted_text)

def decrypt_ECB(plaintext, keyword, IV_Block, blockSize, cipher_func):
    decrypted_text = bytearray()
    for i in range(0,len(plaintext),blockSize):
        current_block = plaintext[i:i+blockSize]
    
        decrypted_block = cipher_func(current_block, keyword)
        decrypted_text.extend(decrypted_block)
    return bytes(decrypted_text)

def encrypt_CBC(plaintext, keyword, IV_Block, blockSize, cipher_func):
    text = bytearray()
    prev_cipher = bytearray(IV_Block)

    for i in range(0,len(plaintext),blockSize):
        current_block = plaintext[i:i+blockSize]
        next_xored = bytes(b_plain ^ b_IV for b_plain,b_IV in zip(current_block, prev_cipher))
        encrypted = cipher_func(next_xored, keyword)
        text.extend(encrypted)

        prev_cipher = encrypted

    return bytes(text)

def decrypt_CBC(plaintext, keyword, IV_Block, blockSize, cipher_func):
    text = bytearray()
    prev_cipher = bytearray(IV_Block)

    for i in range(0,len(plaintext),blockSize):
        current_block = plaintext[i:i+blockSize]
        decrypted = cipher_func(current_block, keyword)

        next_xored = bytes(b_plain ^ b_IV for b_plain,b_IV in zip(decrypted, prev_cipher))
    
        text.extend(next_xored)
        prev_cipher = current_block

    return bytes(text)

def encrypt_CFB(plaintext, keyword, IV_Block, blockSize, cipher_func):
    text = bytearray()
    prev_cipher = bytearray(IV_Block)

    for i in range(0,len(plaintext),blockSize):
        current_block = plaintext[i:i+blockSize]

        encrypted_register = cipher_func(bytes(prev_cipher), keyword)

        leftmost = encrypted_register[:len(current_block)]
        xored = bytes(b_plain ^ b_cyph for b_plain, b_cyph in zip(current_block,leftmost))
        text.extend(xored)

        prev_cipher = prev_cipher[len(xored):] + bytearray(xored)

    return bytes(text)

def decrypt_CFB(plaintext, keyword, IV_Block, blockSize, cipher_func):
    text = bytearray()
    prev_cipher = bytearray(IV_Block)

    for i in range(0,len(plaintext),blockSize):
        current_block = plaintext[i:i+blockSize]

        encrypted_register = cipher_func(bytes(prev_cipher), keyword)

        leftmost = encrypted_register[:len(current_block)]
        xored = bytes(b_plain ^ b_cyph for b_plain, b_cyph in zip(current_block,leftmost))
        text.extend(xored)

        prev_cipher = prev_cipher[len(current_block):] + bytearray(current_block)

    return bytes(text)

def implement_OFB(plaintext, keyword, IV_Block, blockSize, cipher_func):
    keystream_block = bytearray(IV_Block)
    text = bytearray()

    for i in range(0,len(plaintext),blockSize):   
        current_block = plaintext[i:i+blockSize]

        nextinput = bytearray(cipher_func(bytes(keystream_block), keyword))
        keystream_block = nextinput
        register = nextinput[:len(current_block)]

        next_xored = bytes(b_plain ^ b_IV for b_plain,b_IV in zip(register, current_block))
        text.extend(next_xored)

    return bytes(text)


def implement_CTR(plaintext, keyword, IV_Block, blockSize, cipher_func):
    nonce_len = blockSize // 2

    nonce = IV_Block[:nonce_len]
    counter_len = blockSize - nonce_len
    counter = 0

    text = bytearray()
    for i in range(0, len(plaintext), blockSize):
        current_block = plaintext[i:i+blockSize]

        counter_bytes = counter.to_bytes(counter_len, byteorder='big')
        counter_block = bytes(nonce + counter_bytes)

        keystream_block = cipher_func(counter_block, keyword)
        keystream_block = keystream_block[:len(current_block)]

        ciphertext = bytes(b_plain ^ b_IV for b_plain,b_IV in zip(current_block, keystream_block))

        text.extend(ciphertext)
        counter += 1

    return bytes(text)



def cipher_function():

    with open("test.jpg", "rb") as f:
        plaintext = bytearray(f.read())

    counter = 0

    for i in range(10):
        filename = f"config{i}.json"
        
        with open(filename, "r", encoding="utf-8") as f:
            config = json.load(f)


        working_plaintext = bytearray(plaintext)
        key_bytes = base64.b64decode(config["key"])
        iv_bytes = base64.b64decode(config["iv"])
        blockSize = config["blocksize"]

        padding_map = {"ZERO": 0, "DES": 1, "SF": 2}
        paddingType = padding_map.get(config["padding"], 2)

        #csak akkor van szukseg paddingre a ECB vagy CBC van
        if(config["mode"] != "CFB" and config["mode"] != "OFB" and config["mode"] != "CTR"):
                working_plaintext = add_padding(working_plaintext, blockSize, paddingType)

        if config["cipher"] == "VIGENERE-BIN":
            encryptcipher_type = encrypt_vigenere
            decryptcipher_type = decrypt_vigenere
        else: 
            encryptcipher_type = encrypt_AES
            decryptcipher_type = decrypt_AES

        

        mode = config["mode"]

        encrypted = bytearray()
        decrypted = bytearray()

        #kodolom a bemenetet
        match mode:
            case "ECB":
                encrypted = encrypt_ECB(working_plaintext,key_bytes,iv_bytes,blockSize,encryptcipher_type)

            case "CBC":
                encrypted = encrypt_CBC(working_plaintext,key_bytes,iv_bytes,blockSize,encryptcipher_type)

            case "CFB":
                encrypted = encrypt_CFB(working_plaintext,key_bytes,iv_bytes,blockSize,encryptcipher_type)

            case "OFB":
                encrypted = implement_OFB(plaintext,key_bytes,iv_bytes,blockSize,encryptcipher_type)

            case "CTR":
                encrypted = implement_CTR(plaintext,key_bytes,iv_bytes,blockSize,encryptcipher_type)


        #dekodolom a bemenetet
        match mode :
            case "ECB":
                decrypted = decrypt_ECB(encrypted,key_bytes,iv_bytes,blockSize,decryptcipher_type)

            case "CBC":
                decrypted = decrypt_CBC(encrypted,key_bytes,iv_bytes,blockSize,decryptcipher_type)

            case "CFB":
                decrypted = decrypt_CFB(encrypted,key_bytes,iv_bytes,blockSize,encryptcipher_type)

            case "OFB":
                decrypted = implement_OFB(encrypted,key_bytes,iv_bytes,blockSize,encryptcipher_type)

            case "CTR":
                decrypted = implement_CTR(encrypted,key_bytes,iv_bytes,blockSize,encryptcipher_type)


        if(config["mode"] != "CFB" and config["mode"] != "OFB" and config["mode"] != "CTR"):
                decrypted = delete_padding(decrypted, blockSize, paddingType)

        if decrypted == plaintext:
            counter += 1   
    print(f"\n A sikeres tesztek szama: {counter / 10}")

if __name__ == "__main__":
    cipher_function()