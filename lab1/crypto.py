#!/usr/bin/env python3 -tt
"""
File: crypto.py
---------------
Assignment 1: Cryptography
Course: CS 41
Name: <Gyurka Dora>
id: <gdim2446>

Replace this with a description of the program.
"""
import utils
import math

# Caesar Cipher

def encrypt_caesar(plaintext):

    if isinstance(plaintext, str):
        cipher = ''
        for i in range(len(plaintext)): 
            cipher += chr((ord(plaintext[i])-65+3)%26 + 65)

        return cipher

    #itt ha non-text akkor nem kell kivonogassam a 65-t hanem csak hozzaadom a 3-at es modulozom 256-al
    elif isinstance(plaintext,bytes) or isinstance(plaintext,bytearray):
        cipher = bytearray()
        for i in range(len(plaintext)): 
            cipher.append((plaintext[i]+3)%256)

        return cipher
 
def decrypt_caesar(ciphertext):

    if isinstance(ciphertext,str):
        decrypted = ''

        for i in range(len(ciphertext)):
            decrypted += chr((ord(ciphertext[i])-65-3)%26 + 65)

        return decrypted
    elif isinstance(ciphertext,bytes) or isinstance(ciphertext,bytearray):
        decrypted = bytearray()

        for i in range(len(ciphertext)):
            decrypted.append((ciphertext[i]-3)%256)

        return decrypted


# Vigenere Cipher

def encrypt_vigenere(plaintext, keyword):
    
    key = ''
    encrypted = ''

    if len(keyword) == 0:
        raise ValueError("keyword erteke nem lehet 0")

    for i in range(len(plaintext)):
        key += keyword[i%len(keyword)]
    
    for i in range(len(plaintext)):
        encrypted += chr((ord(plaintext[i]) + ord(key[i]))%26+65)
    
    return encrypted

def decrypt_vigenere(ciphertext, keyword):

    key = ''
    decrypted = ''

    if len(keyword) == 0:
        raise ValueError("keyword erteke nem lehet 0")


    for i in range(len(ciphertext)):
        key += keyword[i%len(keyword)]

    for i in range(len(ciphertext)):
        if(ciphertext[i].isalpha()):
            decrypted += chr((ord(ciphertext[i]) - ord(key[i]))%26+65)
        else:
            decrypted += ciphertext[i]
    return decrypted


# Merkle-Hellman Knapsack Cryptosystem

def generate_private_key(n=8):
    """Generate a private key for use in the Merkle-Hellman Knapsack Cryptosystem.

    Following the instructions in the handout, construct the private key components
    of the MH Cryptosystem. This consistutes 3 tasks:

    1. Build a superincreasing sequence `w` of length n
        (Note: you can check if a sequence is superincreasing with `utils.is_superincreasing(seq)`)
    2. Choose some integer `q` greater than the sum of all elements in `w`
    3. Discover an integer `r` between 2 and q that is coprime to `q` (you can use utils.coprime)

    You'll need to use the random module for this function, which has been imported already

    Somehow, you'll have to return all of these values out of this function! Can we do that in Python?!

    @param n bitsize of message to send (default 8)
    @type n int

    @return 3-tuple `(w, q, r)`, with `w` a n-tuple, and q and r ints.
    """
    raise NotImplementedError  # Your implementation here

def create_public_key(private_key):
    """Create a public key corresponding to the given private key.

    To accomplish this, you only need to build and return `beta` as described in the handout.

        beta = (b_1, b_2, ..., b_n) where b_i = r × w_i mod q

    Hint: this can be written in one line using a list comprehension

    @param private_key The private key
    @type private_key 3-tuple `(w, q, r)`, with `w` a n-tuple, and q and r ints.

    @return n-tuple public key
    """
    raise NotImplementedError  # Your implementation here


def encrypt_mh(message, public_key):
    """Encrypt an outgoing message using a public key.

    1. Separate the message into chunks the size of the public key (in our case, fixed at 8)
    2. For each byte, determine the 8 bits (the `a_i`s) using `utils.byte_to_bits`
    3. Encrypt the 8 message bits by computing
         c = sum of a_i * b_i for i = 1 to n
    4. Return a list of the encrypted ciphertexts for each chunk in the message

    Hint: think about using `zip` at some point

    @param message The message to be encrypted
    @type message bytes
    @param public_key The public key of the desired recipient
    @type public_key n-tuple of ints

    @return list of ints representing encrypted bytes
    """
    raise NotImplementedError  # Your implementation here

def decrypt_mh(message, private_key):
    """Decrypt an incoming message using a private key

    1. Extract w, q, and r from the private key
    2. Compute s, the modular inverse of r mod q, using the
        Extended Euclidean algorithm (implemented at `utils.modinv(r, q)`)
    3. For each byte-sized chunk, compute
         c' = cs (mod q)
    4. Solve the superincreasing subset sum using c' and w to recover the original byte
    5. Reconsitite the encrypted bytes to get the original message back

    @param message Encrypted message chunks
    @type message list of ints
    @param private_key The private key of the recipient
    @type private_key 3-tuple of w, q, and r

    @return bytearray or str of decrypted characters
    """
    raise NotImplementedError  # Your implementation here

def encrypt_scytle(plaintext, circumference):

    if len(circumference) == 0:
        raise ValueError("circumference nem lehet 0")
    rows = math.ceil(len(plaintext) / circumference)
    matrix = [['' for _ in range(circumference)] for _ in range(rows)]

    for i in range(len(plaintext)):
        matrix[int(i/circumference)][i%circumference] = plaintext[i]

    cipher = ''
    for i in range(circumference):
        for j in range(rows):
            if matrix[j][i] != '':
                cipher += matrix[j][i]
    
    return cipher

def decrypt_scytle(ciphertext, circumference):

    if len(circumference) == 0:
        raise ValueError("circumference nem lehet 0")
    rows = math.ceil(len(ciphertext) / circumference)
    matrix = [['' for _ in range(circumference)] for _ in range(rows)]

    c = 0
    #vissza kell epiteni a matrixot a kodolt szovegbol
    for i in range(circumference):
        for j in range(rows):
            if circumference * j + i < len(ciphertext):
                matrix[j][i] = ciphertext[c]
                c += 1

    decipher = ''
    #soronkent kiolvasva kijon a kodolt uzenet
    for j in range(rows):
        for i in range(circumference):
            if matrix[j][i] != '':
                decipher += matrix[j][i]

    return decipher

def encrypt_railfence(plaintext, num_rails):

    matrix = ['' for _ in range(num_rails)]
    aktualis_sor = 0
    irany = 1

    for i in range(len(plaintext)):
        matrix[aktualis_sor] += plaintext[i]

        if aktualis_sor == 0:
            irany = 1
        elif aktualis_sor == num_rails - 1:
            irany = -1

        aktualis_sor += irany


    encrypt = ''
    for i in range(num_rails):
            encrypt += matrix[i]
        
    return encrypt

def decrypt_railfence(ciphertext, num_rails):

    if num_rails < 1:
        raise ValueError("numrails nagyobb kell legyen mint 1")

    matrix = ['' for _ in range(num_rails)]
    
    aktualis_sor = 0
    oszlop = 0
    irany = 1

    for i in range(len(ciphertext)):
        matrix[aktualis_sor] += '*'

        if aktualis_sor == 0:
            irany = 1
        elif aktualis_sor == num_rails - 1:
            irany = -1

        aktualis_sor += irany

    cnt = 0
    for i in range(num_rails):
        hossz = len(matrix[i])
        matrix[i] = ciphertext[cnt : cnt + hossz]
        cnt += hossz


    aktualis_sor = 0
    oszlop = 0
    irany = 1

    decrypt = ''
    for i in range(len(ciphertext)):
        decrypt += matrix[aktualis_sor][0]         
        matrix[aktualis_sor] = matrix[aktualis_sor][1:]

        if aktualis_sor == 0:
            irany = 1
        elif aktualis_sor == num_rails - 1:
            irany = -1

        aktualis_sor += irany


    return decrypt


def intelligent_codebraker():

    dictionary_words = set()
    ciphertext = ''
    with open("/usr/share/dict/words","r") as f:
        for line in f:
          word = line.strip()
          if word.isalpha():
            word = word.upper()
            dictionary_words.add(word)

    with open("secret_message.txt","r") as f:
        for line in f:
            nline = line.upper()
            ciphertext += nline

    valid = 0
    total = 0
    best_score = -1
    best_key = ''

    for w in dictionary_words:

        if len(w) > len(ciphertext) or len(w) == 0:
            continue

        dsz = decrypt_vigenere(ciphertext, w)
        decrypted = dsz.split()

        valid = 0
        total = len(decrypted)
        for sz in decrypted:
            new_sz = sz.strip(".,!?;:\"'")
            if new_sz in dictionary_words:
                valid += 1

        if total > 0:
            if(valid/total > best_score):
                best_score = valid/total
                best_key = w

    return best_key