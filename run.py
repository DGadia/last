# Caesar Cipher
'''
def encrypt(text,s):
    result=""
    for i in range (len(text)):
        char=text[i]
        if(char.isupper()):
            result += chr((ord(char) + s -65) % 26 + 65)
        else:
            result +=chr((ord(char) + s- 97) %26 +97)
    return result
text = input("Enter the text to encrypt: ")
s = int(input("Enter the value of the Key: "))
print("Text: "+text)
str(s)
print("Cipher: " +encrypt(text,s))
'''
# Rail-Fence Cipher
'''
string = input("Enter a String: ")
def RailFence(string):
    result=""
    for i in range(len(string)):
        if(i%2==0):
            result += string[i]
    for i in range(len(string)):
        if (i%2!=0):
            result += string[i]
    return result
print("The RailFence Cipher Text is: "+RailFence(string))
'''
#mono-alphabetic cipher

import random

def encrypt(original, key=None):
    alpha = "abcdefghijklmnopqrstuvwxyz"
    if key is None:
        l = list(alpha)
        random.shuffle(l)
        key = "".join(l)
    new = [key[alpha.index(letter)] if letter in alpha else letter for letter in original.lower()]
    return "".join(new), key

def decrypt(cipher, key=None):
    alpha = "abcdefghijklmnopqrstuvwxyz"
    if key is not None:
        new = [alpha[key.index(letter)] if letter in key else letter for letter in cipher]
        return "".join(new)

original = input("Enter the message: ")
encrypted_message, encryption_key = encrypt(original)
decrypted_message = decrypt(encrypted_message, encryption_key)

print(f"Original: {original}")
print(f"Encrypted: {encrypted_message}")
print(f"Decrypted: {decrypted_message}")


#RSA Algorithm
'''
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import binascii

keyPair = RSA.generate(1024)
pubKey = keyPair.publickey()

print(f"Public Key (n={hex(pubKey.n)}, e={hex(pubKey.e)})")
pubKeyPem = pubKey.export_key().decode('ascii')
print(pubKeyPem)

# Encryption
msg = b'diti'
encryptor = PKCS1_OAEP.new(pubKey)
encrypted = encryptor.encrypt(msg)
print("Encrypted:", binascii.hexlify(encrypted).decode('ascii'))
print("015 Diti Gadia")
'''

#Diffie-heliman key Agreement
'''
from random import randint
if __name__ == '__main__':
    p = 97
    g = 4

    print('The value of p is: %d ' %(p))
    print('The value of g is: %d ' %(g))
    a = 4
    print('Secret number for Alice is : %s'%(a))
    x = int(pow(g,a,p))
    b = 6
    print('Secret number for Bob is : %s'%(b))
    y = int(pow(g,b,p))
    ka = int(pow(y,a,p))
    kb = int(pow(x,b,p))
    print('Secret key for the Alice is: %d' %(ka))
    print('Secret key for the Bob is: %d' %(kb))
    print("015 Diti Gadia")
'''
#DES
'''
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def des_encrypt(plain_text, key):
    cipher=DES.new(key,DES.MODE_ECB)
    padded_text=pad(plain_text.encode('utf-8'),DES.block_size)
    encrypted_text=cipher.encrypt(padded_text)
    return  encrypted_text

def des_decrypt(encrypted_text,key):
    cipher=DES.new(key, DES.MODE_ECB)
    decrypted_padded_text=cipher.decrypt(encrypted_text)
    decrypted_text=unpad(decrypted_padded_text, DES.block_size).decode('utf-8')
    return decrypted_text

if __name__ == "__main__":
    key =b'8bytekey'
    plain_text=input("Enter a plain text:")
    print(f"Original Text: {plain_text}")
    encrypted_text=des_encrypt(plain_text, key)
    print(f"Encrypted Text: {encrypted_text.hex()}")
    decrypted_text=des_decrypt(encrypted_text, key)
    print(f"Decrypted Text: {decrypted_text}")
'''

#AES
'''
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

def aes_encrypt(plain_text, key):
    cipher = AES.new(key, AES.MODE_CBC)
    padded_text = pad(plain_text.encode('utf-8'), AES.block_size)
    encrypted_text = cipher.encrypt(padded_text)
    return base64.b64encode(cipher.iv + encrypted_text).decode('utf-8')

def aes_decrypt(encrypted_text, key):
    encrypted_text = base64.b64decode(encrypted_text)
    iv = encrypted_text[:AES.block_size]
    encrypted_text = encrypted_text[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_padded_text = cipher.decrypt(encrypted_text)
    decrypted_text = unpad(decrypted_padded_text, AES.block_size).decode('utf-8')
    return decrypted_text
if __name__ == "__main__":
    key = get_random_bytes(16)
    plain_text=input("Enter a plain text:")
    print(f"Original Text: {plain_text}")
    encrypted_text = aes_encrypt(plain_text, key)
    print(f"Encrypted Text (Base64): {encrypted_text}")
    decrypted_text = aes_decrypt(encrypted_text, key)
    print(f"Decrypted Text: {decrypted_text}")
'''
#MD5
'''
import hashlib
result = hashlib.md5(b'Diti')
result1 = hashlib.md5(b'diti')
print("The byte equivalent of hash is ", end="")
print(result.digest())
print("The byte equivalent of hash is: ", end="")
print(result1.digest())
'''
#SHA
'''
import hashlib
str = input("Enter the value to encode: ")
result = hashlib.sha1(str.encode())
print("The hexadecimal equivalent if SHA1 is: ")
print(result.hexdigest())
'''
#Columnar Transposition Cipher
'''
def encrypt(message, keyword):
    matrix = createEncMatrix(len(keyword), message)
    keywordSequence = getKeywordSequence(keyword)
    
    ciphertext = ""
    for num in range(len(keywordSequence)):
        pos = keywordSequence.index(num + 1)
        for row in range(len(matrix)):
            if len(matrix[row]) > pos:
                ciphertext += matrix[row][pos]
    return ciphertext
def createEncMatrix(width, message):
    r = 0
    c = 0
    matrix = [[]]
    for ch in message:
        matrix[r].append(ch)
        c += 1
        if c >= width:
            c = 0
            r += 1
            matrix.append([])
    return matrix
def getKeywordSequence(keyword):
    sorted_indices = sorted(range(len(keyword)), key=lambda i: keyword[i])
    sequence = [sorted_indices.index(i) + 1 for i in range(len(keyword))]
    return sequence
def createDecrMatrix(keywordSequence, message):
    width = len(keywordSequence)
    height = -(-len(message) // width)  # Ceiling division
    matrix = createEmptyMatrix(width, height, len(message))
    
    pos = 0
    for num in range(len(keywordSequence)):
        column = keywordSequence.index(num + 1)
        
        r = 0
        while r < len(matrix) and len(matrix[r]) > column:
            if pos < len(message):
                matrix[r][column] = message[pos]
                pos += 1
            r += 1
    
    return matrix
def decrypt(message, keyword):
    matrix = createDecrMatrix(getKeywordSequence(keyword), message)
    
    plaintext = ""
    for r in range(len(matrix)):
        for c in range(len(matrix[r])):
            plaintext += matrix[r][c]
    return plaintext

def createEmptyMatrix(width, height, length):
    return [['' for _ in range(width)] for _ in range(height)]
def main():
    # Get user input
    message = input("Enter the message to encrypt: ")
    keyword = input("Enter the keyword: ")

    # Encrypt the message
    encrypted_message = encrypt(message, keyword)
    print(f"Encrypted message: {encrypted_message}")

    # Decrypt the message
    decrypted_message = decrypt(encrypted_message, keyword)
    print(f"Decrypted message: {decrypted_message}")

if __name__ == "__main__":
    main()
'''
