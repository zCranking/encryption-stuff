import hashlib
from simplecrypt import encrypt, decrypt

value = "Account(1): Testing 1 2 3"
def SHA256():
    result = hashlib.sha256(value.encode())
    print("SHA256 encrypted data:", result.hexdigest())
SHA256()

def MD5():
    result = hashlib.md5(value.encode())
    print("MD5 encrypted data:", result.hexdigest())
MD5()

message = "Account(1): Testing 1 2 3"
hexString = ""

def encryption():
    global hexString
    ciphercode = encrypt('AIM', message)
    hexString = ciphercode.hex()
    print("Encryption" , hexString)
    
def decryption():
    global hexString
    byteStr = bytes.fromhex(hexString)
    original = decrypt('AIM', byteStr)
    finalMessage = original.decode("utf-8")
    print("Decryption =", finalMessage)

encryption()
decryption()