import json
from base64 import b64encode
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from base64 import b64decode
import os

def aes256gcm_encrypt(key: bytes,data: bytes,header: bytes,nonce: bytes,tag: bytes) -> list:

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(header)
    ciphertext, tag = cipher.encrypt_and_digest(data)

    encrypted_obj = [ciphertext,tag,header,nonce]

    return encrypted_obj

def aes256gcm_decrypt(key: bytes,data: bytes,header: bytes,nonce: bytes,tag: bytes) -> bytes:

    try:

        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        cipher.update(header)
        decrypted_data = cipher.decrypt_and_verify(data, tag)

        return decrypted_data

    except:
        return [b"KEY ERROR"]

def tests():

    data = b"12345"
    chunk_data = [b"1",b"2",b"3",b"4",b"5"]

    key = b"1234567890123456" # 16 byte key to use aes256

    nonce = b"123456789012"

    header = b"BHZTK_AES-GCM"

    tag = b"123456789021"

    # encrypt data

    encrypted_data = aes256gcm_encrypt(key,data,header,nonce,tag)

    print("Encrypted data: ",encrypted_data[0])

    # encrypt data in chunks
    print("Encrypted data in chunks:")
    encrypted_chunk_data = []
    for CHUNK in chunk_data:
        encrypted_chunk = aes256gcm_encrypt(key,CHUNK,header,nonce,tag)
        encrypted_chunk_data.append(encrypted_chunk)

    print("encrypted_chunk_data: ",end='')
    for encrypted_chunk in encrypted_chunk_data:
        print(encrypted_chunk[0],end=";")
    

    #decrypt data  
    print()
    #encrypted_obj = [ciphertext,tag,header,nonce]
    #key: bytes,data: bytes,header: bytes,nonce: bytes,tag: bytes
    decrypted_data = aes256gcm_decrypt(key,encrypted_data[0],encrypted_data[2],encrypted_data[3],encrypted_data[1])
    print("Decrypted data:",decrypted_data)

    # decrypt chunk datad
    decrypted_chunk_data = b""
    for encrypted_chunk in encrypted_chunk_data:
        decrypted_chunk = aes256gcm_decrypt(key,encrypted_chunk[0],encrypted_chunk[2],encrypted_chunk[3],encrypted_chunk[1])
        decrypted_chunk_data += decrypted_chunk

    print("Decrypted chunk data:",decrypted_chunk_data)
    
def main():
    tests()

if __name__ == '__main__':
    main()