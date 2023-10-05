from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes

import os
import sys

MAX_MEMORY_USAGE = 2**32
def aes256gcm_encrypt(key: bytes,data: bytes,header: bytes,nonce: bytes,tag_size: int) -> list:

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len = tag_size)
    cipher.update(header)
    ciphertext, tag = cipher.encrypt_and_digest(data)

    encrypted_obj = [ciphertext,tag,header,nonce]

    return encrypted_obj

def aes256gcm_decrypt(key: bytes,data: bytes,header: bytes,nonce: bytes,tag: bytes,tag_size) -> bytes:

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len = tag_size)
    cipher.update(header)
    decrypted_data = cipher.decrypt_and_verify(data, tag)

    return decrypted_data

def h():
    print('''
Commands           Info

-t                 run tests suite

-io                runs the script as a i-o
                   display on ur terminal

===========================================

Values             Info

--key or -k        (bytes)key for encrypting your data. 
                   It must be 16, 24 or 32 bytes long
                   (respectively for AES-128, AES-192 or AES-256).

--file or -i       (string)PATH of the file u want to encrypt
                   ex: "C:/path/path/file.extension"
              
--data or -d       data that u are inputing trought
                   cmd.

--nonce or -n      the value of the fixed nonce.
                   It must be unique for the combination message/key.
                   (default: os.urandom(16))

--tag_size or -ts  the desired length of the MAC tag,
                   from 4 to 16 bytes (default: 16).

--header or -h     header for ur encrypted object
''')
def tests():

    data = b"12345"

    chunk_data = [b"1",b"2",b"3",b"4",b"5"]

    key = b"1234567890123456" # 16 byte key to use aes256

    nonce = b"123456789012"

    header = b"BHZTK_AES-GCM"

    tag_size = 4

    # encrypt data

    encrypted_data = aes256gcm_encrypt(key,data,header,nonce,tag_size)

    print("Encrypted data: ",encrypted_data)

    # encrypt data in chunks
    print("Encrypted data in chunks:")
    encrypted_chunk_data = []
    for CHUNK in chunk_data:
        encrypted_chunk = aes256gcm_encrypt(key,CHUNK,header,nonce,tag_size)
        encrypted_chunk_data.append(encrypted_chunk)

    print("encrypted_chunk_data: ",end='')
    for encrypted_chunk in encrypted_chunk_data:
        print(encrypted_chunk)
    

    #decrypt data  
    print()
    #encrypted_obj = [ciphertext,tag,header,nonce]
    #key: bytes,data: bytes,header: bytes,nonce: bytes,tag: bytes
    decrypted_data = aes256gcm_decrypt(key,encrypted_data[0],encrypted_data[2],encrypted_data[3],encrypted_data[1],tag_size)
    print("Decrypted data:",decrypted_data)

    # decrypt chunk datad
    decrypted_chunk_data = b""
    for encrypted_chunk in encrypted_chunk_data:
        decrypted_chunk = aes256gcm_decrypt(key,encrypted_chunk[0],encrypted_chunk[2],encrypted_chunk[3],encrypted_chunk[1],tag_size)
        decrypted_chunk_data += decrypted_chunk

    print("Decrypted chunk data:",decrypted_chunk_data)

def io():
    pass

if __name__ == '__main__':
    inputs = sys.argv
    input_dict = {

        "key": b"",
        "nonce": b"",
        "data": b"",
        "filepath":"",
        "MAC_len":16,
        "header": b"",
    
        }

    for selec in inputs:
        if selec.upper() == "--HELP" or selec.upper() == "-H":
            h()
        elif selec.upper() == "-T":
            tests()
            break;

        elif selec.upper() == "-IO":
            io()
            break;

        elif selec.upper() == "-K" or selec.upper() == "--KEY":
            try:
                 input_dict["key"] = inputs[(inputs.index(selec) + 1)]
            except:
                print("the provided key cant be read!")
        
        elif selec.upper() == "-NONCE" or selec.upper() == "-N":
            try:
                input_dict["nonce"] = inputs[(inputs.index(selec) + 1)]
            except:
                print("the provided nonce cant be read!")
        
        elif selec.upper() == "--FILE" or selec.upper() == "-I":
            try:   
                input_dict["filepath"] = inputs[(inputs.index(selec) + 1)]
            except:
                print("the provided filepath cant be read!")

        elif selec.upper() == "--DATA" or selec.upper() == "-D":
            try:   
                input_dict["data"] = inputs[(inputs.index(selec) + 1)]
            except:
                print("the provided data cant be read!")

        elif selec.upper() == "--TAG_SIZE" or selec.upper() == "-TS":
            try:   
                input_dict["MAC_len"] = inputs[(inputs.index(selec) + 1)]
            except:
                print("the provided tag_size cant be read!")

        elif selec.upper() == "--HEADER" or selec.upper() == "-H":
            try:   
                input_dict["header"] = inputs[(inputs.index(selec) + 1)]
            except:
                print("the provided tag_size cant be read!")
    if len(inputs) <= 1:
        print("No input received... to get help try : '-h' or '--help'")


    if len(input_dict["nonce"]) == 0:
            input_dict["nonce"] = str(os.urandom(16))
    if len(input_dict["header"]) == 0:
        input_dict["header"] = "BHZTK_AES-GCM"

    print(input_dict)
    if len(input_dict["key"]) == 16 or len(input_dict["key"]) == 24 or len(input_dict["key"]) == 32:
        if int(input_dict["MAC_len"]) <= 16 and int(input_dict["MAC_len"]) >= 4:
            if input_dict["data"] != b"": #use data to encrypt
                #encrypted_obj = [ciphertext,tag,header,nonce]
                #key: bytes,data: bytes,header: bytes,nonce: bytes,tag: bytes
                print(aes256gcm_encrypt(bytes(input_dict["key"],encoding="utf-8"),
                    bytes(input_dict["data"],encoding="utf-8"),
                    bytes(input_dict["header"],encoding="utf-8"),
                    bytes(input_dict["nonce"],encoding="utf-8"),
                    int(input_dict["MAC_len"])))
            elif os.path.isfile(input_dict["filepath"]) == True:
                file_size = os.path.getsize(input_dict["filepath"])
                if file_size <= MAX_MEMORY_USAGE:
                    print(file_size)
                    byte_stream = b""
                    with open(f"{input_dict['filepath']}", "rb") as f:
                        while (byte := f.read(1)):
                            byte_stream += byte
                    input_dict['data'] = str(byte_stream)
                    print(aes256gcm_encrypt(bytes(input_dict["key"],encoding="utf-8"),
                        bytes(input_dict["data"],encoding="utf-8"),
                        bytes(input_dict["header"],encoding="utf-8"),
                        bytes(input_dict["nonce"],encoding="utf-8"),
                        int(input_dict["MAC_len"])))   


