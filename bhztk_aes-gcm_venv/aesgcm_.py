from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
import os
import io
import sys
import json
import base64

MAX_MEMORY_USAGE = 2**26 
# 67.108864 megabytes file
def aes256gcm_encrypt(key: bytes,data: bytes,header: bytes,nonce: bytes,tag_size: int) -> list:

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len = tag_size)
    cipher.update(header)

    ciphertext, tag = cipher.encrypt_and_digest(data)

    encrypted_obj = [ciphertext,tag,header,nonce,tag_size]

    return encrypted_obj

def aes256gcm_decrypt(key: bytes,data: bytes,header: bytes,nonce: bytes,tag: bytes,tag_size:int):

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len = tag_size)
    cipher.update(header)
    decrypted_data = cipher.decrypt_and_verify(data, tag)

    return decrypted_data

def read_from_disk(path: str,CHUNK_SIZE: int) -> bytes:

    with open(f"{path}", "rb", buffering=0) as file:
        
        data = file.read(CHUNK_SIZE)

    return data

def write_to_disk(path: str,data: bytes):

    with open(f"{path}", "wb+", buffering=0) as file:
        
        file.write(data)

    return data


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

--header           header for ur encrypted object

--mode or -m       chose either encryption or decryption 
                   "enc","dec", respectively.

--tag or -tg       tag used to encrypt.
''')
def tests():
    with open("dummyfile.txt","a+") as dummyfile:
        dummyfile.write("Dummy data to be encrypted, 12345 password: 23405954 %#@#$")
    data = read_from_disk("dummyfile.txt",-1)
    encrypted_object = aes256gcm_encrypt(b"1234567890123456",data,b"BHZTK_AES",os.urandom(16),16)

    json_save_form ={
        "ciphertext": base64.b64encode(encrypted_object[0]).decode(),  
        "header": base64.b64encode(encrypted_object[2]).decode(),
        "nonce":base64.b64encode(encrypted_object[3]).decode(),
        "tag":base64.b64encode(encrypted_object[1]).decode(),
        "tag_size":encrypted_object[4],         
    } 

    with open("dummyobject.bhztkencfile", "w") as save_file:  
        json.dump(json_save_form, save_file, indent = 6)

    with open("dummyobject.bhztkencfile", "r") as read_file:
        data = json.load(read_file)

    dlf ={

        "ciphertext": base64.b64decode(data["ciphertext"]),  
        "header": base64.b64decode(data["header"]),
        "nonce":base64.b64decode(data["nonce"]),
        "tag":base64.b64decode(data["tag"]),
        "tag_size":data["tag_size"],         
    }

    decrypted_data = aes256gcm_decrypt(b"1234567890123456",dlf["ciphertext"],dlf["header"],dlf["nonce"],dlf["tag"],dlf["tag_size"])

    write_to_disk("decrypted_dummy_file.txt",decrypted_data)



if __name__ == '__main__':

    inputs = sys.argv

    if len(inputs) <= 1:
        print("No input received... to get help try : '-h' or '--help'")
        exit()

    string_key = ''
    string_data = ''
    string_filename = ''
    string_header = ''
    string_nonce = ''
    string_tag = ''
    int_mac_len = 0
    string_mode = ''

    for selec in inputs:
        
        if selec.upper() == "--HELP" or selec.upper() == "-H":
            h()
            exit()
        
        elif selec.upper() == "-T":
            tests()
            exit()

        elif selec.upper() == "-IO":
            io()
            exit()

        elif selec.upper() == "-K" or selec.upper() == "--KEY":
            try:
                string_key = inputs[(inputs.index(selec) + 1)] 
            except:
                print("the provided key cant be read!")
                exit()
        
        elif selec.upper() == "-NONCE" or selec.upper() == "-N":
            try:
                string_nonce = inputs[(inputs.index(selec) + 1)]
            except:
                print("the provided nonce cant be read!")
                exit()
        
        elif selec.upper() == "--FILE" or selec.upper() == "-I":
            try:   
                string_filename = inputs[(inputs.index(selec) + 1)]
            except:
                print("the provided filepath cant be read!")
                exit()

        elif selec.upper() == "--DATA" or selec.upper() == "-D":
            try:   
                string_data = inputs[(inputs.index(selec) + 1)]
            except:
                print("the provided data cant be read!")
                exit()

        elif selec.upper() == "--TAG_SIZE" or selec.upper() == "-TS":
            try:   
                int_mac_len = int(inputs[(inputs.index(selec) + 1)])
            except:
                print("the provided tag_size cant be read!")
                exit()

        elif selec.upper() == "--HEADER":
            try:   
                string_header = inputs[(inputs.index(selec) + 1)]
            except:
                print("the provided header cant be read!")
                exit()

        elif selec.upper() == "--MODE" or selec.upper() == "-M":
            try:   
                string_mode = inputs[(inputs.index(selec) + 1)]
            except:
                print("the provided mode cant be read!")
                exit()

        elif selec.upper() == "--TAG" or selec.upper() == "-TG":
            try:   
                string_tag = inputs[(inputs.index(selec) + 1)]
            except:
                print("the provided tag cant be read!")
                exit()


    if len(string_nonce) == 0:
        string_nonce = base64.b64encode(os.urandom(16)).decode("utf-8")

    if len(string_header) == 0:
        string_header = "BHZTK_AES"

    if int_mac_len <= 4 or int_mac_len >=16:
        int_mac_len = 16
    use_file = False
    if len(string_data) == 0:
        use_file = True
        if os.path.isfile(string_filename) == False:
            print("NO DATA INPUT")
            exit()

    if len(string_mode) == 0:
        print("NO MODE SELECTED")
        exit()

    if string_mode == "dec":
        if use_file == False:
            if len(string_tag) == 0:
                print("NO TAG PROVIDED FOR DECRYPTION WITH DATA")
                exit()

    if len(string_key) == 16 or len(string_key) == 24 or len(string_key) == 32:
        pass
    else:
        print("KEY HAS INVALIDE SIZE")
        exit()


    input_array = [
                   bytes(string_key, 'utf-8'),
                   bytes(string_header, 'utf-8'), 
                   bytes(string_data, 'utf-8'),
                   bytes(string_nonce, 'utf-8'),
                   bytes(string_tag, 'utf-8'),
                   int_mac_len,
                   string_filename,
                   string_mode
                  ]
    if use_file == True:
        print("Using file as input...")
    try:
        if input_array[7] == "enc":
            if use_file == True:
                data = read_from_disk(f"{input_array[6]}",-1)

                encrypted_object = aes256gcm_encrypt(input_array[0],data,input_array[1],input_array[3],input_array[5])

                json_save_form ={
                    "ciphertext": base64.b64encode(encrypted_object[0]).decode(),  
                    "header": base64.b64encode(encrypted_object[2]).decode(),
                    "nonce":base64.b64encode(encrypted_object[3]).decode(),
                    "tag":base64.b64encode(encrypted_object[1]).decode(),
                    "tag_size":encrypted_object[4],         
                } 
                save_to_file_input = input("Save to disk ? (Y/n) >")
                if save_to_file_input.upper() == "Y":
                    file_name = input("Filename >")
                    with open(f"{file_name}.BHZENCOBJ", "w") as save_file:  
                        json.dump(json_save_form, save_file, indent = 6)
                else:
                    exit()
            elif use_file == False:
                encrypted_object = aes256gcm_encrypt(input_array[0],input_array[2],input_array[1],input_array[3],input_array[5])
                json_save_form ={
                    "ciphertext": base64.b64encode(encrypted_object[0]).decode(),  
                    "header": base64.b64encode(encrypted_object[2]).decode(),
                    "nonce":base64.b64encode(encrypted_object[3]).decode(),
                    "tag":base64.b64encode(encrypted_object[1]).decode(),
                    "tag_size":encrypted_object[4],         
                } 
                save_to_file_input = input("Save to disk ? (Y/n) >")
                if save_to_file_input.upper() == "Y":
                    file_name = input("Filename >")
                    with open(f"{file_name}.BHZENCOBJ", "w") as save_file:  
                        json.dump(json_save_form, save_file, indent = 6)
                else:
                    exit()
            else:
                exit()
        elif input_array[7] == "dec":
            if use_file == True:
                try:

                    with open(f"{input_array[6]}", "r") as read_file:
                        data = json.load(read_file)

                    dlf ={

                            "ciphertext": base64.b64decode(data["ciphertext"]),  
                            "header": base64.b64decode(data["header"]),
                            "nonce":base64.b64decode(data["nonce"]),
                            "tag":base64.b64decode(data["tag"]),
                            "tag_size":data["tag_size"],         
                        }
                except:
                    print("File is not a BHZENCOBJ")
                    exit()
                try:
                    decrypted_data = aes256gcm_decrypt(input_array[0],dlf["ciphertext"],dlf["header"],dlf["nonce"],dlf["tag"],dlf["tag_size"])
                except:
                    print("Could not decrypt file.")
                    exit()
                save_to_file_input = input("Save to disk ? (Y/n) >")
                try:
                    if save_to_file_input.upper() == "Y":
                        file_name = input("Filename (include extension!!) >")
                        write_to_disk(f"{file_name}",decrypted_data)    
                    else:
                        exit()
                except:
                    print("Could not save file to disk...")
                    exit()
            elif use_file == False:
                print("Only files can be decrypted...")
            else:
                pass
    except:
        print("FATAL ERROR")