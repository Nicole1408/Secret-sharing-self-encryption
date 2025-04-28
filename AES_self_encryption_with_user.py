########################################################################
import copy
# Author: Nicoleta

# Date: xxxxxx

# installation requirement:

#   PYTHON>=3.7

#   pycryptodome
#   pycryptodomex
#   ......
#usage:
# TODO. simply describe how to use this codebase here with command line
########################################################################
from hashlib import sha256
from Crypto.Hash import SHA256
from Crypto.Cipher import AES, DES, Blowfish
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import math
import os
import argparse
from datetime import datetime
from secretsharing import SecretSharer, HexToHexSecretSharer
from database import database_operations
import random
from io import BytesIO
from path_utils import set_working_path, set_output_path, set_storage_path
import time
import tracemalloc
from twofish import Twofish


#step 1: merge your cureent version with the object-oriented idea \/
#step 2: implement the database stuff (also for decryption) in the obj-oriented version  \/
#step 3: test the working path function  \/
#step 4: GUI (specify path or upload data via a button from local environment)

# store name of encrypted data based on transaction number in db

# Arguments for command line
def loading_args():
    '''Load arguments from command line'''	
    parser = argparse.ArgumentParser(description='This codebase is designed to ecnrypt and decrypt the given file')
    parser.add_argument('--mode', type=str, default='NA', help='mode = encrypt or decrypt or recover_secret or init_db or recover_secret_prop')
    parser.add_argument('--numChunks', type=int, default=10, help='specify the number of chunks to split the data into')
    parser.add_argument('--ownerID', type=str, default='10001', help='ID of the data owner')
    parser.add_argument('--userName', type=str, default='Dazhuang', help='the username of the current user who tries to access the file')
    parser.add_argument('--key', type=str, help='the key of the (last) data chunk')
    parser.add_argument('--confidentialLevel', default=0, type=int, help='how many share are required to gain the decryption key')
    parser.add_argument('--shares', default=0, type=int, help='how many shares to split in')
    parser.add_argument('--sharingUnits', type=str, default='', help='List of sharing units in the format "x-y- .."')
    parser.add_argument('--plainTextFileName', type=str, default='', help='name of the file')
    #parser.add_argument('--workingPath', type=str, help='the base path where the plain text or the encrypted chunks stored in')
    parser.add_argument('--callFromGUI', type=bool, default=False)
    parser.add_argument('--secrets', type=str, default='NA')
    parser.add_argument('--properties', type=str, default='NA', help='the names of sharing units, separated by ,')
    # parser.add_argument('--storage', type=str)
    # parser.add_argument('--outputPath', type=str)
    parser.add_argument('--transaction', type=str)
    #parser.add_argument('--hashArray', type=str, default='NA', help="Values of the hashes of the encryption chunk, seprated by -")
    parser.add_argument('--chunkFile', type=str, default='NA', help="path to the file where the hash values of the encrypted chunks are stored")
    parser.add_argument('--algorithm', type=str, default='AES', help="can be AES, DES, Blowfish or Twofish")
    args = parser.parse_args()
    return args


class self_encryption_decryption_inf_sharing:


    args = None

    def __init__(self, args):
        '''Constructor for the class, initializes the arguments and sets up paths'''	
        self.args = copy.deepcopy(args)

    def set_secrets(self, secrets):
        '''Set the secrets for the encryption/decryption process'''	
        self.secrets = secrets

    def set_properties(self, properties):
        '''Set the properties for the encryption/decryption process'''	
        self.properties = properties

    # XOR function to apply the CBC logic
    def xor_blocks(block1, block2):
        """ XOR two blocks (of equal size) """
        return bytes([b1 ^ b2 for b1, b2 in zip(block1, block2)])
    
    def encodeWithPaddingTwofish(self, plaintext, password):
        '''Encoding method, Twofish CBC, takes plaintext and encodes it with a password. 
        It generates a random salt and IV, derives a key using PBKDF2, and encrypts the plaintext using Twofish in CBC mode. The salt and IV are appended to the ciphertext for storage.'''	
        salt = get_random_bytes(16) 
        iv = get_random_bytes(16)  
        key = PBKDF2(password, salt, 32, count=1000000, hmac_hash_module=SHA256) 
        
        cipher = Twofish(key)  
        padded_plaintext = pad(plaintext, 16)
        ciphertext = b""
        previous_block = iv 
        for i in range(0, len(padded_plaintext), 16):
            block = padded_plaintext[i:i+16]  
            block_to_encrypt = bytes([b1 ^ b2 for b1, b2 in zip(block, previous_block)])
            encrypted_block = cipher.encrypt(block_to_encrypt)  
            ciphertext += encrypted_block  
            previous_block = encrypted_block 
    
        return ciphertext + salt + iv 
    
    def decodeWithPaddingTwofish(self, data, password):
        '''Decoding method, takes the encrypted data and decrypts it using a password. 
        It extracts the salt and IV from the data, derives the key using PBKDF2, and decrypts the ciphertext using Twofish in CBC mode. The decrypted message is unpadded before returning.
        If the key or ciphertext is incorrect or corrupted, a ValueError is raised.'''
        salt = data[-32:-16] 
        key = PBKDF2(password, salt, 32, count=1000000, hmac_hash_module=SHA256) 
        iv = data[-16:] 
        
        cipher = Twofish(key)  
        ciphertext = data[:-32]  
        
        decrypted_message = b""
        previous_block = iv 
        
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i+16]  
            decrypted_block = cipher.decrypt(block) 
            decrypted_block = bytes([b1 ^ b2 for b1, b2 in zip(decrypted_block, previous_block)])
            decrypted_message += decrypted_block 
            previous_block = block 
        
        try:
            return unpad(decrypted_message, 16)
        except ValueError:
            raise ValueError("The key or ciphertext is incorrect or corrupted")
 
    def encrypt_Twofish(self, content, number, userId, transaction_num):
        '''Splits the content of the file in a number of chunks, then encrypts each one of them using the hash of the next as password The encryption algorithm used is Twofish. 
        Chunks are stored in the database if the database is initialized.'''
        filename = self.args.plainTextFileName
        if(len(filename) > 64):
            filename = filename[-64:]
        padded_filename = filename.ljust(64, '\x00')
        user_info = open(self.args.workingPath+'/'+'userInfo.txt', "rb")
        last_chunk = user_info.read()
        chunk_hashes_array = []
        user_info.seek(0)
        if (last_chunk == ""):
            last_chunk = "0. ".encode('utf-8') + userId.encode('utf-8')
        else:
            last_chunk += ("\n".encode('utf-8') + str(len(user_info.readlines())).encode('utf-8') + ". ".encode('utf-8')) + userId.encode('utf-8')
        user_info.close()
        if (len(last_chunk) > 50):
            open(self.args.workingPath+'/'+"userInfo.txt", "wb").close()
            last_chunk = "0. ".encode('utf-8') + userId.encode('utf-8')
        user_info = open(self.args.workingPath+'/'+"userInfo.txt", "wb")
        user_info.write(last_chunk)
        user_info.close()
        while(len(userId.encode('utf-8')) < 16):
            userId+= chr(0)
        chunks = []
        chunk_size = math.ceil(len(content)/number)
        i = 0
        while i < len(content):
            chunk = content[i:i+chunk_size]
            if (i == 0):
                chunk = userId.encode('utf-8') + chunk
            chunks.append(chunk)
            i = i + chunk_size
        chunks.append(last_chunk)
        chunk_hashes = []
        for j in range(len(chunks)):
            hash_object = sha256(chunks[j])
            hash_value = hash_object.hexdigest()
            chunk_hashes.append(hash_value)
        for k in range(len(chunks) - 1):
            f = open(self.args.storage+'/'+"chunk"+ str(k) + transaction_num + ".bin", "wb")
            chunk_to_write = transaction_num.encode() + padded_filename.encode() + self.encodeWithPaddingTwofish(chunks[k], chunk_hashes[k+1])
            try:
                database_operations.insert_chunk_table(transaction_num, sha256(chunk_to_write).hexdigest(), k)
            except RuntimeError as e:
                        if(str(e) == "Please initialize database"):
                            f.write(chunk_to_write)
                            f.close()
                            print(sha256(chunk_to_write).hexdigest())
                            chunk_hashes_array.append(sha256(chunk_to_write).hexdigest())
                            continue
                        else:
                            raise
            f.write(chunk_to_write)
            f.close()
        k = len(chunks) - 1
        extraF = open(self.args.storage+'/'+"chunk"+ str(k) + transaction_num + ".bin", "wb")
        chunk_to_write = transaction_num.encode() + padded_filename.encode() + self.encodeWithPaddingTwofish(chunks[k], chunk_hashes[0])
        try:
            database_operations.insert_chunk_table(transaction_num, sha256(chunk_to_write).hexdigest(), k)
        except RuntimeError as e:
                        if(str(e) == "Please initialize database"):
                            chunk_hashes_array.append(sha256(chunk_to_write).hexdigest())
                            print(sha256(chunk_to_write).hexdigest())
                        else:
                            raise
        extraF.write(chunk_to_write)
        extraF.close()
        return transaction_num+chunk_hashes[0], chunk_hashes_array

    def decrypt_Twofish(self, passK, number, userId, username):
        '''Decrypts the chunks it finds in the database; has to find the hash of the last chunk. If it does not find the database, it will look for the chunks in the storage folder.
        It will find the binary files and decrypt them using the password derived from the hash of the next chunk. The name of the file is also retrieved from the database or the file header.'''
        transaction_num = passK[:18]
        name_of_file = ''
        try:
            name_of_file = database_operations.query_for_file_name(transaction_num)
        except RuntimeError as e:
            if(str(e) == "Please initialize database"):
                name_of_file = ''
        except TypeError as e:
            if("object is not subscriptable" in str(e)):
                print('Secret recovery did not work')
                return
        passK = passK[18:]
        try:
            hashArray = database_operations.query_chunk_table_for_transaction(transaction_num)
        except RuntimeError as e:
            if(str(e) == "Please initialize database"):
                if(self.args.chunkFile != "NA"):
                    with open(self.args.chunkFile, 'r') as chunkFile:
                        chunks = [line.strip() for line in chunkFile]
                        chunks = [chunk for chunk in chunks if chunk != ""]
                    hashArray = [[chunk] for chunk in chunks]
                else:
                    print("Please provide the hashes of the encrypted chunks")
                    return
        if(len(hashArray) == 0):
            if(self.args.chunkFile != "NA"):
                    with open(self.args.chunkFile, 'r') as chunkFile:
                        chunks = [line.strip() for line in chunkFile]
                    hashArray = [[chunk] for chunk in chunks]
            else:
                print("Please provide the hashes of the encrypted chunks")
                return
        if(len(hashArray) != number+1):
            print("Incorrect number of chunks found, cannot decrypt")
            return
        a = number
        decrypted_chunks = []
        binary_files = []
        for filename in os.listdir(self.args.storage):
            if filename.endswith('.bin') and transaction_num in filename:
                filepath = os.path.join(self.args.storage, filename)
                with open(filepath, 'rb') as f:
                    content = f.read()
                    binary_files.append(content)
        if(len(binary_files) != number+1 or name_of_file == ''):
            binary_files = []
            for filename in os.listdir(self.args.storage):
                if filename.endswith('.bin'):
                    filepath = os.path.join(self.args.storage, filename)
                    with open(filepath, 'rb') as f:
                        num = f.read(82)
                        if(num[:18] == transaction_num.encode()):
                            binary_files.append(num + f.read())
                            if(name_of_file == ''):
                                name_of_file = num[18:83].decode().rstrip('\x00')
        while(a >= 0):
            print('decrypted '+ str(a) +'th chunk')
            hash_to_find = hashArray[a][0]
            c = ""
            for content in binary_files:
                if(sha256(content).hexdigest() == hash_to_find):
                    c = content[82:]
                    break
            decrypted_chunk = ''
            try:
                decrypted_chunk = self.decodeWithPaddingTwofish(c, passK)
            except ValueError as e:
                if(str(e) == 'The key was incorrect'):
                    print('Wrong key')
                    return
            try:
                hash_object = sha256(decrypted_chunk)
            except TypeError as e:
                print('Cannot decrypt the file')
                return
            hash_value = hash_object.hexdigest()
            passK = hash_value
            decrypted_chunks.insert(0, decrypted_chunk)
            a-=1
        decrypted_chunks[0] = decrypted_chunks[0][16:]
        print('write the retrived text to result file...',end='')
        counter = 0
        print(name_of_file)
        name = name_of_file.rsplit(".", 1)[0]
        new_name = name
        file_extension = name_of_file.rsplit(".", 1)[1]
        while(os.path.exists(self.args.outputPath + '/' + new_name + "." + file_extension)):
            counter += 1
            new_name = name + str(counter)
        outputF = open(self.args.outputPath+'/'+ new_name + "." + file_extension, "wb")
        print(', path:'+self.args.outputPath+'/'+ new_name + "." + file_extension + "...",end='')
        for v in range(len(decrypted_chunks) - 1):
            outputF.write(decrypted_chunks[v])
        outputF.close()

        user_info = open(self.args.workingPath+'/'+"userInfo.txt", "r", encoding="utf-8")
        last_chunk = decrypted_chunks[len(decrypted_chunks) - 1]
        last_chunk += ("\n" + str(len(user_info.readlines()) -1) + ". ").encode("utf-8") +  username.encode("utf-8")
        user_info.close()
        user_info = open(self.args.workingPath+'/'+"userInfo.txt", "w", encoding="utf-8")
        user_info.write(str(last_chunk))
        user_info.close()



    def encodeWithPaddingBlowfish(self, plaintext, password):
        '''Encoding method, Blowfish CBC, takes plaintext and encodes it with a password. 
        It generates a random salt and IV, derives a key using PBKDF2, and encrypts the plaintext using Blowfish in CBC mode. The salt and IV are appended to the ciphertext for storage.'''
        salt = get_random_bytes(16)
        iv = get_random_bytes(8)
        key = PBKDF2(password, salt, 56, count=1000000, hmac_hash_module=SHA256)
        encrypt_cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
        ciphertext = encrypt_cipher.encrypt(pad(plaintext, 8))
        return ciphertext + salt + iv
    
    def decodeWithPaddingBlowfish(self, data, password):
        '''Decoding method, takes the encrypted data and decrypts it using a password.	
        It retrieves the salt and IV from the data, derives the key using PBKDF2, and decrypts the ciphertext using Blowfish in CBC mode. The decrypted message is unpadded before returning.'''
        salt = data[-24:-8]
        key = PBKDF2(password, salt, 56, count=1000000, hmac_hash_module=SHA256)
        iv = data[-8:]
        decrypt_cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
        ciphertext = data[:-24]
        message = decrypt_cipher.decrypt(ciphertext)
        try:
            return unpad(message, 8)
        except:
            raise ValueError("The key was incorrect")

    def encodeWithPaddingDES(self, plaintext, password):
        '''Encoding method, DES CBC, takes plaintext and encodes it with a password. 
        It generates a random salt and IV, derives a key using PBKDF2, and encrypts the plaintext using DES in CBC mode. The salt and IV are appended to the ciphertext for storage.'''
        salt = get_random_bytes(16)
        iv = get_random_bytes(8)
        key = PBKDF2(password, salt, 8, count=1000000, hmac_hash_module=SHA256)
        encrypt_cipher = DES.new(key, DES.MODE_CBC, iv)
        ciphertext = encrypt_cipher.encrypt(pad(plaintext, 8))
        return ciphertext + salt + iv

    def decodeWithPaddingDES(self, data, password):
        '''Decoding method, takes the encrypted data and decrypts it using a password.	
        It retrieves the salt and IV from the data, derives the key using PBKDF2, and decrypts the ciphertext using DES in CBC mode. The decrypted message is unpadded before returning.'''
        salt = data[-24:-8]
        key = PBKDF2(password, salt, 8, count=1000000, hmac_hash_module=SHA256)
        iv = data[-8:]
        decrypt_cipher = DES.new(key, DES.MODE_CBC, iv)
        ciphertext = data[:-24]
        message = decrypt_cipher.decrypt(ciphertext)
        try:
            return unpad(message, 8)
        except:
            raise ValueError("The key was incorrect")

    def encrypt_Blowfish(self, content, number, userId, transaction_num):
        '''Splits the content of the file in a number of chunks, then encrypts each one of them using the hash of the next as password The encryption algorithm used is Blowfish. 
        Chunks are stored in the database if the database is initialized.'''
        filename = self.args.plainTextFileName
        if(len(filename) > 64):
            filename = filename[-64:]
        padded_filename = filename.ljust(64, '\x00')
        user_info = open(self.args.workingPath+'/'+'userInfo.txt', "rb")
        last_chunk = user_info.read()
        chunk_hashes_array = []
        user_info.seek(0)
        if (last_chunk == ""):
            last_chunk = "0. ".encode('utf-8') + userId.encode('utf-8')
        else:
            last_chunk += ("\n".encode('utf-8') + str(len(user_info.readlines())).encode('utf-8') + ". ".encode('utf-8')) + userId.encode('utf-8')
        user_info.close()
        if (len(last_chunk) > 50):
            open(self.args.workingPath+'/'+"userInfo.txt", "wb").close()
            last_chunk = "0. ".encode('utf-8') + userId.encode('utf-8')
        user_info = open(self.args.workingPath+'/'+"userInfo.txt", "wb")
        user_info.write(last_chunk)
        user_info.close()
        while(len(userId.encode('utf-8')) < 16):
            userId+= chr(0)
        chunks = []
        chunk_size = math.ceil(len(content)/number)
        i = 0
        while i < len(content):
            chunk = content[i:i+chunk_size]
            if (i == 0):
                chunk = userId.encode('utf-8') + chunk
            chunks.append(chunk)
            i = i + chunk_size
        chunks.append(last_chunk)
        chunk_hashes = []
        for j in range(len(chunks)):
            hash_object = sha256(chunks[j])
            hash_value = hash_object.hexdigest()
            chunk_hashes.append(hash_value)
        for k in range(len(chunks) - 1):
            f = open(self.args.storage+'/'+"chunk"+ str(k) + transaction_num + ".bin", "wb")
            chunk_to_write = transaction_num.encode() + padded_filename.encode() + self.encodeWithPaddingBlowfish(chunks[k], chunk_hashes[k+1])
            try:
                database_operations.insert_chunk_table(transaction_num, sha256(chunk_to_write).hexdigest(), k)
            except RuntimeError as e:
                        if(str(e) == "Please initialize database"):
                            f.write(chunk_to_write)
                            f.close()
                            print(sha256(chunk_to_write).hexdigest())
                            chunk_hashes_array.append(sha256(chunk_to_write).hexdigest())
                            continue
                        else:
                            raise
            f.write(chunk_to_write)
            f.close()
        k = len(chunks) - 1
        extraF = open(self.args.storage+'/'+"chunk"+ str(k) + transaction_num + ".bin", "wb")
        chunk_to_write = transaction_num.encode() + padded_filename.encode() + self.encodeWithPaddingBlowfish(chunks[k], chunk_hashes[0])
        try:
            database_operations.insert_chunk_table(transaction_num, sha256(chunk_to_write).hexdigest(), k)
        except RuntimeError as e:
                        if(str(e) == "Please initialize database"):
                            chunk_hashes_array.append(sha256(chunk_to_write).hexdigest())
                            print(sha256(chunk_to_write).hexdigest())
                        else:
                            raise
        extraF.write(chunk_to_write)
        extraF.close()
        return transaction_num+chunk_hashes[0], chunk_hashes_array

    def decrypt_Blowfish(self, passK, number, userId, username):
        '''Decrypts the chunks it finds in the database; has to find the hash of the last chunk. If it does not find the database, it will look for the chunks in the storage folder.
        It will find the binary files and decrypt them using the password derived from the hash of the next chunk. The name of the file is also retrieved from the database or the file header.'''
        transaction_num = passK[:18]
        name_of_file = ''
        try:
            name_of_file = database_operations.query_for_file_name(transaction_num)
        except RuntimeError as e:
            if(str(e) == "Please initialize database"):
                name_of_file = ''
        except TypeError as e:
            if("object is not subscriptable" in str(e)):
                print('Secret recovery did not work')
                return
        passK = passK[18:]
        try:
            hashArray = database_operations.query_chunk_table_for_transaction(transaction_num)
        except RuntimeError as e:
            if(str(e) == "Please initialize database"):
                if(self.args.chunkFile != "NA"):
                    with open(self.args.chunkFile, 'r') as chunkFile:
                        chunks = [line.strip() for line in chunkFile]
                        chunks = [chunk for chunk in chunks if chunk != ""]
                    hashArray = [[chunk] for chunk in chunks]
                else:
                    print("Please provide the hashes of the encrypted chunks")
                    return
        if(len(hashArray) == 0):
            if(self.args.chunkFile != "NA"):
                    with open(self.args.chunkFile, 'r') as chunkFile:
                        chunks = [line.strip() for line in chunkFile]
                    hashArray = [[chunk] for chunk in chunks]
            else:
                print("Please provide the hashes of the encrypted chunks")
                return
        if(len(hashArray) != number+1):
            print("Incorrect number of chunks found, cannot decrypt")
            return
        a = number
        decrypted_chunks = []
        binary_files = []
        for filename in os.listdir(self.args.storage):
            if filename.endswith('.bin') and transaction_num in filename:
                filepath = os.path.join(self.args.storage, filename)
                with open(filepath, 'rb') as f:
                    content = f.read()
                    binary_files.append(content)
        if(len(binary_files) != number+1 or name_of_file == ''):
            binary_files = []
            for filename in os.listdir(self.args.storage):
                if filename.endswith('.bin'):
                    filepath = os.path.join(self.args.storage, filename)
                    with open(filepath, 'rb') as f:
                        num = f.read(82)
                        if(num[:18] == transaction_num.encode()):
                            binary_files.append(num + f.read())
                            if(name_of_file == ''):
                                name_of_file = num[18:83].decode().rstrip('\x00')
        while(a >= 0):
            print('decrypted '+ str(a) +'th chunk')
            hash_to_find = hashArray[a][0]
            c = ""
            for content in binary_files:
                if(sha256(content).hexdigest() == hash_to_find):
                    c = content[82:]
                    break
            decrypted_chunk = ''
            try:
                decrypted_chunk = self.decodeWithPaddingBlowfish(c, passK)
            except ValueError as e:
                if(str(e) == 'The key was incorrect'):
                    print('Wrong key')
                    return
            try:
                hash_object = sha256(decrypted_chunk)
            except TypeError as e:
                print('Cannot decrypt the file')
                return
            hash_value = hash_object.hexdigest()
            passK = hash_value
            decrypted_chunks.insert(0, decrypted_chunk)
            a-=1
        decrypted_chunks[0] = decrypted_chunks[0][16:]
        print('write the retrived text to result file...',end='')
        counter = 0
        print(name_of_file)
        name = name_of_file.rsplit(".", 1)[0]
        new_name = name
        file_extension = name_of_file.rsplit(".", 1)[1]
        while(os.path.exists(self.args.outputPath + '/' + new_name + "." + file_extension)):
            counter += 1
            new_name = name + str(counter)
        outputF = open(self.args.outputPath+'/'+ new_name + "." + file_extension, "wb")
        print(', path:'+self.args.outputPath+'/'+ new_name + "." + file_extension + "...",end='')
        for v in range(len(decrypted_chunks) - 1):
            outputF.write(decrypted_chunks[v])
        outputF.close()

        user_info = open(self.args.workingPath+'/'+"userInfo.txt", "r", encoding="utf-8")
        last_chunk = decrypted_chunks[len(decrypted_chunks) - 1]
        last_chunk += ("\n" + str(len(user_info.readlines()) -1) + ". ").encode("utf-8") +  username.encode("utf-8")
        user_info.close()
        user_info = open(self.args.workingPath+'/'+"userInfo.txt", "w", encoding="utf-8")
        user_info.write(str(last_chunk))
        user_info.close()

    def encrypt_DES(self, content, number, userId, transaction_num):
        '''Splits the content of the file in a number of chunks, then encrypts each one of them using the hash of the next as password The encryption algorithm used is DES. 
        Chunks are stored in the database if the database is initialized.'''
        filename = self.args.plainTextFileName
        if(len(filename) > 64):
            filename = filename[-64:]
        padded_filename = filename.ljust(64, '\x00')
        user_info = open(self.args.workingPath+'/'+'userInfo.txt', "rb")
        last_chunk = user_info.read()
        chunk_hashes_array = []
        user_info.seek(0)
        if (last_chunk == ""):
            last_chunk = "0. ".encode('utf-8') + userId.encode('utf-8')
        else:
            last_chunk += ("\n".encode('utf-8') + str(len(user_info.readlines())).encode('utf-8') + ". ".encode('utf-8')) + userId.encode('utf-8')
        user_info.close()
        if (len(last_chunk) > 50):
            open(self.args.workingPath+'/'+"userInfo.txt", "wb").close()
            last_chunk = "0. ".encode('utf-8') + userId.encode('utf-8')
        user_info = open(self.args.workingPath+'/'+"userInfo.txt", "wb")
        user_info.write(last_chunk)
        user_info.close()
        while(len(userId.encode('utf-8')) < 16):
            userId+= chr(0)
        chunks = []
        chunk_size = math.ceil(len(content)/number)
        i = 0
        while i < len(content):
            chunk = content[i:i+chunk_size]
            if (i == 0):
                chunk = userId.encode('utf-8') + chunk
            chunks.append(chunk)
            i = i + chunk_size
        chunks.append(last_chunk)
        chunk_hashes = []
        for j in range(len(chunks)):
            hash_object = sha256(chunks[j])
            hash_value = hash_object.hexdigest()
            chunk_hashes.append(hash_value)
        for k in range(len(chunks) - 1):
            f = open(self.args.storage+'/'+"chunk"+ str(k) + transaction_num + ".bin", "wb")
            chunk_to_write = transaction_num.encode() + padded_filename.encode() + self.encodeWithPaddingDES(chunks[k], chunk_hashes[k+1])
            try:
                database_operations.insert_chunk_table(transaction_num, sha256(chunk_to_write).hexdigest(), k)
            except RuntimeError as e:
                        if(str(e) == "Please initialize database"):
                            f.write(chunk_to_write)
                            f.close()
                            print(sha256(chunk_to_write).hexdigest())
                            chunk_hashes_array.append(sha256(chunk_to_write).hexdigest())
                            continue
                        else:
                            raise
            f.write(chunk_to_write)
            f.close()
        k = len(chunks) - 1
        extraF = open(self.args.storage+'/'+"chunk"+ str(k) + transaction_num + ".bin", "wb")
        chunk_to_write = transaction_num.encode() + padded_filename.encode() + self.encodeWithPaddingDES(chunks[k], chunk_hashes[0])
        try:
            database_operations.insert_chunk_table(transaction_num, sha256(chunk_to_write).hexdigest(), k)
        except RuntimeError as e:
                        if(str(e) == "Please initialize database"):
                            chunk_hashes_array.append(sha256(chunk_to_write).hexdigest())
                            print(sha256(chunk_to_write).hexdigest())
                        else:
                            raise
        extraF.write(chunk_to_write)
        extraF.close()
        return transaction_num+chunk_hashes[0], chunk_hashes_array

    def decrypt_DES(self, passK, number, userId, username):
        '''Decrypts the chunks it finds in the database; has to find the hash of the last chunk. If it does not find the database, it will look for the chunks in the storage folder.
        It will find the binary files and decrypt them using the password derived from the hash of the next chunk. The name of the file is also retrieved from the database or the file header.'''
        transaction_num = passK[:18]
        name_of_file = ''
        try:
            name_of_file = database_operations.query_for_file_name(transaction_num)
        except RuntimeError as e:
            if(str(e) == "Please initialize database"):
                name_of_file = ''
        except TypeError as e:
            if("object is not subscriptable" in str(e)):
                print('Secret recovery did not work')
                return
        passK = passK[18:]
        try:
            hashArray = database_operations.query_chunk_table_for_transaction(transaction_num)
        except RuntimeError as e:
            if(str(e) == "Please initialize database"):
                if(self.args.chunkFile != "NA"):
                    with open(self.args.chunkFile, 'r') as chunkFile:
                        chunks = [line.strip() for line in chunkFile]
                        chunks = [chunk for chunk in chunks if chunk != ""]
                    hashArray = [[chunk] for chunk in chunks]
                else:
                    print("Please provide the hashes of the encrypted chunks")
                    return
        if(len(hashArray) == 0):
            if(self.args.chunkFile != "NA"):
                    with open(self.args.chunkFile, 'r') as chunkFile:
                        chunks = [line.strip() for line in chunkFile]
                    hashArray = [[chunk] for chunk in chunks]
            else:
                print("Please provide the hashes of the encrypted chunks")
                return
        if(len(hashArray) != number+1):
            print("Incorrect number of chunks found, cannot decrypt")
            return
        a = number
        decrypted_chunks = []
        binary_files = []
        for filename in os.listdir(self.args.storage):
            if filename.endswith('.bin') and transaction_num in filename:
                filepath = os.path.join(self.args.storage, filename)
                with open(filepath, 'rb') as f:
                    content = f.read()
                    binary_files.append(content)
        if(len(binary_files) != number+1 or name_of_file == ''):
            binary_files = []
            for filename in os.listdir(self.args.storage):
                if filename.endswith('.bin'):
                    filepath = os.path.join(self.args.storage, filename)
                    with open(filepath, 'rb') as f:
                        num = f.read(82)
                        if(num[:18] == transaction_num.encode()):
                            binary_files.append(num + f.read())
                            if(name_of_file == ''):
                                name_of_file = num[18:83].decode().rstrip('\x00')
        while(a >= 0):
            print('decrypted '+ str(a) +'th chunk')
            hash_to_find = hashArray[a][0]
            c = ""
            for content in binary_files:
                if(sha256(content).hexdigest() == hash_to_find):
                    c = content[82:]
                    break
            decrypted_chunk = ''
            try:
                decrypted_chunk = self.decodeWithPaddingDES(c, passK)
            except ValueError as e:
                if(str(e) == 'The key was incorrect'):
                    print('Wrong key')
                    return
            try:
                hash_object = sha256(decrypted_chunk)
            except TypeError as e:
                print('Cannot decrypt the file')
                return
            hash_value = hash_object.hexdigest()
            passK = hash_value
            decrypted_chunks.insert(0, decrypted_chunk)
            a-=1
        decrypted_chunks[0] = decrypted_chunks[0][16:]
        print('write the retrived text to result file...',end='')
        counter = 0
        print(name_of_file)
        name = name_of_file.rsplit(".", 1)[0]
        new_name = name
        file_extension = name_of_file.rsplit(".", 1)[1]
        while(os.path.exists(self.args.outputPath + '/' + new_name + "." + file_extension)):
            counter += 1
            new_name = name + str(counter)
        outputF = open(self.args.outputPath+'/'+ new_name + "." + file_extension, "wb")
        print(', path:'+self.args.outputPath+'/'+ new_name + "." + file_extension + "...",end='')
        for v in range(len(decrypted_chunks) - 1):
            outputF.write(decrypted_chunks[v])
        outputF.close()

        user_info = open(self.args.workingPath+'/'+"userInfo.txt", "r", encoding="utf-8")
        last_chunk = decrypted_chunks[len(decrypted_chunks) - 1]
        last_chunk += ("\n" + str(len(user_info.readlines()) -1) + ". ").encode("utf-8") +  username.encode("utf-8")
        user_info.close()
        user_info = open(self.args.workingPath+'/'+"userInfo.txt", "w", encoding="utf-8")
        user_info.write(str(last_chunk))
        user_info.close()

    def encodeWithPaddingAES(self, plaintext, password):
        '''Encoding method, AES CBC, takes plaintext and encodes it with a password. 
        It generates a random salt and IV, derives a key using PBKDF2, and encrypts the plaintext using AES in CBC mode. The salt and IV are appended to the ciphertext for storage.'''
        salt = get_random_bytes(16)
        iv = get_random_bytes(16)
        key = PBKDF2(password, salt, 16, count=1000000, hmac_hash_module=SHA256)
        encrypt_cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = encrypt_cipher.encrypt(pad(plaintext, 16))
        return ciphertext + salt + iv

    def decodeWithPaddingAES(self, data, password):
        '''Decoding method, takes the encrypted data and decrypts it using a password.	
        It retrieves the salt and IV from the data, derives the key using PBKDF2, and decrypts the ciphertext using AES in CBC mode. The decrypted message is unpadded before returning.'''
        salt = data[-32:-16]
        key = PBKDF2(password, salt, 16, count=1000000, hmac_hash_module=SHA256)
        iv = data[-16:]
        decrypt_cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = data[:-32]
        message = decrypt_cipher.decrypt(ciphertext)
        try:
            return unpad(message, 16)
        except:
            raise ValueError("The key was incorrect")


    def encrypt_AES(self, content, number, userId, transaction_num):
        '''Splits the content of the file in a number of chunks, then encrypts each one of them using the hash of the next as password The encryption algorithm used is AES. 
        Chunks are stored in the database if the database is initialized.'''
        filename = self.args.plainTextFileName
        if(len(filename) > 64):
            filename = filename[-64:]
        padded_filename = filename.ljust(64, '\x00')
        user_info = open(self.args.workingPath+'/'+'userInfo.txt', "rb")
        last_chunk = user_info.read()
        chunk_hashes_array = []
        user_info.seek(0)
        if (last_chunk == ""):
            last_chunk = "0. ".encode('utf-8') + userId.encode('utf-8')
        else:
            last_chunk += ("\n".encode('utf-8') + str(len(user_info.readlines())).encode('utf-8') + ". ".encode('utf-8')) + userId.encode('utf-8')
        user_info.close()
        if (len(last_chunk) > 50):
            open(self.args.workingPath+'/'+"userInfo.txt", "wb").close()
            last_chunk = "0. ".encode('utf-8') + userId.encode('utf-8')
        user_info = open(self.args.workingPath+'/'+"userInfo.txt", "wb")
        user_info.write(last_chunk)
        user_info.close()
        while(len(userId.encode('utf-8')) < 16):
            userId+= chr(0)
        chunks = []
        chunk_size = math.ceil(len(content)/number)
        i = 0
        while i < len(content):
            chunk = content[i:i+chunk_size]
            if (i == 0):
                chunk = userId.encode('utf-8') + chunk
            chunks.append(chunk)
            i = i + chunk_size
        chunks.append(last_chunk)
        chunk_hashes = []
        for j in range(len(chunks)):
            hash_object = sha256(chunks[j])
            hash_value = hash_object.hexdigest()
            chunk_hashes.append(hash_value)
        for k in range(len(chunks) - 1):
            f = open(self.args.storage+'/'+"chunk"+ str(k) + transaction_num + ".bin", "wb")
            chunk_to_write = transaction_num.encode() + padded_filename.encode() + self.encodeWithPaddingAES(chunks[k], chunk_hashes[k+1])
            try:
                database_operations.insert_chunk_table(transaction_num, sha256(chunk_to_write).hexdigest(), k)
            except RuntimeError as e:
                        if(str(e) == "Please initialize database"):
                            f.write(chunk_to_write)
                            f.close()
                            print(sha256(chunk_to_write).hexdigest())
                            chunk_hashes_array.append(sha256(chunk_to_write).hexdigest())
                            continue
                        else:
                            raise
            f.write(chunk_to_write)
            f.close()
        k = len(chunks) - 1
        extraF = open(self.args.storage+'/'+"chunk"+ str(k) + transaction_num + ".bin", "wb")
        chunk_to_write = transaction_num.encode() + padded_filename.encode() + self.encodeWithPaddingAES(chunks[k], chunk_hashes[0])
        try:
            database_operations.insert_chunk_table(transaction_num, sha256(chunk_to_write).hexdigest(), k)
        except RuntimeError as e:
                        if(str(e) == "Please initialize database"):
                            chunk_hashes_array.append(sha256(chunk_to_write).hexdigest())
                            print(sha256(chunk_to_write).hexdigest())
                        else:
                            raise
        extraF.write(chunk_to_write)
        extraF.close()
        return transaction_num+chunk_hashes[0], chunk_hashes_array
    
    def decrypt_no_database(self, passK, number, userId, username):
        transaction_num = passK[:18]
        name_of_file = ''
        passK = passK[18:]
        a = number
        decrypted_chunks = []
        binary_files = []
        for filename in os.listdir(self.args.storage):
            if filename.endswith('.bin') and transaction_num in filename:
                filepath = os.path.join(self.args.storage, filename)
                with open(filepath, 'rb') as f:
                    content = f.read()
                    binary_files.append(content)
        if(len(binary_files) != number+1 or name_of_file == ''):
            binary_files = []
            for filename in os.listdir(self.args.storage):
                if filename.endswith('.bin'):
                    filepath = os.path.join(self.args.storage, filename)
                    with open(filepath, 'rb') as f:
                        num = f.read(82)
                        if(num[:18] == transaction_num.encode()):
                            binary_files.append(num + f.read())
                            if(name_of_file == ''):
                                name_of_file = num[18:83].decode().rstrip('\x00')
        # last_chunk = self.decodeWithPadding(c, passK)
        
    def decrypt_AES(self, passK, number, userId, username):
        '''Decrypts the chunks it finds in the database; has to find the hash of the last chunk. If it does not find the database, it will look for the chunks in the storage folder.
        It will find the binary files and decrypt them using the password derived from the hash of the next chunk. The name of the file is also retrieved from the database or the file header.'''
        transaction_num = passK[:18]
        name_of_file = ''
        try:
            name_of_file = database_operations.query_for_file_name(transaction_num)
        except RuntimeError as e:
            if(str(e) == "Please initialize database"):
                name_of_file = ''
        except TypeError as e:
            if("object is not subscriptable" in str(e)):
                print('Secret recovery did not work')
                return
        passK = passK[18:]
        try:
            hashArray = database_operations.query_chunk_table_for_transaction(transaction_num)
        except RuntimeError as e:
            if(str(e) == "Please initialize database"):
                if(self.args.chunkFile != "NA"):
                    with open(self.args.chunkFile, 'r') as chunkFile:
                        chunks = [line.strip() for line in chunkFile]
                        chunks = [chunk for chunk in chunks if chunk != ""]
                    hashArray = [[chunk] for chunk in chunks]
                else:
                    print("Please provide the hashes of the encrypted chunks")
                    return
        if(len(hashArray) == 0):
            if(self.args.chunkFile != "NA"):
                    with open(self.args.chunkFile, 'r') as chunkFile:
                        chunks = [line.strip() for line in chunkFile]
                    hashArray = [[chunk] for chunk in chunks]
            else:
                print("Please provide the hashes of the encrypted chunks")
                return
        if(len(hashArray) != number+1):
            print("Incorrect number of chunks found, cannot decrypt")
            return
        a = number
        decrypted_chunks = []
        binary_files = []
        for filename in os.listdir(self.args.storage):
            if filename.endswith('.bin') and transaction_num in filename:
                filepath = os.path.join(self.args.storage, filename)
                with open(filepath, 'rb') as f:
                    content = f.read()
                    binary_files.append(content)
        if(len(binary_files) != number+1 or name_of_file == ''):
            binary_files = []
            for filename in os.listdir(self.args.storage):
                if filename.endswith('.bin'):
                    filepath = os.path.join(self.args.storage, filename)
                    with open(filepath, 'rb') as f:
                        num = f.read(82)
                        if(num[:18] == transaction_num.encode()):
                            binary_files.append(num + f.read())
                            if(name_of_file == ''):
                                name_of_file = num[18:83].decode().rstrip('\x00')
        while(a >= 0):
            print('decrypted '+ str(a) +'th chunk')
            hash_to_find = hashArray[a][0]
            c = ""
            for content in binary_files:
                if(sha256(content).hexdigest() == hash_to_find):
                    c = content[82:]
                    break
            decrypted_chunk = ''
            try:
                decrypted_chunk = self.decodeWithPaddingAES(c, passK)
            except ValueError as e:
                if(str(e) == 'The key was incorrect'):
                    print('Wrong key')
                    return
            try:
                hash_object = sha256(decrypted_chunk)
            except TypeError as e:
                print('Cannot decrypt the file')
                return
            hash_value = hash_object.hexdigest()
            passK = hash_value
            decrypted_chunks.insert(0, decrypted_chunk)
            a-=1
        decrypted_chunks[0] = decrypted_chunks[0][16:]
        print('write the retrived text to result file...',end='')
        counter = 0
        print(name_of_file)
        name = name_of_file.rsplit(".", 1)[0]
        new_name = name
        file_extension = name_of_file.rsplit(".", 1)[1]
        while(os.path.exists(self.args.outputPath + '/' + new_name + "." + file_extension)):
            counter += 1
            new_name = name + str(counter)
        outputF = open(self.args.outputPath+'/'+ new_name + "." + file_extension, "wb")
        print(', path:'+self.args.outputPath+'/'+ new_name + "." + file_extension + "...",end='')
        for v in range(len(decrypted_chunks) - 1):
            outputF.write(decrypted_chunks[v])
        outputF.close()

        user_info = open(self.args.workingPath+'/'+"userInfo.txt", "r", encoding="utf-8")
        last_chunk = decrypted_chunks[len(decrypted_chunks) - 1]
        last_chunk += ("\n" + str(len(user_info.readlines()) -1) + ". ").encode("utf-8") +  username.encode("utf-8")
        user_info.close()
        user_info = open(self.args.workingPath+'/'+"userInfo.txt", "w", encoding="utf-8")
        user_info.write(str(last_chunk))
        user_info.close()



    def hash_verification(self, file_1_name, file_2_name):
        '''Verifies if the two files are identical by comparing their hash values.'''	
        file1 = open(self.args.workingPath + '/' + file_1_name, "r", encoding="utf-8")
        file1_content = file1.read()
        file1.close()
        file2 = open(self.args.workingPath + '/' + file_2_name, "r", encoding="utf-8").read()
        file2_content = file2.read()
        file2.close()
        return hash(file1_content) == hash(file2_content)

    def output_summary(self):
        '''Generates a summary of the chunks in the encryption and their hash values. It creates a file named outputSummary.txt in the working path. 
        The file contains the hash algorithm, encryption algorithm, number of chunks, and the hash values of each chunk.'''
        file = open(self.args.workingPath + '/' + "outputSummary.txt", "w", encoding="utf-8")
        file.write("HASH ALGORITHM: SHA256 \nENCRYPTION ALGORITHM: AES128, MODE CBC \nNUM_CHUNKS: " + str(self.args.numChunks))
        for i in range(self.args.numChunks + 1):
            f = open(self.args.workingPath+'/'+"chunk"+ str(i) + ".bin", "rb")
            c = f.read()
            hash_object = sha256(c)
            hash_value = hash_object.hexdigest()
            file.write("\nHash of binary chunk " + str(i) + ": " + hash_value)
            f.close()
        file.close()

    def load_summary(self):
        '''Reads the hash values from the outputSummary.txt file. The hash values are used to identify potentially renamed chunks in the decrypt method.'''	
        file = open(self.args.workingPath + '/' + "outputSummary.txt", "r", encoding="utf-8")
        file.readline()
        file.readline()
        file.readline()
        hashv = []
        while True:
            line = file.readline()
            if not line:
                break
            else:
                t1 = line.split(": ")
                hashv.append(t1[1].rstrip("\n"))

        file.close()
        return hashv

    def encrypt_workflow(self):
        '''Main function for the encryption workflow. It generates a transaction number, and encrypts the file using the specified algorithm.
        It also handles secret sharing if specified. The function returns the credential of the last chunk and the shares generated, if any.'''
        tracemalloc.start()
        start_time = time.time()
        transaction_num = int(datetime.now().strftime('%Y%m%d%H%M%S'))
        random_digits = ''.join([str(random.randint(0, 9)) for _ in range(4)])
        transaction_num = str(transaction_num)+str(random_digits)
        try:
            database_operations.insert_transaction_file_table(transaction_num, self.args.plainTextFileName)
        except RuntimeError as e:
            if(str(e) == "Please initialize database"):
                print("No database :(")
                print("PASTE THE FOLLOWING VALUES TO A TXT FILE (WITHOUT SECRET SHARES), EACH ONE ON A DIFFERENT LINE! DECRYPTION IS NOT POSSIBLE OTHERWISE, AS YOU HAVE NOT INITIALIZED A DATABASE")
            else:
                raise
        inputFile = open(self.args.workingPath + '/' + self.args.plainTextFileName, "rb")
        content = inputFile.read()
        if not os.path.exists(self.args.workingPath + '/' + 'userInfo.txt'):
            print('create a new user access list:' + self.args.workingPath + '/' + 'userInfo.txt')
            with open(self.args.workingPath + '/' + 'userInfo.txt', 'w') as file:
                file.write("Users: ")
                file.close()
        if (self.args.algorithm == 'AES'):
            credential_last_chunk, hash_array = self.encrypt_AES(content, self.args.numChunks, self.args.ownerID, transaction_num)
        elif (self.args.algorithm == 'DES'):
            credential_last_chunk, hash_array = self.encrypt_DES(content, self.args.numChunks, self.args.ownerID, transaction_num)
        elif (self.args.algorithm == 'Blowfish'):
            credential_last_chunk, hash_array = self.encrypt_Blowfish(content, self.args.numChunks, self.args.ownerID, transaction_num)
        elif (self.args.algorithm == 'Twofish'):
            credential_last_chunk, hash_array = self.encrypt_Twofish(content, self.args.numChunks, self.args.ownerID, transaction_num)
        else:
            print('Algorithm not supported')
            return
        sharing_has_been_called = False
        print('\n')
        if (self.args.shares == 0 or self.args.shares == 1):
            print('no secret sharing applied \n')
        elif (self.args.shares > 1):
            units = self.args.sharingUnits.split("-")
            if (len(units) != self.args.shares):
                print('The number of units does not match the number of shares')          
                return
            shares = SecretSharer.split_secret(credential_last_chunk, self.args.confidentialLevel, self.args.shares)
            f = open(self.args.workingPath + '/' + "secretShares" + ".txt", "w")
            i = 0
            for s in shares:
                if (units[0] != ''):
                    f.write(units[i] + ": " + s + "\n")
                    try:
                        database_operations.insert_property_table_3(transaction_num, i, units[i])
                    except RuntimeError as e:
                        if(str(e) == "Please initialize database"):
                            pass
                        else:
                            raise
                    print('Secret share ' + str(i+1) + ' (' + units[i] + ') is ' + str(s))
                else:
                    try:
                        database_operations.insert_property_table_2(transaction_num, i)
                    except RuntimeError as e:
                        if(str(e) == "Please initialize database"):
                            pass
                        else:
                            raise
                    print('Secret share ' + str(i+1)  +' is ' + str(s))
                try:
                    database_operations.insert_secret_key_table(transaction_num, i, s)
                except RuntimeError as e:
                    if(str(e) == "Please initialize database"):
                        pass
                    else:
                        raise
                i += 1
            f.close()
            sharing_has_been_called = True
        else:
            None
        print('the credential of the last chunk:' + credential_last_chunk)
        if sharing_has_been_called == True:
            end_time = time.time()
            print(end_time - start_time)
            current, peak = tracemalloc.get_traced_memory() 
            tracemalloc.stop()
            print(f"Current memory usage: {current / 1024} KB")
            print(f"Peak memory usage: {peak / 1024} KB")
            return shares
        else:
            end_time = time.time()
            print(end_time - start_time)
            current, peak = tracemalloc.get_traced_memory() 
            tracemalloc.stop()
            print(f"Current memory usage: {current / 1024} KB")
            print(f"Peak memory usage: {peak / 1024} KB")
            return credential_last_chunk
        
    def decrypt_in_browser(self, passK, number, userId, username):
        '''This method is used for the web client version of the application. 
        Decrypts the chunks it finds in the database; has to find the hash of the last chunk. If it does not find the database, it will look for the chunks in the storage folder.
        It will find the binary files and decrypt them using the password derived from the hash of the next chunk. The name of the file is also retrieved from the database or the file header.'''
        transaction_num = passK[:18]
        name_of_file = ''
        try:
            name_of_file = database_operations.query_for_file_name(transaction_num)
        except (RuntimeError, TypeError) as e:
            if(str(e) == "Please initialize database" or "object is not subscriptable" in str(e)):
                name_of_file = ''
        passK = passK[18:]
        try:
            hashArray = database_operations.query_chunk_table_for_transaction(transaction_num)
        except RuntimeError as e:
            if(str(e) == "Please initialize database"):
               with open(self.args.chunkFile, 'r') as chunkFile:
                    chunks = [line.strip() for line in chunkFile]
                    chunks = [chunk for chunk in chunks if chunk != ""]
               hashArray = [[chunk] for chunk in chunks] 
        if(len(hashArray) == 0):
            if(self.args.chunkFile != "NA"):
                    with open(self.args.chunkFile, 'r') as chunkFile:
                        chunks = [line.strip() for line in chunkFile]
                        chunks = [chunk for chunk in chunks if chunk != ""]
                    hashArray = [[chunk] for chunk in chunks]
        a = number
        decrypted_chunks = []
        binary_files = []
        for filename in os.listdir(self.args.storage):
            if filename.endswith('.bin') and transaction_num in filename:
                filepath = os.path.join(self.args.storage, filename)
                with open(filepath, 'rb') as f:
                    content = f.read()
                    binary_files.append(content)
        if(len(binary_files) != number+1 or name_of_file == ''):
            binary_files = []
            for filename in os.listdir(self.args.storage):
                if filename.endswith('.bin'):
                    filepath = os.path.join(self.args.storage, filename)
                    with open(filepath, 'rb') as f:
                        num = f.read(82)
                        if(num[:18] == transaction_num.encode()):
                            binary_files.append(num + f.read())
                            if(name_of_file == ''):
                                name_of_file = num[18:83].decode().rstrip('\x00')
        while(a >= 0):
            hash_to_find = hashArray[a][0]
            c = ""
            for content in binary_files:
                if(sha256(content).hexdigest() == hash_to_find):
                    c = content[82:]
                    break
            decrypted_chunk = self.decodeWithPaddingAES(c, passK)
            hash_object = sha256(decrypted_chunk)
            hash_value = hash_object.hexdigest()
            passK = hash_value
            decrypted_chunks.insert(0, decrypted_chunk)
            a-=1
        decrypted_chunks[0] = decrypted_chunks[0][16:]
        file = BytesIO()
        for v in range(len(decrypted_chunks) - 1):
            file.write(decrypted_chunks[v])
        file.seek(0)
        with open("output.txt", "wb") as f:
            f.write(file.getvalue())
        user_info = open(self.args.workingPath+'/'+"userInfo.txt", "r", encoding="utf-8")
        last_chunk = decrypted_chunks[len(decrypted_chunks) - 1]
        last_chunk += ("\n" + str(len(user_info.readlines()) -1) + ". ").encode("utf-8") +  username.encode("utf-8")
        user_info.close()
        user_info = open(self.args.workingPath+'/'+"userInfo.txt", "w", encoding="utf-8")
        user_info.write(str(last_chunk))
        user_info.close()
        return file.getvalue(), name_of_file
    

    def decrypt_workflow(self):
        '''Main function for the decryption workflow. It decrypts the file using the specified algorithm and handles secret recovery if necessary.'''
        tracemalloc.start()
        start_time = time.time()
        print('start to decrypt the given plain text')
        key = self.args.key
        if(self.args.secrets != 'NA'):
            shares = self.args.secrets
            shares = shares.split(',')
            secret = SecretSharer.recover_secret(shares)
            key = secret
        elif(self.args.properties != 'NA'):
            try:
                properties = self.args.properties
                properties = properties.split(',')
                shares = []
                for p in properties:
                    shares.append(database_operations.query_for_secret_key(self.args.transaction, p))
                secret = SecretSharer.recover_secret(shares)
                key = secret
            except TypeError as e:
                if(str(e) == '\'NoneType\' object is not subscriptable'):
                    print('Incorrect property name')
                    return
        if (self.args.algorithm == 'AES'):
            self.decrypt_AES(key, self.args.numChunks, self.args.ownerID, self.args.userName)
        elif (self.args.algorithm == 'DES'):
            self.decrypt_DES(key, self.args.numChunks, self.args.ownerID, self.args.userName)
        elif (self.args.algorithm == 'Blowfish'):
            self.decrypt_Blowfish(key, self.args.numChunks, self.args.ownerID, self.args.userName)
        elif (self.args.algorithm == 'Twofish'):
            self.decrypt_Twofish(key, self.args.numChunks, self.args.ownerID, self.args.userName)
        else:
            print("Algorithm not supported")
            return
        end_time = time.time()
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        user_info = open(self.args.workingPath+'/'+"userInfo.txt", "r", encoding="utf-8")
        print('\nPrevious users: ')
        print(user_info.readlines())
        user_info.close()
        print(end_time - start_time)
        print(f"Current memory usage: {current / 1024} KB")
        print(f"Peak memory usage: {peak / 1024} KB")


    def decrypt_workflow_from_browser(self):
        '''Main function for the decryption workflow from the web client. It decrypts the file using the specified algorithm and handles secret recovery if necessary.'''	
        set_working_path(self.args)

        set_storage_path(self.args)

        set_output_path(self.args)
        key = self.args.key
        print("hello")
        if (self.args.secret_shares != ''):
            shares = self.args.secret_shares.split(',')
            print(shares)
            secret = SecretSharer.recover_secret(shares)
            key = secret
        elif (self.args.properties != ''):
            properties = self.args.properties.split(',')
            shares = []
            for p in properties:
                shares.append(database_operations.query_for_secret_key(self.args.transaction, p))
            secret = SecretSharer.recover_secret(shares)
            key = secret
        content = self.decrypt_in_browser(key, self.args.numChunks, self.args.ownerID, self.args.userName)
        return content

    def recovery_secret_workflow(self):
        '''Main function for the secret recovery workflow. It recovers the secret using the provided shares.'''	
        if self.args.callFromGUI == False:
            shares = self.args.secrets
            shares = shares.split(',')
            secret = SecretSharer.recover_secret(shares)
            print(secret)
            return secret
        else:
            shares = self.secrets.split(',')
            secret = SecretSharer.recover_secret(shares)
            print(secret)
            self.recovered_secret = secret
            return

    def recovery_secret_via_property_name(self):
        '''Main function for the secret recovery workflow using property names. It recovers the secret using the provided property names.'''
        if self.args.callFromGUI == False:
            properties = self.args.properties
            properties = properties.split(',')
            shares = []
            for p in properties:
                shares.append(database_operations.query_for_secret_key(self.args.transaction, p))
            secret = SecretSharer.recover_secret(shares)
            print(secret)
            return secret
        else:
            properties = self.properties.split(',')
            shares = []
            for p in properties:
                shares.append(database_operations.query_for_secret_key(self.args.transaction, p))
            secret = SecretSharer.recover_secret(shares)
            print(secret)
            self.recovered_secret = secret
            return secret

    def initialize_db_workflow(self):
        '''It initializes the database and creates the necessary tables.'''	
        database_operations.init_db()
        print("Database successfully initiated")

    def encrypt_workflow_uploaded_file(self, content):
        '''Main function for the encryption workflow with uploaded files. It generates a transaction number, and encrypts the file using the specified algorithm.
        It also handles secret sharing if specified. The function returns the credential of the last chunk and the shares generated, if any.'''
        set_working_path(self.args)
        set_storage_path(self.args)
        set_output_path(self.args)
        transaction_num = int(datetime.now().strftime('%Y%m%d%H%M%S'))
        random_digits = ''.join([str(random.randint(0, 9)) for _ in range(4)])
        transaction_num = str(transaction_num)+str(random_digits)
        try:
            database_operations.insert_transaction_file_table(transaction_num, self.args.plainTextFileName)
        except RuntimeError as e:
            if(str(e) != "Please initialize database"):
                raise
        if not os.path.exists(self.args.workingPath + '/' + 'userInfo.txt'):
            with open(self.args.workingPath + '/' + 'userInfo.txt', 'w') as file:
                file.write("Users: ")
                file.close()

        credential_last_chunk, hash_array = self.encrypt_AES(content, self.args.numChunks, self.args.ownerID, transaction_num)

        sharing_has_been_called = False

        chunk_dict = dict()
        chunk_dict[0] = credential_last_chunk

        if (self.args.shares == 0 or self.args.shares == 1):
            return chunk_dict, hash_array
        else:
            shares = SecretSharer.split_secret(credential_last_chunk, self.args.confidentialLevel, self.args.shares)
            f = open(self.args.workingPath + '/' + "secretShares" + ".txt", "w")
            units = self.args.sharingUnits.split("-")
            i = 0
            for s in shares:
                if (units[0] != ''):
                    f.write(units[i] + ": " + s + "\n")
                    try:
                        database_operations.insert_property_table_3(transaction_num, i, units[i])
                    except RuntimeError as e:
                        if(str(e) != "Please initialize database"):
                            raise
                else:
                    try:
                        database_operations.insert_property_table_2(transaction_num, i)
                    except RuntimeError as e:
                        if(str(e) != "Please initialize database"):
                            raise
                try:
                    database_operations.insert_secret_key_table(transaction_num, i, s)
                except RuntimeError as e:
                    if(str(e) != "Please initialize database"):
                        raise
                chunk_dict[i+1] = s
                i += 1
            f.close()
            sharing_has_been_called = True
            return chunk_dict, hash_array, units

    def launch(self):

        set_working_path(self.args)

        set_storage_path(self.args)

        set_output_path(self.args)

        if self.args.mode.lower() == 'encrypt':
            ret = self.encrypt_workflow()
            return ret
        elif self.args.mode.lower() == 'decrypt':
            self.decrypt_workflow()
        elif self.args.mode.lower() == 'recover_secret':
            self.recovery_secret_workflow()
        elif self.args.mode.lower() == 'recover_secret_prop':
            self.recovery_secret_via_property_name()
        elif self.args.mode.lower() == 'init_db':
            self.initialize_db_workflow()
        else:
            print("unknown mode")

def main():

    args = loading_args()
    sedss = self_encryption_decryption_inf_sharing(args)
    sedss.launch()

if __name__ == '__main__':
    main()