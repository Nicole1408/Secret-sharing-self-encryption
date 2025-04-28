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
from Crypto.Cipher import DES
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

#step 1: merge your cureent version with the object-oriented idea \/
#step 2: implement the database stuff (also for decryption) in the obj-oriented version  \/
#step 3: test the working path function  \/
#step 4: GUI (specify path or upload data via a button from local environment)

# store name of encrypted data based on transaction number in db

# Arguments for command line
def loading_args():
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
    parser.add_argument('--properties', type=str, default='NA')
    # parser.add_argument('--storage', type=str)
    # parser.add_argument('--outputPath', type=str)
    parser.add_argument('--transaction', type=str)
    #parser.add_argument('--hashArray', type=str, default='NA', help="Values of the hashes of the encryption chunk, seprated by -")
    parser.add_argument('--chunkFile', type=str, default='NA', help="path to the file where the hash values of the encrypted chunks are stored")
    args = parser.parse_args()
    return args


class self_encryption_decryption_inf_sharing:


    args = None

    def __init__(self, args):
        self.args = copy.deepcopy(args)

    def set_secrets(self, secrets):
        self.secrets = secrets

    def set_properties(self, properties):
        self.properties = properties

    # Encoding method, DES CBC, takes plaintext and encodes it with a password
    def encodeWithPadding(self, plaintext, password):
        salt = get_random_bytes(16)
        iv = get_random_bytes(8)
        key = PBKDF2(password, salt, 8, count=1000000, hmac_hash_module=SHA256)
        encrypt_cipher = DES.new(key, DES.MODE_CBC, iv)
        ciphertext = encrypt_cipher.encrypt(pad(plaintext, 8))
        return ciphertext + salt + iv

    # Decoding method, takes the encrypted data and decrypts it using a password
    def decodeWithPadding(self, data, password):
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


    # Splits the content of the file in a number of chunks, then encrypts each one of them using the hash of the next as password
    def encrypt(self, content, number, userId, transaction_num):
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
            chunk_to_write = transaction_num.encode() + padded_filename.encode() + self.encodeWithPadding(chunks[k], chunk_hashes[k+1])
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
        chunk_to_write = transaction_num.encode() + padded_filename.encode() + self.encodeWithPadding(chunks[k], chunk_hashes[0])
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

    # Decrypts the chunks it finds in the database; has to find the hash of the last chunk
    def decrypt(self, passK, number, userId, username):
        transaction_num = passK[:18]
        name_of_file = ''
        try:
            name_of_file = database_operations.query_for_file_name(transaction_num)
        except RuntimeError as e:
            if(str(e) == "Please initialize database"):
                name_of_file = ''
                # if((self.args.properties != 'NA' and self.args.secrets == 'NA') or (self.args.secrets != 'NA' and self.args.properties == 'NA')):
                #     print('Secret recovery did not work')
                #     return
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
                decrypted_chunk = self.decodeWithPadding(c, passK)
            except ValueError as e:
                if(str(e) == 'The key was incorrect'):
                    print('Wrong key')
                    return
            hash_object = sha256(decrypted_chunk)
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


    # Opens the file and reads the content to be encrypted. If secret sharing is used, it also generates the secrets
    def encrypt_workflow(self):
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
        # print('start to encrypt the given plain text')
        inputFile = open(self.args.workingPath + '/' + self.args.plainTextFileName, "rb")
        content = inputFile.read()
        if not os.path.exists(self.args.workingPath + '/' + 'userInfo.txt'):
            print('create a new user access list:' + self.args.workingPath + '/' + 'userInfo.txt')
            with open(self.args.workingPath + '/' + 'userInfo.txt', 'w') as file:
                file.write("Users: ")
                file.close()

        credential_last_chunk, hash_array = self.encrypt(content, self.args.numChunks, self.args.ownerID, transaction_num)

        sharing_has_been_called = False
        print('\n')
        if (self.args.shares == 0 or self.args.shares == 1):
            print('no secret sharing applied \n')
        elif (self.args.shares > 1):
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
        # self.output_summary()
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
        

    # Handles decryption
    def decrypt_workflow(self):
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
        try:
            hashArray = database_operations.query_chunk_table_for_transaction(key[:18])
            self.decrypt(key, self.args.numChunks, self.args.ownerID, self.args.userName)
        except RuntimeError as e:
            if(str(e) == "Please initialize database"):
                self.decrypt_no_database(key, self.args.numChunks, self.args.ownerID, self.args.userName)
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


    # Initializes the database
    def initialize_db_workflow(self):
        database_operations.init_db()
        print("Database successfully initiated")
      

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
        # elif self.args.mode.lower() == 'encrypt_uploaded_file':
        #     self.encrypt_uploaded()
        else:
            # raise Exception('error, unknown working mode, should be encrypt, decrypt or recover_secret')
            print("unknown mode")

def main():

    args = loading_args()
    sedss = self_encryption_decryption_inf_sharing(args)
    sedss.launch()

if __name__ == '__main__':
    main()