#!/usr/bin/env python3
#Author: Chanchai Lee
#The purpose of this project is to create secure file sharing by using Dropbox API and python
# 1.Do convergent encryption of a file prior to uploading
# 2.Decrypte a file upon downloading
#Refercenes:
# https://gist.github.com/lkdocs/6519359
# https://stackoverflow.com/questions/606191/convert-bytes-to-a-string
# https://www.dlitz.net/software/pycrypto/api/current/Crypto.Util.Counter-module.html
# https://www.datacamp.com/community/tutorials/functions-python-tutorial
# https://www.laurentluce.com/posts/python-and-cryptography-with-pycrypto/#a_3
# https://stackoverflow.com/questions/21327491/using-pycrypto-how-to-import-a-rsa-public-key-and-use-it-to-encrypt-a-string?utm_medium=organic&utm_source=google_rich_qa&utm_campaign=google_rich_qa
import dropbox, hashlib, os,codecs,requests
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Util import Counter
from dropbox.files import WriteMode
from dropbox.exceptions import ApiError, AuthError

def readInputFile():
    f = open("input.txt","r")
    input = f.read()
    print("Input:")
    print(input)
    print("\n\n")
    return input

def createKeyandHash(input):
    hash_object = hashlib.sha256(input.encode('utf-8'))
    K = hash_object.hexdigest()
    H = hash_object.hexdigest()
    print("Return K:")
    print(K)
    print("\n\n")
    print("Return H:")
    print(H)
    print("\n\n")
    return K,H

def createCiphertext(K,input):
    #IV = Initial Vector for Counter Mode Prefix
    random_generator = Random.new()
    IV = random_generator.read(8)
    keye = (K)[:32] # keye would be from index 0 to 32
    ctr_e = Counter.new(64, prefix=IV)
    encryptor = AES.new(keye, AES.MODE_CTR, counter=ctr_e)
    ciphertext = encryptor.encrypt(input)
    print("Return IV:")
    print(IV)
    print("\n\n")
    print("Return ciphertext:")
    print(ciphertext)
    print("\n\n")
    return IV+ciphertext

def createRSAKeys():
    random_generator = Random.new().read
    # Note : key = private key,
    #       key.publickey() = public_key
    key = RSA.generate(1024, random_generator)
    public_key = key.publickey()
    return key, public_key

def encryptedKeywithRSA(K,public_key):
    # Input: K
    # Output: W (K encrypted with public_key)
    # Ref: https://www.laurentluce.com/posts/python-and-cryptography-with-pycrypto/#a_3

    W = public_key.encrypt(K.encode('utf-8'), 32)
    print("Public-Key:")
    print(public_key)
    print("\n\n")
    print("Encrypted(K)=W:")
    print(W)
    print("\n\n")
    return W

def connectToDropbox():
    # Read Dropbox Access token from text file and store as a list of object
    f = open('../token.txt', 'r')
    token = f.readlines()
    #Connect to Dropbox application with access token
    dbx = dropbox.Dropbox(token[0])
    #get dropbox user account
    dbx_user = dbx.users_get_current_account()
    return dbx

def uploadDatatoDropbox(dbx,data,filename):

    try:
        dbx.files_upload(data, filename, mode=WriteMode('overwrite'))
        print("Finished Upload. File location:"+filename+"\n");
    except dropbox.exceptions.HttpError as err:
        print('HttpError', err)
    return None

def downloadFileFromDropbox(dbx,path):
    try:
        md, res = dbx.files_download(path)
    except dropbox.exceptions.HttpError as err:
        print('HttpError', err)

    data = res.content
    print ("Downdloaded Data")
    # print(len(data), 'bytes; md:', md)
    print(data)
    print("Data Dropbox URL:")
    # print(dbx.sharing_get_file_metadata(path))
    print(dbx.sharing_get_file_metadata(path).preview_url)
    print("\n\n")
    return data,dbx.sharing_get_file_metadata(path).preview_url

def main():
    #0.Read input file
    input = readInputFile()
    #Encryption
    #1.Create K by hash input file with sha256
    K,H = createKeyandHash(input)
    #2 Create Cipher text C with AES Counter mode
    ciphertext = createCiphertext(K,input)

    #3 Encrypt K with the sender's RSA public key
    f = open('./Alice_private.key','r')
    sender_private_key = f.read()
    sender_private_key = RSA.importKey(sender_private_key)

    f = open('./Alice_public.key','r')
    sender_public_key = f.read()
    sender_public_key = RSA.importKey(sender_public_key)


    W = encryptedKeywithRSA(K,sender_public_key)
    #4 Upload Ciphertext (C) and W to dropbox
    dbx=connectToDropbox()
    #upload ciphertext to dropbox
    uploadDatatoDropbox(dbx,ciphertext,'/A2/C')
    #upload W to dropbox
    uploadDatatoDropbox(dbx,W[0],'/A2/W')
    #upload Hash Value of the plain text to dropbox for Server Deduplication checking in the future
    uploadDatatoDropbox(dbx,H,'/A2/H')

    #Decryption
    #1. Downloading C and W from dropbox
    print("Downdloaded CipherText Details:")
    dl_C,cipher_url =  downloadFileFromDropbox(dbx,'/A2/C')
    print("CiphetText URL: " + cipher_url)
    print("\n\n")
    print("Downdloaded W Details:")
    dl_W,W_url =  downloadFileFromDropbox(dbx,'/A2/W')

    #2. Extract Key K from W by using RSA decryption.
    decrypted_W = sender_private_key.decrypt(dl_W)
    print("Decrypted Key:")
    print(decrypted_W)
    print("\n\n")

    #3.Decypteing the chiphertext C with AES-CTR withd decrypted_W=K
    keyd = (decrypted_W)[:32]
    IV=(dl_C)[:8]
    dl_C=(dl_C)[8:]
    # Create counter for decryptor with IV
    ctr_d = Counter.new(64, prefix=IV)

    # Create decryptor, then decrypt and print decoded text
    decryptor = AES.new(keyd, AES.MODE_CTR, counter=ctr_d)
    decrypted_text = decryptor.decrypt(dl_C)
    print ("Decrypted Data:\n"+decrypted_text.decode('utf-8'))

    #Write Output to file
    f= open("./decrypted_data_by_Sender","w+")
    f.write(decrypted_text.decode('utf-8'))
    f.close()



if __name__ == '__main__':
    main()
