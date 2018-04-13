#!/usr/bin/env python3

#Author: Chanchai Lee

#The purpose of this project is to create secure file sharing by using Dropbox API and python

#Refercenes:
# https://gist.github.com/lkdocs/6519359
# https://stackoverflow.com/questions/606191/convert-bytes-to-a-string
# https://www.dlitz.net/software/pycrypto/api/current/Crypto.Util.Counter-module.html
# https://www.datacamp.com/community/tutorials/functions-python-tutorial
# https://www.laurentluce.com/posts/python-and-cryptography-with-pycrypto/#a_3

import dropbox, hashlib, os,codecs
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
    print("Return K===================================")
    print(K)
    print("\n\n")
    print("Return H===================================")
    print(H)
    print("\n\n")
    return K,H

def createCiphertext(K,input):
    #IV = Initial Vector for Counter Mode Prefix
    random_generator = Random.new()
    IV = random_generator.read(8)
    keye = (K)[:32]
    ctr_e = Counter.new(64, prefix=IV)
    encryptor = AES.new(keye, AES.MODE_CTR, counter=ctr_e)
    ciphertext = encryptor.encrypt(input)
    print("Return IV===================================")
    print(IV)
    print("\n\n")
    print("Return ciphertext===================================")
    print(ciphertext)
    print("\n\n")
    return IV,ciphertext

def encryptedKeywithRSA(K):
    # Input: K
    # Output: Sender's private key,Sender's public key,W
    # Ref: https://www.laurentluce.com/posts/python-and-cryptography-with-pycrypto/#a_3
    #ba = bitarray.bitarray()
    #key = RSA.generate(1024,ba.frombytes(key1.encode('utf-8')))

    random_generator = Random.new().read
    # Note : key = private key,
    #       key.publickey() = public_key
    key = RSA.generate(1024, random_generator)
    public_key = key.publickey()
    W = public_key.encrypt(K.encode('utf-8'), 32)

    print("Private-Key:")
    print(key)
    print("\n\n")
    print("Public-Key:")
    print(public_key)
    print("\n\n")
    print("Encrypted(K)=W:")
    print(W)
    print("\n\n")

    # print("W is")
    # print(W)
    # print(type(W))
    # print(type(W[0]))
    return key,public_key,W

def connectToDropbox():
    # Read Dropbox Access token from text file and store as a list of object
    f = open('../token.txt', 'r')
    token = f.readlines()
    #Connect to Dropbox application with access token
    dbx = dropbox.Dropbox(token[0])
    #get dropbox user account
    dbx_user = dbx.users_get_current_account()
    return dbx

def uploadCipherAndWtoDropbox(dbx,ciphertext,W):

    #Upload C (CipherText)
    ciphertext_fileName='/A2/C'
    dbx.files_upload(ciphertext, ciphertext_fileName, mode=WriteMode('overwrite'))
    print("Finished Upload C(CipherText). File location: /A2/C\n");

    #Upload W(Encrypted Key)
    encrypted_key_fileName='/A2/W'
    dbx.files_upload(W[0], encrypted_key_fileName, mode=WriteMode('overwrite'))
    print("Finished Upload W(Key Encryption). File location: /A2/W\n\n")

def downloadFileFromDropbox(dbx,path):
    try:
        md, res = dbx.files_download(path)
    except dropbox.exceptions.HttpError as err:
        print('*** HTTP error', err)

    data = res.content
    print ("Downdloaded Data")
    # print(len(data), 'bytes; md:', md)
    print(data)
    print("Data Dropbox URL:")
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
    IV,ciphertext = createCiphertext(K,input)
    #3 Encrypt K with the sender's RSA public key
    key,public_key,W = encryptedKeywithRSA(K)
    #4 Upload Ciphertext (C) and W to dropbox
    dbx=connectToDropbox()
    uploadCipherAndWtoDropbox(dbx,ciphertext,W)
    #__________________________________________________________________________________________

    #Decryption
    #1. Downloading C and W from dropbox
    print("Downdloaded CipherText Details:")
    dl_C,cipher_url =  downloadFileFromDropbox(dbx,'/A2/C')
    print("Downdloaded W Details:")
    dl_W,W_url =  downloadFileFromDropbox(dbx,'/A2/W')
    #2. Extract Key K from W by using RSA decryption.
    decrypted_W = key.decrypt(dl_W)
    print("Decrypted Key:")
    print(decrypted_W)
    print("\n\n")
    #3.Decypteing the chiphertext C with AES-CTR withd decrypted_W=K
    keyd = (decrypted_W)[:32]
    # Create counter for decryptor with IV
    ctr_d = Counter.new(64, prefix=IV)
    # Create decryptor, then decrypt and print decoded text
    decryptor = AES.new(keyd, AES.MODE_CTR, counter=ctr_d)
    decoded_text = decryptor.decrypt(dl_C)
    print ("Decrypted Data:\n"+decoded_text.decode('utf-8'))
    #__________________________________________________________________________________________

    # Secure File Sharing
    #1. Fetch W from URL

if __name__ == '__main__':
    main()
