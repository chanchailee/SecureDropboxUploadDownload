#!/usr/bin/env python3
#Author: Chanchai Lee
#The purpose of this file is to create secure file sharing by using Dropbox API and python
# 1.Do convergent encryption of a file prior to uploading
# 2.Decrypte a file upon downloading
#Refercenes:
# https://gist.github.com/lkdocs/6519359
# https://stackoverflow.com/questions/606191/convert-bytes-to-a-string
# https://www.dlitz.net/software/pycrypto/api/current/Crypto.Util.Counter-module.html
# https://www.datacamp.com/community/tutorials/functions-python-tutorial
# https://www.laurentluce.com/posts/python-and-cryptography-with-pycrypto/#a_3
# https://stackoverflow.com/questions/21327491/using-pycrypto-how-to-import-a-rsa-public-key-and-use-it-to-encrypt-a-string?utm_medium=organic&utm_source=google_rich_qa&utm_campaign=google_rich_qa


# To run this program:
# $ python ClientConvergentEncryptDecrypt.py input.txt Alice
# where ClientConvergentEncryptDecrypt is this program name
# input.txt is inputfile name
# Alice is a sender_name

import dropbox, hashlib, os,codecs,requests,sys,copy
from pathlib import Path
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Util import Counter
from dropbox.files import WriteMode
from dropbox.exceptions import ApiError, AuthError

def readInputFile(filename):
    f = open(filename,"r")
    input = f.read()
    return input

def createHash(input):
    hash_object = hashlib.sha256(str.encode(input))
    H = hash_object.hexdigest()
    return H

def createCiphertext(K,input):
    random_generator = Random.new()
    IV = random_generator.read(8)
    keye = (K)[:32] # keye would be from index 0 to 32
    ctr_e = Counter.new(64, prefix=IV)
    encryptor = AES.new(keye, AES.MODE_CTR, counter=ctr_e)
    ciphertext = encryptor.encrypt(input)
    print("Return ciphertext:")
    print(ciphertext)
    return IV+ciphertext

# Note : key = private key,
#       key.publickey() = public_key
def createRSAKeys():
    random_generator = Random.new().read
    key = RSA.generate(1024, random_generator)
    public_key = key.publickey()
    return key, public_key

# Input: K
# Output: W (K encrypted with public_key)
# Ref: https://www.laurentluce.com/posts/python-and-cryptography-with-pycrypto/#a_3
def encryptedKeywithRSA(K,public_key):
    W = public_key.encrypt(K.encode('utf-8'), 32)
    return W

def connectToDropbox():
    f = open('../token.txt', 'r')
    token = f.readlines()
    dbx = dropbox.Dropbox(token[0])
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
    except dropbox.exceptions.ApiError as err:
        print('This file is not EXIST in the Dropbox')
    data = res.content
    print("Metadata from Dropbox\n",len(data), 'bytes; md:', md)
    print ("\n\nDowndloaded Data:\n")
    print(data)
    return data,dbx.sharing_get_file_metadata(path).preview_url

def createHashMetadata(H):
    path = Path('./metadata.txt')
    if path.exists() and os.path.getsize(path)!=0:
        f = open(path,'r')
        lists=[]
        for line in f:
            lists.append(line.rstrip())
        if H not in lists:
            w = open(path,'a+')
            w.write(H+"\n")
            w.close()
    else:
        f= open(path,'w+')
        f.writelines(H+"\n")
        f.close
    return None


def main():
    try:
        filename=sys.argv[1]
        sender_name=sys.argv[2]
    except:
        print("\n\nError!!\nPlease include include filename and sender name before run this program:\n"+
                "Ex: python ClientConvergentEncryptDecrypt.py input.txt Alice\n\n")
        sys.exit(2)
    input = readInputFile(filename)
    print("Plaintext:")
    print(input)
    K = createHash(input)
    ciphertext = createCiphertext(K,input)
    HK = createHash(str(K))
    print("\n\nHash Value of Key:")
    print (HK,"\n\n")
    createHashMetadata(HK)
    f = open('./'+sender_name+'_private.key','r')
    sender_private_key = f.read()
    sender_private_key = RSA.importKey(sender_private_key)
    f = open('./'+sender_name+'_public.key','r')
    sender_public_key = f.read()
    sender_public_key = RSA.importKey(sender_public_key)
    W = encryptedKeywithRSA(K,sender_public_key)
    dbx=connectToDropbox()
    uploadDatatoDropbox(dbx,ciphertext,'/A2/'+filename+'_C')
    uploadDatatoDropbox(dbx,W[0],'/A2/'+filename+'_'+sender_name+'_W')
    uploadDatatoDropbox(dbx,str.encode(HK),'/A2/'+filename+'_H')
    #Decryption
    #1. Downloading C and W from dropbox
    print("Downdloaded CipherText Details:")
    dl_C,cipher_url =  downloadFileFromDropbox(dbx,'/A2/'+filename+'_C')
    print("CiphetText URL: " + cipher_url)
    print("\n\n")
    print("Downdloaded W Details:")
    dl_W,W_url =  downloadFileFromDropbox(dbx,'/A2/'+filename+'_'+sender_name+'_W')
    #2. Extract Key K from W by using RSA decryption.
    decrypted_W = sender_private_key.decrypt(dl_W)
    #3.Decypteing the chiphertext C with AES-CTR withd decrypted_W=K
    keyd = (decrypted_W)[:32]
    IV=(dl_C)[:8]
    dl_C=(dl_C)[8:]
    # Create counter for decryptor with IV
    ctr_d = Counter.new(64, prefix=IV)
    # Create decryptor, then decrypt and print decoded text
    decryptor = AES.new(keyd, AES.MODE_CTR, counter=ctr_d)
    decrypted_text = decryptor.decrypt(dl_C)
    print ("\n\nDecrypted Data:\n"+decrypted_text.decode('utf-8'))
    #Write Output to file
    f= open("./decrypted_data_by_"+sender_name,"w+")
    f.write(decrypted_text.decode('utf-8'))
    f.close()

if __name__ == '__main__':
    main()