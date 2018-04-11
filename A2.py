#!/usr/bin/env python3

#Author: Chanchai Lee

import dropbox, hashlib, os,codecs
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from base64 import b64decode
from Crypto.Util import Counter
from dropbox.files import WriteMode
from dropbox.exceptions import ApiError, AuthError


#Read input file
f = open("input.txt","r") #opens file with name of "test.txt"

input = f.read()
print("################ Input Content #######################")
print(input)

#1.Create K by hash input file with sha256
hash_object = hashlib.sha256(input.encode('utf-8'))
K = hash_object.hexdigest()

print("################print K from hashlib.sha256(input) #######################")
print("K: "+ K)





#2 Create Cipher text C with AES Counter mode
# Ref: https://www.dlitz.net/software/pycrypto/api/current/Crypto.Util.Counter-module.html
#Stuck

####################Modified############################

random_generator = Random.new()
IV = random_generator.read(8)
#modified
keye = (K)[:32]
ctr_e = Counter.new(64, prefix=IV)
encryptor = AES.new(keye, AES.MODE_CTR, counter=ctr_e)
ciphertext = encryptor.encrypt(input)
print("ciphertext:")
print(ciphertext)
print("_________________________")

####################Modified############################

#3 Encrypt K with the sender's RSA public key
	# Input K and Sender's public key
	# Output W
	# Ref: https://www.laurentluce.com/posts/python-and-cryptography-with-pycrypto/#a_3
#ba = bitarray.bitarray()
#key = RSA.generate(1024,ba.frombytes(key1.encode('utf-8')))
random_generator = Random.new().read
key = RSA.generate(1024, random_generator)

print("Sender's public key")
print(key.publickey())

print("Sender's private key")
print(key)

# Note : key = private key, key.publickey() = public key = public_key
public_key = key.publickey()


W = public_key.encrypt(K.encode('utf-8'), 32)
#W = public_key.encrypt(K, 32)

print("\n\n W is")
print(W)
print(type(W))

print(type(W[0]))

#4 Upload Ciphertext (C) and W to dropbox
# Read Dropbox Access token from text file and store as a list of object
f = open('../token.txt', 'r')
#f = open('../sample.txt', 'r')
token = f.readlines()
#print(token[0])


#Connect to Dropbox application with access token
dbx = dropbox.Dropbox(token[0])

#get dropbox user account
dbx_user = dbx.users_get_current_account()
#print(dbx_user)

#Upload C (CipherText)
ciphertext_fileName='/A2/C'
dbx.files_upload(ciphertext, ciphertext_fileName, mode=WriteMode('overwrite'))
print("Finished Upload C(CipherText). File location: /A2/C");


#Upload W(Encrypted Key)
encrypted_key='/A2/W'
dbx.files_upload(W[0], encrypted_key, mode=WriteMode('overwrite'))
print("Finished Upload W(Key Encryption). File location: /A2/W")


##############################################################################################

#Decryption


#1. Downloading C and W from cloud storage

####################Download C #############################
try:
    md, res = dbx.files_download('/A2/C')
except dropbox.exceptions.HttpError as err:
    print('*** HTTP error', err)


data_C = res.content
print ("Downdloaded Ciphertext")
# print(len(data_C), 'bytes; md:', md)
print(data_C)



###################Download W ################

try:
    md, res = dbx.files_download('/A2/W')
except dropbox.exceptions.HttpError as err:
    print('*** HTTP error', err)


data = res.content
# print(len(data), 'bytes; md:', md)
print ("Downdloaded W")
print(data)



#2. Extract Key K from W by using RSA decryption.
decrypted_W = key.decrypt(data)
print("Decrypted Key:")
print(decrypted_W)


#3.Decypteing the chiphertext C with AES-CTR withd decrypted_W=K
keyd = (decrypted_W)[:32]

# Create counter for decryptor with IV
ctr_d = Counter.new(64, prefix=IV)

# Create decryptor, then decrypt and print decoded text
decryptor = AES.new(keyd, AES.MODE_CTR, counter=ctr_d)
decoded_text = decryptor.decrypt(data_C)
print ("Plaintext:\n"+decoded_text.decode('utf-8'))
