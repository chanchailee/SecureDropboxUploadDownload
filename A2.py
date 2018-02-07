#!/usr/bin/env python3

import dropbox, hashlib, os
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import AES
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
#f = open('../token.txt', 'r')
f = open('../sample.txt', 'r')
token = f.readlines()
#print(token[0])


#Connect to Dropbox application with access token
dbx = dropbox.Dropbox(token[0])

#get dropbox user account

dbx_user = dbx.users_get_current_account()
#print(dbx_user)

filename='/test/test'
dbx.files_upload(W[0], filename, mode=WriteMode('overwrite'))
