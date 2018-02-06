#!/usr/bin/env python3

import dropbox, hashlib, os
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto import Random
import bitarray


#Read input file
f = open("input.txt","r") #opens file with name of "test.txt"

input = f.read()
print("################ Input Content #######################")
print(input)

#1.Create key1 by hash input file with sha256
hash_object = hashlib.sha256(input.encode('utf-8'))
#hex_dig = hash_object.hexdigest()
key1 = hash_object.hexdigest()

#print("################print hash_object #######################")
#print(hash_object)

print("################print key1 from hashlib.sha256(input) #######################")
print("key1: "+ key1)


#2 Create Cipher text C with AES Counter mode





#3 Encrypt K with the sender's RSA public key
	# Input K and Sender's public key
	# Output W
ba = bitarray.bitarray()
key = RSA.generate(1024,ba.frombytes(key1.encode('utf-8')))
print("key1 public key")
print(key.publickey())
print("key1 private key")
print(key)

# Note : key = private key, key.publickey() = public key = public_key
public_key = key.publickey()

W = public_key.encrypt(key1.encode('utf-8'), 32)

print("\n\n W is")
print(W)



#4 Upload Ciphertext (C) and W to dropbox
# Read Dropbox Access token from text file and store as a list of object
f = open('../token.txt', 'r')
token = f.readlines()
#print(token[0])


#Connect to Dropbox application with access token
dbx = dropbox.Dropbox(token[0])

#get dropbox user account

dbx_user = dbx.users_get_current_account()
print(dbx_user)
