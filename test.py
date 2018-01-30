#!/usr/bin/env python3

import dropbox, hashlib, os
from Crypto.Cipher import AES

#Read input file
f = open("input.txt","r") #opens file with name of "test.txt"

input = f.read()
print("################ read() #######################")
print(input)

#Create key1 by hash input file with sha256
hash_object = hashlib.sha256(input.encode('utf-8'))
#hex_dig = hash_object.hexdigest()
key1 = hash_object.hexdigest()

#print("################print hash_object #######################")
#print(hash_object)

print("################print key1 from hashlib.sha256(input) #######################")
print(key1)


# Create Cipher text C with AES Counter mode




# Read Dropbox Access token from text file and store as a list of object
f = open('../token.txt', 'r')
token = f.readlines()
#print(token[0])


#Connect to Dropbox application with access token
dbx = dropbox.Dropbox(token[0])

#get dropbox user account

dbx_user = dbx.users_get_current_account()
#print(dbx_user)
