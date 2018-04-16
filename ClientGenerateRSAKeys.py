#!/usr/bin/env python3
#Author: Chanchai Lee
#The purpose of this file is to generate public_key and private_key by using RSA

#To Run the program:
# $ python ClientGenerateRSAKeys.py Alice

from Crypto.PublicKey import RSA
from Crypto import Random
from os import chmod

def createRSAKeys(user):
    random_generator = Random.new().read
    # Note : key = private key,
    #       key.publickey() = public_key
    key = RSA.generate(1024, random_generator)
    public_key = key.publickey().exportKey("PEM")
    private_key = key.exportKey("PEM")

    f = open('./'+user+'_private.key','wb')
    f. write(private_key)
    f.close()

    f = open('./'+user+'_public.key','wb')
    f. write(public_key)
    f.close()

    return None


def main():
    user = input("Enter the name: ")
    createRSAKeys(user)
    print("Create Key Successful")

if __name__ == '__main__':
    main()
