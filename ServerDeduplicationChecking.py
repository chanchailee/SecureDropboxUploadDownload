#!/usr/bin/env python3
#Author: Chanchai Lee
#The purpose of this file is to act as a server and check whether the input file is aleady existed in the dropbox or not.

# To run program:
# python ServerDeduplicationChecking.py input.txt


from ClientConvergentEncryptDecrypt import createHash,readInputFile,connectToDropbox,downloadFileFromDropbox
from pathlib import Path

import sys,os

def readInputFromArgs():
    #0.Read input file
    #filename='./input.txt'
    try:
        print("Server: Check Deduplication File")
        filename=sys.argv[1]

    except:
        print("\n\nError!!\nPlease include inclue filename before run this program:\n"+
                "Ex: python ServerDeduplicationChecking.py input.txt\n\n")
        sys.exit(2)
    input = readInputFile(filename)
    #Encryption
    #1.Create K by hash input file with sha256

    H = createHash(input)
    print('Hash of current input:')
    print(H)
    print("\n\n")
    return H

def checkDeduplicationFromMetadata(H):
    path = Path('./metadata.txt')
    if path.exists() and os.path.getsize(path)!=0:
        f = open(path,'r')
        lists=[]
        for line in f:
            lists.append(line.rstrip())
        if H in lists:
            print("\n\nThe incoming file hash value is identical (duplicate) with hash values in metadata\n\n")
        else:
            print("\n\nThe incoming file hash value is defference from hash values in metadata\n\n")
    else:
        print("No Metadata File")

def checkDeduplicationFromDropbox(H):

    #2.Connect server to Dropbox
    dbx = connectToDropbox()

    #3.Download Hash of the existing file from Dropbox
    dl_H,H_url = downloadFileFromDropbox(dbx,'/A2/H')
    print('Hash of the existing file in Dropbox:')
    print(dl_H.decode('utf-8'))

    if(H==dl_H.decode('utf-8')):
        print("\n\nThe hash value of incoming file is identical with an existing file on Dropbox\n\n")
    else:
        print("\n\nThe incoming file is difference from an existing file on Dropbox\n\n")

def main():
    H=readInputFromArgs()
    select_option = ''
    while select_option != '3':

        select_option = input("Please select options:"+
        "\n1.Check Deduplication from Dropbox (Press:1)\n2.Check Deduplication from metadata file (Press:2)\n3.Quit program (Press:3):\nYour option:")

        if select_option=='1':
            checkDeduplicationFromDropbox(H)

        elif select_option=="2":
            checkDeduplicationFromMetadata(H)
        else:
            continue

if __name__ == '__main__':
    main()
