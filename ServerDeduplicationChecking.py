#!/usr/bin/env python3
#Author: Chanchai Lee
#The purpose of this file is to act as a server and check whether the input file is aleady existed in the dropbox or not.

# To run program:
# $ python ServerDeduplicationChecking.py input.txt

from ClientConvergentEncryptDecrypt import createHash,readInputFile,connectToDropbox,downloadFileFromDropbox
from pathlib import Path

import sys,os,re,dropbox

def readInputFromArgs():
    try:
        print("Server: Check Deduplication File")
        filename=sys.argv[1]

    except:
        print("\n\nError!!\nPlease include inclue filename before run this program:\n"+
                "Ex: python ServerDeduplicationChecking.py input.txt\n\n")
        sys.exit(2)
    input = readInputFile(filename)
    H = createHash(input)
    print('Hash of current input:')
    print(H)
    print("\n\n")
    return H,filename

def checkDeduplicationFromMetadata(H):
    path = Path('./metadata.txt')
    if path.exists() and os.path.getsize(path)!=0:
        f = open(path,'r')
        lists=[]
        for line in f:
            lists.append(line.rstrip())
        if H in lists:
            print("\n\nThe incoming file hash value is IDENTICAL (DUPLICATE) with hash values in METADATA\n\n")
        else:
            print("\n\nThe incoming file hash value is DIFFERENT from hash values in METADATA\n\n")
    else:
        print("No Metadata File")

def checkDeduplicationFromDropbox(H,filename):
    dbx = connectToDropbox()
    dl_H,H_url = downloadFileFromDropbox(dbx,'/A2/'+filename+'_H')
    if dl_H is not None:
        print('Hash of the EXISTING FILE on Dropbox:')
        print(dl_H.decode('utf-8'))

        if(H==dl_H.decode('utf-8')):
            print("\n\nThe hash value of incoming file is IDENTICAL (DUPLICATE) with an existing file on Dropbox\n\n")
        else:
            print("\n\nThe incoming file is DIFFERENT from an EXISTING FILE on Dropbox\n\n")

def main():
    H,filename=readInputFromArgs()
    H=createHash(str(H))
    select_option = ''
    while select_option != '3':

        select_option = input("Please select options:"+
        "\n1.Check Deduplication from Dropbox (Press:1)\n2.Check Deduplication from metadata file (Press:2)\n3.Quit program (Press:3):\nYour option:")

        if select_option=='1':
            checkDeduplicationFromDropbox(H,filename)

        elif select_option=="2":
            checkDeduplicationFromMetadata(H)
        else:
            continue

if __name__ == '__main__':
    main()