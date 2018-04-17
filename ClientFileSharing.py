#!/usr/bin/env python3
#Author: Chanchai Lee
#The purpose of this file is resealed decrypted_W(K) with the reciever public_key as encrypted_WB
#Once Reciever download decrypted_WB from Dropbox,  reciever can decrypted this key by using his private_key as decrypted_WB
#To decrypt ciphertext, reciever can use decryted_WB to decrypt ciphertext that he download from dropbox

#To run: $ python ClientFileSharing.py input.txt Alice Bob

from ClientConvergentEncryptDecrypt import downloadFileFromDropbox,encryptedKeywithRSA,connectToDropbox,uploadDatatoDropbox
import dropbox, hashlib, os,codecs,requests,sys
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Util import Counter
from dropbox.files import WriteMode
from dropbox.exceptions import ApiError, AuthError

def main():
    # Secure File Sharing
    # 0.Read input file
    try:
        filename=sys.argv[1]
        sender_name=sys.argv[2]
        reciever_name=sys.argv[3]
    except:
        print("\n\nError!!\nPlease include inclue filename, sender_name and reciever_name before run this program:\n"+
                "Ex: python ClientConvergentEncryptDecrypt.py input.txt Alice Bob\n\n")
        sys.exit(2)

    #0. Make dbx connection
    dbx=connectToDropbox()
    
    #1. Fetch W from URL
    #url = 'https://www.dropbox.com/scl/fi/qn9wosorwd4t7ooxuxr0d/W?dl=1'
    dl_W,W_url =  downloadFileFromDropbox(dbx,'/A2/'+filename+'_'+sender_name+'_W')

    f = open('./'+sender_name+'_private.key','r')
    sender_private_key = f.read()
    sender_private_key = RSA.importKey(sender_private_key)

    #2. Extract Key K from W by using RSA decryption.
    decrypted_W = sender_private_key.decrypt(dl_W)
    # print("Decrypted W:")
    # print(decrypted_W)
    # print("\n\n")

    #3.Encrypt K with Reciever Publickey
    f = open('./'+reciever_name+'_public.key','r')
    reciever_public_key = f.read()
    reciever_public_key = RSA.importKey(reciever_public_key)
    encrypted_W = encryptedKeywithRSA(decrypted_W.decode('utf-8'),reciever_public_key)

    #4. Upload encrypted_W to Dropbox

    uploadDatatoDropbox(dbx,encrypted_W[0],'/A2/'+filename+'_'+reciever_name+'_W')

    #5. Download W
    dl_WB,WB_url =  downloadFileFromDropbox(dbx,'/A2/'+filename+'_'+reciever_name+'_W')

    #6. Decrypted WB with Reciever Private Key
    f = open('./Bob_private.key','r')
    reciever_private_key = f.read()
    reciever_private_key = RSA.importKey(reciever_private_key)
    decrypted_WB = reciever_private_key.decrypt(dl_WB)
    # print("Decrypted WB:")
    # print(decrypted_WB)
    # print("\n\n")
    #7. Download CipherText
    dl_C,C_url =  downloadFileFromDropbox(dbx,'/A2/'+filename+'_C')

    #8. Decrypted Ciphertext with decrypted_WB with AES-CTR
    keyd = (decrypted_WB)[:32]
    IV=(dl_C)[:8]
    dl_C=(dl_C)[8:]
    # Create counter for decryptor with IV
    ctr_d = Counter.new(64, prefix=IV)

    # Create decryptor, then decrypt and print decoded text
    decryptor = AES.new(keyd, AES.MODE_CTR, counter=ctr_d)
    decrypted_text = decryptor.decrypt(dl_C)
    #decrypted_text = unicode(sdecrypted_text, errors='ignore')
    print ("Decrypted Data OR Plaintext:\n"+decrypted_text.decode('utf-8'))

    #Write Output to file
    f= open("./decrypted_data_by_"+reciever_name,"w+")
    f.write(decrypted_text.decode('utf-8'))
    f.close()


if __name__ == '__main__':
    main()
