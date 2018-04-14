from A2 import downloadFileFromDropbox,encryptedKeywithRSA,connectToDropbox,uploadDatatoDropbox
import dropbox, hashlib, os,codecs,requests
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Util import Counter
from dropbox.files import WriteMode
from dropbox.exceptions import ApiError, AuthError



def main():
    # Secure File Sharing

    #0. Make dbx connection
    dbx=connectToDropbox()

    #1. Fetch W from URL
    #url = 'https://www.dropbox.com/scl/fi/qn9wosorwd4t7ooxuxr0d/W?dl=1'
    dl_W,W_url =  downloadFileFromDropbox(dbx,'/A2/W')

    f = open('./Alice_private.key','r')
    sender_private_key = f.read()
    sender_private_key = RSA.importKey(sender_private_key)

    #2. Extract Key K from W by using RSA decryption.
    decrypted_W = sender_private_key.decrypt(dl_W)
    print("Decrypted W:")
    print(decrypted_W)
    print("\n\n")

    #3.Encrypt K with Reciever Publickey
    f = open('./Bob_public.key','r')
    reciever_public_key = f.read()
    reciever_public_key = RSA.importKey(reciever_public_key)
    encrypted_W = encryptedKeywithRSA(decrypted_W.decode('UTF-8'),reciever_public_key)

    #4. Upload encrypted_W to Dropbox

    uploadDatatoDropbox(dbx,encrypted_W[0],'/A2/WB')

    #5. Download WB
    dl_WB,WB_url =  downloadFileFromDropbox(dbx,'/A2/WB')
    #6. Decrypted WB with Receiver Private Key
    f = open('./Bob_private.key','r')
    reciever_private_key = f.read()
    reciever_private_key = RSA.importKey(reciever_private_key)
    decrypted_WB = reciever_private_key.decrypt(dl_WB)
    print("Decrypted WB:")
    print(decrypted_WB)
    print("\n\n")
    #7. Download CipherText
    dl_C,C_url =  downloadFileFromDropbox(dbx,'/A2/C')

    #8. Decrypted Ciphertext with decrypted_WB with AES-CTR
    keyd = (decrypted_WB)[:32]
    IV=(dl_C)[:8]
    dl_C=(dl_C)[8:]
    # Create counter for decryptor with IV
    ctr_d = Counter.new(64, prefix=IV)

    # Create decryptor, then decrypt and print decoded text
    decryptor = AES.new(keyd, AES.MODE_CTR, counter=ctr_d)
    decrypted_text = decryptor.decrypt(dl_C)
    print ("Decrypted Data:\n"+decrypted_text.decode('utf-8'))

    #Write Output to file
    f= open("./decrypted_data_by_Reciever","w+")
    f.write(decrypted_text.decode('utf-8'))
    f.close()


if __name__ == '__main__':
    main()
