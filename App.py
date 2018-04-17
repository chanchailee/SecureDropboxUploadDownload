from flask import Flask, flash, redirect, render_template, request, session, abort, url_for,redirect
from flask_bootstrap import Bootstrap
import dropbox
from werkzeug import secure_filename
from ClientConvergentEncryptDecrypt import createHash,createCiphertext,encryptedKeywithRSA,connectToDropbox,uploadDatatoDropbox,downloadFileFromDropbox,connectToDropbox,encryptedKeywithRSA

from pathlib import Path
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Util import Counter
from dropbox.files import WriteMode
from dropbox.exceptions import ApiError, AuthError

app = Flask(__name__)

@app.route('/')
def home():
   return render_template('index.html')

@app.route('/upload', methods = ['GET', 'POST'])
def upload():
    if request.method == 'POST':
        sender_public_key = request.files['sender_public_key']
        upload_file = request.files['file']

        spk_filename=sender_public_key.filename
        ul_filename=upload_file.filename
      # f.save(secure_filename(f.filename))
        sender_public_key=sender_public_key.read().decode('utf-8')
        upload_file=upload_file.read().decode('utf-8')



        K = createHash(upload_file)
        H = createHash(str(K))# Return Hash of Key
        # print(K)



        sender_public_key = RSA.importKey(sender_public_key)
        W = encryptedKeywithRSA(K,sender_public_key)

        ciphertext = createCiphertext(K,upload_file) # return IV+ciphertext
        print(ciphertext)
        return render_template ('create_cipher.html',spk_filename=spk_filename,ul_filename=ul_filename,W=W,ciphertext=ciphertext,H=H)
    else:
        return render_template('index.html')

@app.route('/uploadToDropbox', methods = ['GET', 'POST'])
def uploadToDropbox():
    if request.method == 'POST':
        W=request.form['W']
        H=request.form['H']
        ciphertext=request.form['ciphertext']
        # K = request.args.get('K')
        # ciphertext = request.args['ciphertext']
        print("\nW from POST Method")
        print(W)
        print("\nCiphertext from POST Method")
        print(ciphertext)

        dbx=connectToDropbox()
        #upload ciphertext to dropbox
        uploadDatatoDropbox(dbx,str.encode(ciphertext),'/A2/C')
        #upload W to dropbox
        uploadDatatoDropbox(dbx,str.encode(W),'/A2/W')
        #upload Hash Value of the plain text to dropbox for Server Deduplication checking in the future
        uploadDatatoDropbox(dbx,str.encode(H),'/A2/H')

    return render_template('upload_successful.html')

@app.route('/DecryptWwithPrivateKeyTemplate', methods = ['GET', 'POST'])
def decryptedWTemplate():
    return render_template('decryptedW.html')


@app.route('/DecryptWwithPrivateKey', methods = ['GET', 'POST'])
def decryptedW():
    dbx=connectToDropbox()
    dl_W,W_url =  downloadFileFromDropbox(dbx,'/A2/W')
    print(dl_W)

    sender_private_key = request.files['sender_private_key']
    sender_private_key=sender_private_key.read()
    sender_private_key=RSA.importKey(sender_private_key)

    decrypted_W = sender_private_key.decrypt(dl_W)


    reciever_public_key = request.files['reciever_public_key']
    reciever_public_key=reciever_public_key.read()
    reciever_public_key=RSA.importKey(reciever_public_key)

    encrypted_W =encryptedKeywithRSA(str(decrypted_W),reciever_public_key)
    print("ReSealed_W")
    print(encrypted_W)
    f = open('./WB',"w+")
    f.write(str(encrypted_W[0]))
    f.close()
    return render_template('decryptedWSuccessful.html')

@app.route('/DecryptedMessageTemplate')
def decryptedMessageTemplate():


    return render_template('decryptedMessageTemplate.html')
@app.route('/DecryptedMessage', methods = ['GET', 'POST'])
def decryptedMessage():
    message="Plaintext"
    decrypted_WB=request.files['message_key'].read().decode('utf-8')

    print("KEY:")
    print(decrypted_WB)
    dl_C=request.files['ciphertext'].read()
    print("CipherText:")
    print(dl_C)
    keyd = (decrypted_WB)[:32]
    IV=(dl_C)[:8]
    dl_C=(dl_C)[8:]
    # # Create counter for decryptor with IV
    ctr_d = Counter.new(64, prefix=IV)
    #
    # # Create decryptor, then decrypt and print decoded text
    decryptor = AES.new(keyd, AES.MODE_CTR, counter=ctr_d)
    decrypted_text = decryptor.decrypt(dl_C)
    print ("Decrypted Data OR Plaintext:\n",decrypted_text)




    return render_template('decryptedMessageSuccessful.html',message=message)


if __name__ == "__main__":
    app.run(debug=True)
