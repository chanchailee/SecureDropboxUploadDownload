from flask import Flask, flash, redirect, render_template, request, session, abort, url_for,redirect
from flask_bootstrap import Bootstrap
import dropbox
from werkzeug import secure_filename
from ClientConvergentEncryptDecrypt import createHash,createCiphertext,encryptedKeywithRSA,connectToDropbox,uploadDatatoDropbox
from Crypto.PublicKey import RSA

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
        H = createHash(upload_file)# Return Key to encrypt plaintext
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

if __name__ == "__main__":
    app.run(debug=True)
