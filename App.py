from flask import Flask, flash, redirect, render_template, request, session, abort
from werkzeug import secure_filename
app = Flask(__name__)

@app.route('/')
def home():
   return render_template('index.html')

@app.route('/uploader', methods = ['GET', 'POST'])
def uploader():
   if request.method == 'POST':
      fs = request.files['sender_public_key']
      fr = request.files['receiver_public_key']
      # f.save(secure_filename(f.filename))
      return fs.read()+fr.read()

if __name__ == "__main__":
    app.run(debug=True)
