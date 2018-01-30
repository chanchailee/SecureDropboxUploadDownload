import dropbox, hashlib

#Read input file



#Create Key by hash input file with sha256

input = 'hello'
hash_object = hashlib.sha256(b'test')
hex_dig = hash_object.hexdigest()
#print(hex_dig)



# Read Dropbox Access token from text file and store as a list of object
f = open('../token.txt', 'r')
token = f.readlines()
#print(token[0])


#Connect to Dropbox application with access token
dbx = dropbox.Dropbox(token[0])

#get dropbox user account

dbx_user = dbx.users_get_current_account()
print(dbx_user)
