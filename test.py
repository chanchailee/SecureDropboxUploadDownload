import dropbox

# Read Access token from text file and store as a list of object
f = open('../token.txt', 'r')
token = f.readlines()
print(token[0])


#Connect to Dropbox application with access token
