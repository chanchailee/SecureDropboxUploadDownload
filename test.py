# Import modules
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util import Counter


# Pad for short keys
#pad = '# constant pad for short keys ##'
pad = 'random textdaflkds;lfk;saldkf;laksd;lfk;lsadf;lsd;lfla;'

# Generate a random initialization vector, to be used by both encryptor and decryptor
# This may be sent in clear in a real communication

random_generator = Random.new()
IV = random_generator.read(8)


# Encryption steps

# Ask user for input and pad or truncate to a 32 bytes (256 bits) key
prompt = 'Input your key. It will padded or truncated at 32 bytes (256 bits).\n-: '
user_keye = input(prompt)
keye = (user_keye + pad)[:32]

# Create counter for encryptor
ctr_e = Counter.new(64, prefix=IV)

# Create encryptor, ask for plaintext to encrypt, then encrypt and print ciphertext
encryptor = AES.new(keye, AES.MODE_CTR, counter=ctr_e)
plaintext = input('Enter message to cipher: ')
ciphertext = encryptor.encrypt(plaintext)
print (ciphertext)



# Decryption steps

# Ask user for key: it must be equal to that used for encryption
prompt = 'Input your key. It will padded or truncated at 32 bytes (256 bits).\n-: '
user_keyd = input(prompt)
keyd = (user_keyd + pad)[:32]

# Create counter for decryptor: it is equal to the encryptor, but restarts from the beginning

ctr_d = Counter.new(64, prefix=IV)

# Create decryptor, then decrypt and print decoded text
decryptor = AES.new(keyd, AES.MODE_CTR, counter=ctr_d)
decoded_text = decryptor.decrypt(ciphertext)
print (decoded_text)