import os
aes_key = os.urandom(16) 

file = open('AESkey.txt','wb')
file.write(aes_key)
file.close()