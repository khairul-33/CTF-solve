import hashlib

### THIS FUNCTION WILL NOT HELP YOU FIND THE FLAG --LT ########################
def str_xor(secret, key):
    #extend key to secret length
    new_key = key
    i = 0
    while len(new_key) < len(secret):
        new_key = new_key + key[i]
        i = (i + 1) % len(key)        
    return "".join([chr(ord(secret_c) ^ ord(new_key_c)) for (secret_c,new_key_c) in zip(secret,new_key)])
###############################################################################

flag_enc = open('level5.flag.txt.enc', 'rb').read()
correct_pw_hash = open('level5.hash.bin', 'rb').read()


def hash_pw(pw_str):
    pw_bytes = bytearray()
    pw_bytes.extend(pw_str.encode())
    m = hashlib.md5()
    m.update(pw_bytes)
    return m.digest()

file_path = '/home/hp/ArduinoCreateAgent/sfds/dictionary.txt'

# file_path = 'path/to/your/file.txt'

# Open the file and read its contents
with open(file_path, 'r') as file:
    # Read lines, remove newline characters, and split each line into a list
    flat_list = [line.strip().split() for line in file.readlines()]

# Flatten the list of lists into a single flat list
flat_list = [item for sublist in flat_list for item in sublist]

# Now, 'flat_list' is a single list containing elements from the file
# print(flat_list)

def level_5_pw_check():

    for i in flat_list:
        user_pw = i
        user_pw_hash = hash_pw(user_pw)
        
        if( user_pw_hash == correct_pw_hash ):
            print("Welcome back... your flag, user:")
            decryption = str_xor(flag_enc.decode(), user_pw)
            print(decryption)
            return
        # print("That password is incorrect")


level_5_pw_check()

