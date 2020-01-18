from sys import argv
from time import time
import hashlib

types = ['SHA256', 'SHA512', 'SHA384']

#function for hashing the passwords to compare against hashed_password
def hash_password(password, hash_type):
    if hash_type.upper() == 'SHA256':
        return hashlib.sha256(password.encode()).hexdigest()
    elif hash_type.upper() == 'SHA512':
        return hashlib.sha512(password.encode()).hexdigest()
    elif hash_type.upper() == 'SHA384':
        return hashlib.sha384(password.encode()).hexdigest()

#function for cracking hashing with the list of passwords
def crack_hash(hash_type=None, hashed_password=None, password_list=None):
    if hash_type is None or password_list is None or hashed_password is None:
        print('An unexpected error has occured')
        exit()

    #if the password list doesn't have the file extention
    #add it.
    if password_list.find('.txt') == -1:
        password_list += '.txt'

    passwords = []
    try:
        with open(password_list, 'r') as pw_list:
            passwords = pw_list.readlines()  
    except FileNotFoundError:
        print(f'{password_list} doesn\'t exist')
        exit()

    #loop through all passwords and compared the hashed versions of them with the 
    #hashed password
    t0 = time()
    for pw in passwords:
        if hashed_password == hash_password(pw.replace('\n', ''), hash_type):
            t1 = time()
            print(f'password is: {pw}\n password was found in: {t1-t0} seconds')
            exit()

#show the help menu if there are no arguments
if len(argv) == 1:
    print('''hashcracker.py [type] [hash] [password list] 
type -> SHA256, SHA512, SHA384
hash -> hashed password
password list (leave empty for bruteforce) -> text file containing list of passwords''')
    exit()

#check if the type specified in the arguments is valid
if argv[1] not in types:
    print(f'''Invalid type: {argv[1]}
type must be one of the following:''')
    print(', '.join(types))
    exit()

#check if the password list is present
#if it's not then enter bruteforce mode
if len(argv) < 4:
    pass
else:
    crack_hash(argv[1], argv[2], argv[3])