from sys import argv
from time import time
import hashlib
from random import choice

types = ['SHA256', 'SHA512', 'SHA384', 'SHA1', 'MD5']
bf_range = range(3, 4)

#function for hashing the passwords to compare against hashed_password
def hash_password(password, hash_type):
    if hash_type.upper() == 'SHA256':
        return hashlib.sha256(password.encode()).hexdigest()
    elif hash_type.upper() == 'SHA512':
        return hashlib.sha512(password.encode()).hexdigest()
    elif hash_type.upper() == 'SHA384':
        return hashlib.sha384(password.encode()).hexdigest()
    elif hash_type.upper() == 'SHA1':
        return hashlib.sha1(password.encode()).hexdigest()
    elif hash_type.upper() == 'MD5':
        return hashlib.md5(password.encode()).hexdigest()

#detect hash type automatically
#unsafe
def detect_hash(hashed_password):
    if len(hashed_password) == 128:
        return 'SHA512'
    elif len(hashed_password) == 96:
        return 'SHA384'
    elif len(hashed_password) == 64:
        return 'SHA256'
    elif len(hashed_password) == 40:
        return 'SHA1'
    elif len(hashed_password) == 32:
        return 'MD5'
    else:
        print('Could not auto detect hash type')
        exit()

#generate random strings and compare them against hashed_password
def bruteforce(hashed_password, hash_type, bruteforce_range):
    chars = list('abcdefghijklmnopqrstuvwxyzABCDEFGHJIKLMNOPQRSTUVWXYZ0123456789')
    bruteforce_range = list(bruteforce_range)

    t0 = time()
    try:
        while True:
            #generate random string based on 
            pw = ''.join([choice(chars) for i in range(choice(bruteforce_range))])
            print(pw)
            if hashed_password == hash_password(pw, hash_type):
                t1 = time()
                print(f'password is: {pw}\npassword was found in: {t1-t0} seconds')
                #save the password in a text file then exit
                with open('result.txt', 'w') as res:
                    res.write(pw)
                exit()

    except KeyboardInterrupt:
        t1 = time()
        print(f'Password could not be found, tried for: {t1-t0} seconds')

#function for cracking hash with the list of passwords
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

    #loop through all passwords and compare the hashed versions of them with the 
    #hashed password
    t0 = time()
    try:
        for pw in passwords:
            if hashed_password == hash_password(pw.replace('\n', ''), hash_type):
                t1 = time()
                print(f'password is: {pw}\n password was found in: {t1-t0} seconds')
                #save the password in a text file then exit
                with open('result.txt', 'w') as res:
                    res.write(pw)
                exit()
    except KeyboardInterrupt:
        t1 = time()
        print(f'Password could not be found, tried for: {t1-t0} seconds')

#show the help menu if there are no arguments
if len(argv) == 1:
    print(f'''hashcracker.py [type] [hash] [password list] 
type (AUTO for hash type detection)-> {', '.join(types)}
(Automatic hash detection is not recommended)
hash -> hashed password
password list (leave empty for bruteforce) -> text file containing list of passwords
''')
    exit()

elif len(argv) == 2:
    print('Missing required argument: [hash]')
    exit()

#check if the type specified in the arguments is valid
if argv[1] == 'AUTO':
    argv[1] = detect_hash(argv[2])
elif argv[1] not in types:
    print(f'''Invalid type: {argv[1]}
type must be one of the following:''')
    print(', '.join(types))
    exit()

#check if the password list is present
#if it's not then enter bruteforce mode
if len(argv) < 4:
    bruteforce(argv[2], argv[1], bf_range)
else:
    print()
    crack_hash(argv[1], argv[2], argv[3])