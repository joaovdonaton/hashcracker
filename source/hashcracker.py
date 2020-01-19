from sys import argv
from time import time
from hashlib import sha256, sha512, sha384, md5, sha1
from random import choice
import argparse

types = ['SHA256', 'SHA512', 'SHA384', 'SHA1', 'MD5']

#function for hashing the passwords to compare against hashed_password
def hash_password(password, hash_type):
    if hash_type.upper() == 'SHA256':
        return sha256(password.encode()).hexdigest()
    elif hash_type.upper() == 'SHA512':
        return sha512(password.encode()).hexdigest()
    elif hash_type.upper() == 'SHA384':
        return sha384(password.encode()).hexdigest()
    elif hash_type.upper() == 'SHA1':
        return sha1(password.encode()).hexdigest()
    elif hash_type.upper() == 'MD5':
        return md5(password.encode()).hexdigest()

#detect hash type automatically
#unsafe because it's only based on length
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
def bruteforce(hashed_password, hash_type, bruteforce_range, hashlist=False):
    chars = list('abcdefghijklmnopqrstuvwxyzABCDEFGHJIKLMNOPQRSTUVWXYZ0123456789')
    bruteforce_range = list(bruteforce_range)

    #check if the hash list has the correct file extension
    if hashed_password.find('.txt') == -1 and hashlist:
        hashed_password += '.txt'
    
    #get the hash list from the text file 
    hashes = []
    try:
        if hashlist:
            with open(hashed_password, 'r') as h_list:
                hashes = h_list.readlines()
                hashes = [i.replace('\n', '') for i in hashes]
        else:
            hashes.append(hashed_password)
    except FileNotFoundError:
        print(f'{hashed_password} doesn\'t exist')
        exit()

    t0 = time()
    try:
        for h in hashes:
            while True:
                #generate random string based on bruteforce range and chars
                pw = ''.join([choice(chars) for i in range(choice(bruteforce_range))])
                print(pw)
                if h == hash_password(pw, hash_type):
                    t1 = time()
                    print(f'password is: {pw}\npassword was found in: {t1-t0} seconds')
                    if not hashlist:
                        #save the password in a text file then exit
                        with open('result.txt', 'w') as res:
                            res.write(pw)
                        exit()
                    else:
                        #save the password in a text file then move onto the next hash
                        with open('result.txt', 'a') as res:
                            res.write(pw+'\n')
                            break
        print(f'All passwords were found in a total of {t1-t0} seconds')

    except KeyboardInterrupt:
        t1 = time()
        print(f'Password could not be found, tried for: {t1-t0} seconds')

#function for cracking a hash with a list of passwords
def crack_hash(hash_type=None, hashed_password=None, password_list=None, hashlist=False):
    if hash_type is None or password_list is None or hashed_password is None:
        print('An unexpected error has occured')
        exit()

    #if the password list or hash list doesn't have the file extention add it.
    if password_list.find('.txt') == -1:
        password_list += '.txt'
    if hashed_password.find('.txt') == -1 and hashlist:
        hashed_password += '.txt'

    #get the password list and the hash list from their respective files
    passwords, hashes = [], []
    try:
        with open(password_list, 'r') as pw_list:
            passwords = pw_list.readlines() 
        if hashlist:
            with open(hashed_password, 'r') as h_list:
                hashes = h_list.readlines()
                hashes = [i.replace('\n', '') for i in hashes]
    except FileNotFoundError:
        print(f'{password_list} or ${hashed_password} doesn\'t exist')
        exit()

    #loop through all passwords and compare the hashed versions of them with the 
    #hashed password
    t0 = time()
    try:
        #check if a hash list is being used
        if not hashlist:
            for pw in passwords:
                print(pw.replace('\n', ''))
                if hashed_password == hash_password(pw.replace('\n', ''), hash_type):
                    t1 = time()
                    print(f'password is: {pw}\n password was found in: {t1-t0} seconds')
                    #save the password in a text file then exit
                    with open('result.txt', 'w') as res:
                        res.write(pw)
                    exit()
        else:
            for h in hashes:
                for pw in passwords:
                    print(pw.replace('\n', ''))
                    if h == hash_password(pw.replace('\n', ''), hash_type):
                        t1 = time()
                        print(f'password is: {pw}\n password was found in: {t1-t0} seconds')
                        #save the password in a text file then move onto the next hash
                        with open('result.txt', 'a') as res:
                            res.write(pw+'\n')
                        break
    except KeyboardInterrupt:
        t1 = time()
        print(f'Password could not be found, tried for: {t1-t0} seconds')

if __name__ == '__main__':
    #parse arguments with argparse library
    parser = argparse.ArgumentParser()
    parser.add_argument('type', nargs=1, help='hash algorithm (SHA512, SHA384, SHA256, SHA1, MD5)')
    parser.add_argument('hash', nargs=1, help='hashed password (or text file contaning hashes if -hashlist is used)')
    parser.add_argument('-pwlist', nargs=1, help='list of passwords to compare against hash (required if mode is list)')
    parser.add_argument('-mode', nargs=1, default=['bruteforce'], help='bruteforce, list')
    parser.add_argument('-range', nargs=2, help='bruteforce password length range(use space to separate)',
    default=['8', '11'])
    parser.add_argument('-hashlist', help='use list of hashes instead of single hash', action='store_true')

    arguments = parser.parse_args()

    #check if the mode is bruteforce or list (if it's neither, print an error message)
    if arguments.mode[0] == 'bruteforce':
        bruteforce(arguments.hash[0], arguments.type[0], range(int(arguments.range[0]), int(arguments.range[1])),
        arguments.hashlist)
    elif arguments.mode[0] == 'list':
        if arguments.pwlist is not None:
            crack_hash(arguments.type[0], arguments.hash[0], arguments.pwlist[0], arguments.hashlist)
        else:
            print('Missing -pwlist argument')
    else:
        print('Invalid mode')
