from itertools import product
from time import time
from hashlib import sha256, sha512, sha384, md5, sha1, sha224
import argparse
from hashid import HashID


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
    elif hash_type.upper() == 'SHA224':
        return sha224(password.encode()).hexdigest()


def detect_hash(hashed_password):
    hashid = HashID()
    results = hashid.identifyHash(hashed_password)

    if results:
        print(f"[+] Detected hash type(s): {[result.name for result in results]}")
        return results[0].name  # Optionally handle multiple matches if needed
    else:
        print("Could not auto-detect hash type.")
        return None


def load_hashes(filename):
    try:
        with open(filename, 'r') as file:
            return [line.strip() for line in file]
    except FileNotFoundError:
        print(f"[!] File '{filename}' not found. Please check the path and try again.")
        exit()


def bruteforce(hashed_password, hash_type, bruteforce_range, charsstr, hashlist=False):
    chars = list(charsstr)
    hashes = [hashed_password] if not hashlist else load_hashes(hashed_password)
    detect = (hash_type.upper() == 'AUTO')

    results = []
    t0 = time()
    try:
        for h in hashes:
            if detect:
                hash_type = detect_hash(h)
                if hash_type is None:
                    continue

            print(f'[?] Attempting to crack: {h}')
            found = False
            for length in bruteforce_range:
                for pw_tuple in product(chars, repeat=length):
                    pw = ''.join(pw_tuple)
                    if h == hash_password(pw, hash_type):
                        found = True
                        print(f'[~] Password is: {pw}\n[~] Password was found in: {time() - t0:.2f} seconds\n')
                        results.append(f'{pw} = {h}\n')
                        break
                if found:
                    break
    except KeyboardInterrupt:
        print(f'[!] Interrupted after {time() - t0:.2f} seconds')

    if results:
        write_results(results)


def load_default_passwords(count):
    filename = f'resources/common-passwords-{count}.txt'
    try:
        with open(filename, 'r') as file:
            return [line.strip() for line in file]
    except FileNotFoundError:
        print(f"[!] Default password list '{filename}' not found. Please ensure it's available.")
        exit()


def crack_hash(hash_type=None, hashed_password=None, password_list=None, common_count=None, hashlist=False):
    if hash_type is None or hashed_password is None:
        print('An unexpected error has occurred')
        exit()

    # Determine the password list source
    passwords = load_default_passwords(common_count) if common_count else load_password_list(password_list)

    # Process hash list if specified
    hashes = [hashed_password] if not hashlist else load_hashes(hashed_password)
    detect = (hash_type.upper() == 'AUTO')

    t0 = time()
    results = []
    try:
        for h in hashes:
            if detect:
                hash_type = detect_hash(h)
                if hash_type is None:
                    continue

            print(f'[?] Attempting to crack: {h}')
            found = False
            for pw in passwords:
                if h == hash_password(pw, hash_type):
                    print(f'[~] Password is: {pw}\n[~] Password was found in: {time() - t0:.2f} seconds\n')
                    results.append(f'{pw} = {h}\n')
                    found = True
                    break

            if not found:
                print(f'[!] Failed to crack {h} with the provided password list\n')
    except KeyboardInterrupt:
        print(f'[!] Interrupted after {time() - t0:.2f} seconds')

    if results:
        write_results(results)


def load_password_list(password_list):
    if password_list.find('.txt') == -1:
        password_list += '.txt'
    try:
        with open(password_list, 'r') as pw_list:
            return [line.strip() for line in pw_list]
    except FileNotFoundError:
        print(f"[!] Password list '{password_list}' not found. Please ensure it's available.")
        exit()


def write_results(results):
    with open('result.txt', 'a') as res:
        res.writelines(results)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('type', nargs=1, help='Hash algorithm (SHA512, SHA384, SHA256, SHA1, MD5, SHA224)')
    parser.add_argument('hash', nargs=1, help='Hashed password (or text file containing hashes if -hashlist is used)')
    parser.add_argument('-pwlist', nargs=1, help='List of passwords to compare against hash (required if mode is list)')
    parser.add_argument('-mode', nargs=1, default=['bruteforce'], help='bruteforce, list')
    parser.add_argument('-range', nargs=2, help='Bruteforce password length range (use space to separate)',
                        default=['8', '11'])
    parser.add_argument('-chars', nargs=1, default=['abcdefghijklmnopqrstuvwxyzABCDEFGHJIKLMNOPQRSTUVWXYZ0123456789'],
                        help='String of characters to pick from when generating random strings for bruteforce')
    parser.add_argument('-hashlist', help='Use list of hashes instead of single hash', action='store_true')
    parser.add_argument('--common', type=int, choices=[1000, 10000, 100000],
                        help="Use a default list of the most common passwords")

    arguments = parser.parse_args()

    if arguments.mode[0] == 'bruteforce':
        bruteforce(arguments.hash[0], arguments.type[0], range(int(arguments.range[0]), int(arguments.range[1])),
                   arguments.chars[0], arguments.hashlist)
    elif arguments.mode[0] == 'list':
        if arguments.pwlist is not None:
            crack_hash(arguments.type[0], arguments.hash[0], password_list=arguments.pwlist[0], hashlist=arguments.hashlist)
        elif arguments.common is not None:
            crack_hash(arguments.type[0], arguments.hash[0], common_count=arguments.common, hashlist=arguments.hashlist)
        else:
            print("Missing either -pwlist or --common argument for list mode")
    else:
        print('Invalid mode')
