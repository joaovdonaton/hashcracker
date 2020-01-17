from sys import argv
from time import time
import hashlib

types = ['SHA256', 'SHA512', 'bruteforce']

#show the help menu if there are no arguments
if len(argv) == 1:
    print('''hashcracker.py [type] [password list]
type -> SHA256, SHA512, bruteforce
password list (only if type isn't bruteforce) -> text file containing list of passwords''')
    exit()

#check if the type specified in the arguments is valid
if argv[1] not in types:
    print(f'''Invalid type: {argv[1]}
type must be one of the following:''')
    print(', '.join(types))
    exit()

#check if the password list is present (unless the type is bruteforce)
if argv[1].lower() != 'bruteforce' and len(argv) < 3:
    print('''Missing required parameter: [password list]''')
    exit()

