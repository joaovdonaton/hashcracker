from sys import path, argv

path.append('../source/')
from hashcracker import hash_password

if len(argv) == 1:
    print('Usage: <type> <string>')
    exit()

print(hash_password(argv[2], argv[1]))
