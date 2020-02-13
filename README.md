# hashcracker
![alt text](https://raw.githubusercontent.com/Bot3939/hashcracker/master/imgs/usage2.png) <br>

<b>Supported hashing algorithms:</b> SHA512, SHA256, SHA384, SHA1, MD5, SHA224 <br>
<b>Features:</b> auto detection of hashing algorithm based on length (not recommended), bruteforce, password list <br>
<b>Arguments:</b> <br>
_type:_ hash algorithm (must be one of the supported hashing algorithms mentioned above or AUTO if you want to use automatic algorithm detection) <br>
_hash:_ can be either the hashed password, or a text file containing a list of hashes to crack (_hashlist_ must be activated if _hash_ is a text file containing multiple hashes) <br>
_mode:_ list or bruteforce<br>
_pwlist:_ list of passwords to compare against a single hash or a list of hashes <br>
_range:_ bruteforce string length range (default: 8-11)<br>
_hashlist:_ no parameters required for this argument, if hashlist is used, then _hash_ should be a text file with more than 1 hash <br>
_chars:_ string of characters to pick from to generate random strings for bruteforce (default value is: 
abcdefghijklmnopqrstuvwxyzABCDEFGHJIKLMNOPQRSTUVWXYZ0123456789)<br>


<b>Examples:</b> <br>
_Cracking a single hash with a password list:_ <br>
hashcracker.py SHA256 11a1162b984fef626ecc27c659a8b0eead5248ca867a6a87bea72f8a8706109d -mode list -pwlist passwordlist.txt<br>
<br>
_Cracking a single hash with bruteforce:_ <br>
hashcracker.py SHA256 11a1162b984fef626ecc27c659a8b0eead5248ca867a6a87bea72f8a8706109d -mode bruteforce -range 6 11 -chars abcdefghijklmnopqrstuvwxyz0123456789$#@<br>
<br>
_Cracking a list of hashes with a password list:_ <br>
hashcracker.py MD5 list_of_hashes.txt -mode list -pwlist passwordlist.txt -hashlist <br>
<br>
_Cracking a list of hashes with bruteforce:_ <br>
hashcracker.py MD5 list_of_hashes.txt -mode bruteforce -hashlist -range 6 11 -chars ABCDEFGHJIKLMNOPQRSTUVWXYZ0123456789<br>
<br>

![alt text](https://raw.githubusercontent.com/Bot3939/hashcracker/master/imgs/example2.png) <br>

