# hashcracker
![alt text](https://raw.githubusercontent.com/Bot3939/hashcracker/master/imgs/usage2.png) <br>

<b>Supported hashing algorithms:</b> SHA512, SHA256, SHA384, SHA1, MD5 <br>
<b>Features:</b> auto detection of hashing algorithm based on length (not recommended), bruteforce, password list <br>
<b>Arguments:</b> <br>
_type:_ hash algorithm (must be one of the supported hashing algorithms mentioned above) <br>
_hash:_ can be either the hashed password, or a text file containing a list of hashes to crack (_hashlist_ must be activated if _hash_ is a text file containing multiple hashes) <br>
_mode:_ list or bruteforce<br>
_pwlist:_ list of passwords to compare against a single hash or a list of hashes <br>
_range:_ bruteforce string length range (default: 8-11)<br>
_hashlist:_ no parameters required for this argument, if hashlist is used, then _hash_ should be a text file with more than 1 hash <br>


<b>Example:</b> <br>
hashcracker.py SHA256 11a1162b984fef626ecc27c659a8b0eead5248ca867a6a87bea72f8a8706109d -mode list -pwlist passwordlist.txt<br>

![alt text](https://raw.githubusercontent.com/Bot3939/hashcracker/master/imgs/example2.png) <br>

