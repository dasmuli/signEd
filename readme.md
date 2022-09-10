signEd
======

This is a command line tool to sign and check (proprietary) signatures. It is based on [Ed25519](http://ed25519.cr.yp.to/) using the code from [ed25519](https://github.com/orlp/ed25519). You can exchange public keys to verify files and you can print a shared secret word that only you and the other user know. This code is unaltered and under zlib license.

The base64 encoding/decoding source is copied from [littlstar](https://github.com/littlstar/b64.c), MIT licensed.

For fun, aes encryption is added from [kokke](https://github.com/kokke/tiny-AES-c) using PKCS7 from [bonybrown](https://github.com/bonybrown/tiny-AES128-C), public domain.

The code is ugly and hacked. MIT licensed. Consider openssl.

Usage
-----

```
signed                                     - Prints your public key
signed -s -i input -o output               - Signs input writing to output
signed -c -i input -f signaturefile        - Checks the signature of a file
signed -s -m -i input -o output            - Merges input and sig. in one file
signed -c -i input                         - Checks signature of a merged file
signed -s -m -e -i input -o output -u user - Sign and encrypt into one file
signed -c -x -i input -o output            - Check, decrypt and extract
signed -z -u user                          - Show the secret key for the user and you
signed -n personality                      - Adds a new personality key for you
signed -p personality                      - Shows the public key for the personality
signed -s -i input -p personality          - Signs with the personality
signed -w                                  - Show the list of local personalities
signed -a key user                         - Adds a public key for a user to be trusted
signed -l                                  - Show the list of trusted users
```


Example session
---------------

Show your public key:
```
alice@Kratos:~$ signed
eYkoZ61SvpofdIKbpS6SkyoWyX17VErbIUSv2+/LQTA= alice@Kratos
```

Sign a file printing to console:
```
alice@Kratos:~$ signed -s -i msg.txt

Signature msg.txt                                           
OXozCYdq3n/tN8Oab8JebzZUVD5CIMotwfudV/Pw/2C4wkvU21preZZk3Pd0K7CMeMJSj1sgfkxJJNK47qTwAQ==
eYkoZ61SvpofdIKbpS6SkyoWyX17VErbIUSv2+/LQTA=
```

Sign a file and put the signature into its own file:
```
alice@Kratos:~$ signed -s -i msg.txt -o msg.txt.signed 
```

Now check with another user that this file was signed by alice:
```
dasmuli@Kratos:~$ signed -c -i msg.txt -f msg.txt.signed 
File is signed by alice@Kratos
```

Sign and encrypt data into one file:
```
alice@Kratos:~$ signed -s -m -e -u dasmuli@Kratos -i msg.txt -o msg.txt.aes.signed 
alice@Kratos:~$ cat msg.txt.aes.signed 
�){����8�lG�a�5P
AES256
iUJH8x161cvsQ6AEHE5EFQ==
9fb92WtxqOqsDvSiB/Oj2H1anVNF7vE87Wxg672YNDc=
Signature msg.txt                                           
p5hFHBeiaea94I8O0roS6S+SCipVb7ceOurG0RxVEI1H7pdmD+Sj5z9aG/tWhG7tz6k5Dg2wDwjyWB/NsGfOBQ==
eYkoZ61SvpofdIKbpS6SkyoWyX17VErbIUSv2+/LQTA=
```

This can be checked for a known signature with:
```
signed -c -i msg.txt.aes.signed 
File is signed by alice@Kratos
```

Checking the signature and decrypting in a single step can be done with:
```
signed -c -x -i msg.txt.aes.signed 
Hi muli
```

Or you can check the signature, decrypt and write into a file using:
```
signed -c -x -i msg.txt.aes.signed -o msg.txt
cat msg.txt 
Hi muli
```

If this file was not encrypted for me, it will look like:
```
signed -c -x -i msg.txt.aes.signed 
Could not find own personality for EsyHrh9V1K3E/a8H6wy7hkT7Ys/KxlQVmOq8tU+Nbn0=, message not for me
```

Regarding user management, you add a known public key using:
```
alice@Kratos:~$ signed -a 9fb92WtxqOqsDvSiB/Oj2H1anVNF7vE87Wxg672YNDc= bob@Kratos
```
This is the citical moment - the question is if the public really belongs to someone you know. Note that the public key does not have to be protected.

You can list all known users you can encrypt for with:
```
signed -l
alice@Kratos
```

Finally show a shared zecret word with a known user based on ED25519:
```
alice@Kratos:~$ signed -z -u bob@Kratos
5OlvXwI/9KjEz68LVWvMOM9kA1EAVtjQvH0z9bTJbz8=
```
When you exchange public keys, only you and the other user will see this same secret key, but nobody else. Even if they have both public keys, the zecret stays secret. Sort of magic :)

If you want to mess with the user database, they are stored in ~/snap/signed/common/.signEd when using the snap or ~/.signEd when using the local installation.



Installation
------------

Install [![signed](https://snapcraft.io/signed/badge.svg)](https://snapcraft.io/signed) from snapcraft, ``sudo snap install signed`` on Ubuntu.

Or clone and make.

Requirements
------------

Linux and gcc, no external libraries.


