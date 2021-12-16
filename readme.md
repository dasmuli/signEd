signEd
======

This is a command line tool to sign and check (proprietary) signatures. It is based on [Ed25519](http://ed25519.cr.yp.to/) using the code from [ed25519](https://github.com/orlp/ed25519). You can exchange public keys to verify files and you can print a shared secret word that only you and the other user know. This code is unaltered and under zlib license.

The base64 encoding/decoding source is copied from [littlstar](https://github.com/littlstar/b64.c), MIT licensed.

For fun, aes encryption is added from [kokke](https://github.com/kokke/tiny-AES-c) using PKCS7 from [bonybrown](https://github.com/bonybrown/tiny-AES128-C), public domain.

The code is ugly and hacked. MIT licensed. Consider openssl.

Usage
-----

```
signEd                                     - Prints your public key
signEd -s -i input -o output               - Signs input writing to output
signEd -c -i input -f signaturefile        - Checks the signature of a file
signEd -s -m -i input -o output            - Merges input and sig. in one file
signEd -c -i input                         - Checks signature of a merged file
signEd -s -m -e -i input -o output -u user - Sign and encrypt into one file
signEd -c -x -i input -o output            - Check, decrypt and extract
signEd -z -u user                          - Show the secret key for the user and you
signEd -n personality                      - Adds a new personality key for you
signEd -p personality                      - Shows the public key for the personality
signEd  -s -i input -p personality         - Signs with the personality
signEd -w                                  - Show the list of local personalities
signEd -a key user                         - Adds a public key for a user to be trusted
signEd -l                                  - Show the list of trusted users
```


Example session
---------------

Show public key:
```
alice@Kratos:~$ signEd
eYkoZ61SvpofdIKbpS6SkyoWyX17VErbIUSv2+/LQTA= alice@Kratos
```

Sign a file printing to console:
```
alice@Kratos:~$ signEd -s -i msg.txt

Signature msg.txt                                           
OXozCYdq3n/tN8Oab8JebzZUVD5CIMotwfudV/Pw/2C4wkvU21preZZk3Pd0K7CMeMJSj1sgfkxJJNK47qTwAQ==
eYkoZ61SvpofdIKbpS6SkyoWyX17VErbIUSv2+/LQTA=
```

Sign a file and output the signature into a file:
```
alice@Kratos:~$ signEd -s -i msg.txt -o msg.txt.signed 
```

Add a user:
```
alice@Kratos:~$ signEd -a 9fb92WtxqOqsDvSiB/Oj2H1anVNF7vE87Wxg672YNDc= bob@Kratos
```

Sign and encrypt into one file:
```
alice@Kratos:~$ signEd -s -m -e -u bob@Kratos -i msg.txt -o msg.txt.aes.signed 
alice@Kratos:~$ cat msg.txt.aes.signed 
�){����8�lG�a�5P
AES256
iUJH8x161cvsQ6AEHE5EFQ==
9fb92WtxqOqsDvSiB/Oj2H1anVNF7vE87Wxg672YNDc=
Signature msg.txt                                           
p5hFHBeiaea94I8O0roS6S+SCipVb7ceOurG0RxVEI1H7pdmD+Sj5z9aG/tWhG7tz6k5Dg2wDwjyWB/NsGfOBQ==
eYkoZ61SvpofdIKbpS6SkyoWyX17VErbIUSv2+/LQTA=
```

Finally show a shared zecret word with a user based on ED25519:
```
alice@Kratos:~$ signEd -z -u bob@Kratos
5OlvXwI/9KjEz68LVWvMOM9kA1EAVtjQvH0z9bTJbz8=
```

Note: the user bob@Kratos actually was dasmuli@Kratos, that evil guy.


Installation
------------

Clone and make.

Requirements
------------

Linux and gcc, no external libraries.


