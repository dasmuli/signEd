signEd
======

This is a command line tool to sign and check (proprietary) signatures. It is based on [Ed25519](http://ed25519.cr.yp.to/) using the code from [ed25519](https://github.com/orlp/ed25519). You can exchange public keys to verify files and you can print a shared secret word that only you and the other user know. This code is unaltered and under zlib license.

For fun, aes encryption is added from [kokke](https://github.com/kokke/tiny-AES-c) using PKCS7 from [bonybrown](https://github.com/bonybrown/tiny-AES128-C).

The code is ugly and hacked. Consider openssl.

Usage
-----

signEd                                     - Prints your public key
signEd -s -i input -o output               - Signs input writing to output
signEd -c -i input -f signaturefile        - Checks the signature of a file
signEd -s -m -i input -o output            - Merges input and sig. in one file
signEd -s -m -e -i input -o output -u user - Sign and encrypt into one file
signEd -c -x -i input -o output            - Check, decrypt and extract
signEd -z -u user                          - Show the secret key for the user and you
signEd -n personality                      - Adds a new personality key for you
signEd -p personality                      - Shows the public key for the personality
signEd  -s -i input -p personality         - Signs with the personality
signEd -w                                  - Show the list of local personalities
signEd -a key user                         - Adds a public key for a user to be trusted
signEd -l                                  - Show the list of trusted users


Installation
------------

Clone and make.

Requirements
------------

Linux and gcc.


