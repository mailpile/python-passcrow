# Python Passcrow

Passcrow is a system for implementing a secure "password escrow", a tool
which makes it possible to recover from forgetting or losing a password
or passphrase.

The user experience should be similar to the "reset password" recovery
flow of popular online services, but adapted to the needs of Open Source,
decentralization and users keeping locally encrypted data.

This is a stand-alone proof-of-concept Python implementation of Mailpile's
[passcrow protocol](docs/README.md).

**Note:** This is the document for people who want to use Passcrow.
[Look here to understand how it works and why.](docs/README.md)


## Getting Started - As a User

    $ pip3 install passcrow

    $ passcrow init
    
    $ passcrow protect "My secrets" /path/to/secrets.txt

    $ passcrow list

    $ passcrow recover "My secrets" recovered-secrets.txt

    $ passcrow forget "My secrets"

Note, these behaviours should ideally be built into client-side software,
but until that happens users can DIY like so.


## Getting Started - As a Developer


## Getting Started - As a Provider





