# Python Passcrow

Passcrow is a system for implementing secure "password escrow", making it
possible to recover from forgetting or losing a key, password or passphrase.

The user experience should be similar to the "reset password" recovery
flow of popular online services, but adapted to the needs of Open Source,
decentralization and users keeping locally encrypted data.

This is a stand-alone proof-of-concept Python implementation of Mailpile's
[passcrow protocol](docs/README.md).

This package includes the following things:

   1. A command-line tool for using passcrow "by hand"
   2. A Python library for integrating passcrow into other Python apps
   3. A passcrow server implementation


## Other Resources

You are reading the instructions for people who just want to use Passcrow.

   * [Protocol documentation](docs/README.md)
   * [Discourse forum](https://community.mailpile.is/c/development/passcrow)


## Getting Started - As a Passcrow Developer

    ## Install requirements (use one of the following)
    $ apt install python3-cryptography python3-appdirs
    $ dnf install python3-cryptography python3-appdirs
    $ pip3 install cryptography appdirs

    # Get the code
    $ git pull https://github.com/mailpile/python-passcrow
    $ cd python-passcrow

    # Test if it runs
    $ python3 -m passcrow help

TODO:

   * Document some hacker hints


## Getting Started - As a User

    ## Install requirements (use one of the following)
    $ apt install python3-cryptography python3-appdirs
    $ dnf install python3-cryptography python3-appdirs
    $ pip3 install cryptography appdirs

    $ pip3 install passcrow

    $ passcrow init

Now, use a text editor to customize the configuration file as recommended
by `passcrow init`. Once this is done, you can start putting secrets in
escrow:
    
    $ passcrow protect -n "My secrets" /path/to/secrets.txt

    $ passcrow list

    $ passcrow recover "My secrets" -o recovered-secrets.txt

    $ passcrow forget "My secrets"

To learn more about passcrow commands, options and arguments:

    $ passcrow help
    $ passcrow help protect
    $ passcrow help recover
    ...


## Getting Started - As a Python app Developer

    ## Install requirements (use one of the following)
    $ apt install python3-cryptography python3-appdirs
    $ dnf install python3-cryptography python3-appdirs
    $ pip3 install cryptography appdirs

    $ pip3 install passcrow

For now, in liu of docs, check out `passcrow/__main__.py` for a complete
implementation of the features provided by this library.

If you also want to run your own private passcrow server for testing, the
quickest method is to register for an account with <https://pagekite.net/>
and use the Pagekite integration to expose a test server:

    $ pip3 install upagekite
    $ mkdir /tmp/passcrow_server_data
    $ touch /tmp/passcrow_server_data/server_config.py
    $ python3 -m passcrow.integration.upagekite_app \
         KITE_NAME KITE_SECRET /tmp/passcrow_server_data

You can verify it is up and running like so:

    $ curl https://KITE_NAME/passcrow/policy

TODO:

   * Create proper API docs for the passcrow client library


## Getting Started - As a Provider

Passcrow servers expose a very simple API over HTTP. They also send e-mail
and may make use of 3rd party APIs such as Twilio.

There are a few standard patterns for running such a server, one of which is
described here below:

    ## Install requirements (use one of the following)
    $ apt install python3-cryptography python3-appdirs python3-flask gunicorn
    $ pip3 install passcrow

    $ adduser passcrow
    $ python3 -m passcrow server_init \
        passcrow /etc/passcrow/server_config.py /var/spool/passcrow

This will create an empty passcrow database in `/var/spool/passcrow` and a
default configuration file in `/etc/passcrow/server_config.py` which you
will probably want to open in a text editor, examine and customize.

Once you are satisfied, you can launch the server like so:

    $ su - passcrow
    $ gunicorn passcrow.integration.flask_app:app /etc/passcrow/server_config.py

You will also want to install a proper HTTP server such as `nginx` or `apache`,
and configure that to reverse-proxy the passcrow traffic to the gunicorn HTTP
server. And of course `letsencrypt` to procure and renew TLS certificates, if
you haven't already.

TODO:

   * Start on boot using sysvinit or systemd modules?
   * Dockerize?


## Copyright and License

Copyright (C) 2022, Mailpile ehf. and Bjarni R. Einarsson.

This program is free software: you can redistribute it and/or modify it
under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation, either version 3 of the License, or (at your
option) any later version.

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser
General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.
