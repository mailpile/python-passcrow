import os
import sys

from .proto import *


CLI_COMMANDS = {}
CLI_DATABASE = os.path.expanduser('~/.passcrow')


def cli_help(args):
    """
    Passcrow is a tool to facilitate secure password/passphrase/key
    recovery when using local encryption.

    For each recoverable data set, passcrow stores a local encrypted
    "recovery pack" which can only be decrypted with the assistance of
    a remote Passcrow Helper, which in turn takes care of verifying the
    identity of the owner before granting access.

    If using the passcrow tool directly, you must first initialize your
    local recovery database using `passcrow init`.

    Run `passcrow help COMMAND` for more details about each command.
    """
    if args and args[0] in CLI_COMMANDS:
        print('passcrow %s' % args[0])
        print(CLI_COMMANDS[args[0]].__doc__)
        return True
    else:
        print('passcrow [%s]' % '|'.join(sorted(CLI_COMMANDS.keys())))
        print(cli_help.__doc__)
        return (not args)


def cli_init(args):
    """
    Initialize the passcrow recovery database. This is an interactive
    command which will ask the user questions if the answers are not
    provided as command-line arguments.
    """
    if not os.path.exists(CLI_DATABASE):
        os.mkdir(CLI_DATABASE, 0o700)

    # FIXME: Ask the user, or extract from the command line, what the
    #        default recovery policy and Passcrow Helper should be.

    return True


def cli_list(args):
    """
    Display an overview of the current passcrow recovery database contents.

    """
    print('FIXME')


def cli_protect(args):
    """
    Add a new secret to the passcrow recovery database, so it can be
    recovered later if necessary.
    """
    print('FIXME')


def cli_recover(args):
    """
    Recover one of the secrets in your passcrow recovery database.
    """
    print('FIXME')


def cli_forget(args):
    """
    Forget one of the secrets in your passcrow recovery database.
    """
    print('FIXME')


def cli_main(args):
    if len(args) < 1:
        args = ['help']
    try:
        return CLI_COMMANDS[args[0]](args[1:])
    except KeyError:
        return cli_help(args)


CLI_COMMANDS.update({
    'help': cli_help,
    'init': cli_init,
    'list': cli_list,
    'protect': cli_protect,
    'recover': cli_list,
    'forget': cli_list})

sys.exit(0 if cli_main(sys.argv[1:]) else 1)
