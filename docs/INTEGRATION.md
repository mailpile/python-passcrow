# Integration Guide

This document explains how to add Passcrow-based reset functionality to
your Python app, using the `passcrow` library.

Topics:

   1. [Add passcrow as a dependency, install it](#install)
   2. [Decide what data to make recoverable](#data)
   3. [Define a Recovery Policy](#policy)
   4. [Protect the data with Passcrow](#protect)
   5. [Recovering data with Passcrow](#recovery)


## Add passcrow as a dependency, install it

If your project has a `requirements.txt` file, add the following lines:

    appdirs
    cryptography
    passcrow

If you want to pin it to a particular version of the library, you may
prefer this syntax instead:

    ...
    passcrow==1.2.3
    ...

You can now install `passcrow`, along with your other dependencies
using `pip3`:

    pip3 -r requirements.txt

Alternately, you can install `passcrow` and its dependencies manually,
as described in [the README](../README.md).


## Decide what data to make recoverable

Passcrow can put any kind of data "in escrow" and Passcrow never sends
the data ifself over the network. The data is encrypted and placed,
along with some Passcrow-specific metadata, in a Recovery Pack which is
stored in the user's filesystem.

That said, deciding what data to make recoverable and how to store it,
is one of the most important decisions you must make before making use
of Passcrow.

Some rules of thumb:

   1. The escrowed data should fit easily in RAM
   2. Include some versioning metadata, so future versions of your app
      can know what to expect
   3. Avoid storing user passwords directly, it is better to store
      random keys or (strong) password hashes (see below)

An example:

    import json
    import base64
 
    ...
    class Configuration:
        ...

        def get_recovery_data(self):
            # Encode the key in a way json.dumps can handle
            key = str(base64.b64encode(self.SECRET_KEY_MATERIAL), 'utf-8')

            # Include some metadata for our own purposes
            data = {
                'marker': 'FooApp Recovery Data',
                'version': self.APP_VERSION,
                'key': key}

            # Returns a binary blob: ready for use by passcrow
            return json.dumps(data)


### Why not store passwords?

Expanding upon the final point, from above: even though one of
Passcrow's main use cases is to recover from forgotten or lost
passwords, it is usually bad practice to store user passwords as
plaintext. Unless you are writing a password manager, it is probably
also unnecessary!

Since most well written encryption tools will use a hashing (or
stretching) function to derive a key from a password, that key (the
output of the hashing/stretching function) can be used to recover access
without ever revealing or storing the user's password. Store that
instead!

This has particular importance in the cases where the people performing
recovery are not the original owner of the data (e.g. if the user has
died, or left their place of work). The goal is to grant access to the
encrypted application data, not reveal the user's password.


## Define a Recovery Policy

A Recovery Policy is a combination of identities, Passcrow servers and
rules which together determine what is required to recover data which
has been protected using Passcrow.

The `passcrow.client` module provides classes for creating such
policies, as well as reasonable defaults and methods for power users to
override them.

    import os
    
    from passcrow.client import PasscrowRecoveryPolicy, PasscrowClient
    
    ...
    class Configuration:
        ...
    
        def get_passcrow_dir(self):
            return os.path.join(self.appdata_dir, 'passcrow')
    
        def get_passcrow_client(self, reset_defaults=False):
            client = PasscrowClient(
    
                # These are policy defaults; note the Passcrow library
                # has sensible defaults for these so you only need to
                # set them if your app has special needs.
                #
                default_expiration_days=365,
                default_timeout_minutes=30,
                default_n=3,  # n, from n/m fragments required
                default_m=4,  # m, from n/m fragments required
    
                # These are our preferred recovery servers
                default_servers=[
                    'tel, sms, mailto via passcrow.app.org',
                    'mailto via passcrow.mailpile.is'],
    
                # By default, this stores Passcrow settings and data with
                # other app data. But we set both env_override=True and
                # load_defaults=True, so power users can override our
                # settings by editing `passcrow/policy.rc` and/or control
                # where the data goes using Passcrow environment variables.
                #
                create_dirs=True,
                data_dir=self.get_passcrow_dir(),
                config_dir=self.get_passcrow_dir(),
                env_override=True,
                load_defaults=(not reset_defaults))

            if reset_defaults:
                client.save_default_policy()

            return client
    
        def get_passcrow_policy(self, user_id_list, client=None):
            client = client or self.get_passcrow_client()
    
            # user_id_list contains either PasscrowIdentityPolicy objects,
            # or e-mail addresses and phone numbers (strings), which the
            # library will interpret accordingly. Which e-mails and phone
            # numbers to use will have to come from the user of the app.

            return PasscrowRecoveryPolicy(
                idps=user_id_list,
                defaults=client.default_policy)

**WARNING:** Specifying `create_dirs=True` will cause the Passcrow
client to save its default policy to a file, the first time it runs.
Changing the code defaults after that point will have no effect (as long
as `load_defaults=True`), since they will be overridden by the contents
of the `policy.rc` file. This is deliberate, since code changes should
rarely override what the user may have specified in the configuration
file. The example above illustrates one way to force a reset.


### User configuration

App developers may choose to expose all of the Passcrow policy settings
to their users, using an appropriate settings diaog. This is fine, but
it is important to provide sensible defaults and not overload the user
with too many choices.

Apps without such a dialog can still be configured by power users who
edit the `policy.rc` file directly.


### User identities

The identities that the user provides for verification should be stored
in the app settings, and should generally be treated as sensitive data:
this is the list of accounts an attacker needs to compromise to gain
access to the user's data!


### Expiration times

Expiration of Passcrow protection is a very tricky subject; there is no
easy answer. After all, the purpose of Passcrow is to help users regain
access to data when they have lost or forgotten keys - this is the sort
of thing that happens months or even years later.

The pros of a shorter expiration period are:

   * More secure against some adversaries
   * Less of a false sense of security, in the case that Passcrow
     servers themselves may go offline

The cons are:

   * If the data has expired, recovery is impossible


### Multiple recovery policies?

Some applications may want to allow their user to specify multiple
recovery policies. For example:

   * A policy so the user themselves can regain access
   * Policies so 3rd parties (coworkers, family) can regain access

This quickly gets very complex, and is largely beyond the scope of this
document - the simplest approach would be to allow multiple lists of
user identities while keeping other parameters unchanged.


## Protect the data with Passcrow

Once the data and policies have been prepared, protecting data with
Passcrow is quite straightforward.

Building on the previous examples:

    ...
    class Configuration:
        ...
    
        def passcrow_protect(self, user_id_list, name='FooApp Data'):
            data = self.get_recovery_data()
            client = self.get_passcrow_client()
            policy = self.get_passcrow_policy(user_id_list, client=client)
            
            ok = client.protect(name, data, policy,
                pack_description=name,
                verify_description=name,
                quick=True)
            if not ok:
                tell_user_it_failed( ... )

            return ok

The main caveat, is that this process involves contacting multiple
servers and there are delays (sleeps) built into the process to avoid
overloading the servers and to potentially improve user anonymity (if
`quick=False`). You probably want this to happen on a background thread
and report results back to the user asynchronously.


### Expiration and updates

Note that the recovery policy specifies an expiration time in days,
after which the Passcrow servers are expected to delete any data they
are holding on the user's behalf.

The app should therefore periodically re-protect the data, as long as
the user is still using the application.

The app obviously also needs to re-protect if passwords and/or keys are
changed/rotated.

Note that re-protection can be fully automated and not require user
intervention, as long as the app keeps track of the user-ids and
policies. However, it may also be worth checking with the user every
few months whether their needs have changed.


## Recovering data with Passcrow

Recovering data takes place in two steps: verification and recovery.

When the user requests recovery, this triggers the verification step.
The app contacts all the recovery servers specified by the recovery
policy, and requests they verify the user's identities.

In response, the recovery servers will either send a code to one of the
user's identities (an SMS or an e-mail, usually), or request the user
visit a URL to verify their identity by some other means.

In both cases, the user collects a set of verification codes which they
must then input into the app in order to initiate recovery.

    ...
    class Configuration:
        ...
    
        def passcrow_verify(self, name='FooApp Data'):
            client = self.get_passcrow_client()
            pack = client.pack(name)

            verifications = client.verify(pack, quick=True)
            if not verifications:
                tell_user_it_failed( ... )
                return False

            for vfy in verifications:
                if 'action-url' in vfy:
                    tell_user_to_visit_URL(vfy.action_url, vfy.hint)
                else:
                    tell_user_to_expect_code(vfy.kind, vfy.hint)

            return True

        def passcrow_recover(self, codes, name='FooApp Data'):
            client = self.get_passcrow_client()
            pack = client.pack(name)

            secret_data = client.recover(pack, codes, quick=True)
            if not secret_data:
                tell_user_it_failed( ... )
                return False
            
            # Next:
            #   1. Reverse the encoding done in get_recovery_data()
            #   2. Verify we can access the application data
            #   3. Ask the user to set a new password

 
## Deleting data from Passcrow

Deleting data from Passcrow, superficially only requires deleting the
local Recovery Pack data. However, in case that data persists in backups
or has been compromised, it is also worthwhile to request the Passcrow
servers delete the key fragments they hold in escrow.

The `passcrow.client.delete` method will do both of these things (delete
local and remote data):

    ...
    class Configuration:
        ...
    
        def passcrow_forget(self, name='FooApp Data'):
            client = self.get_passcrow_client()

            ok = client.delete(name, remote=True, quick=True)
            if not ok:
                tell_user_it_failed( ... )

            return ok

