# This collects the code fragments from INTEGRATION.md into a simple
# app for testing (and verifying the docs actually work).
#
# The contents of this file are in the public domain, feel free to remix
# and reuse as you wish.
#
import base64
import json
import os
import time
import sys
 
from passcrow.client import PasscrowRecoveryPolicy, PasscrowClient


tell_user_it_failed = print


def tell_user_to_visit_URL(url, hint):
    print('Please visit %s, account %s' % (url, hint))


def tell_user_to_expect_code(kind, hint):
    print('Please check %s for a code, account %s' % (kind, hint))
 

class Configuration:

    SECRET_KEY_MATERIAL = b'CAN HAZ SEKRITZ'
    APP_VERSION = '1.2.3'

    appdata_dir = '/tmp'


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
                'email, sms via passcrow-test.mailpile.is'],

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

    def passcrow_protect(self, user_id_list, name='FooApp Data'):
        data = self.get_recovery_data()
        client = self.get_passcrow_client()
        policy = self.get_passcrow_policy(user_id_list, client=client)
        
        ok = client.protect(name, data, policy,
            pack_description=name,
            verify_description=name,
            quick=True)
        if not ok:
            tell_user_it_failed('passcrow_protect failed')

        return ok

    def passcrow_verify(self, name='FooApp Data'):
        client = self.get_passcrow_client()
        pack = client.pack(name)

        verifications = client.verify(pack, quick=True)
        if not verifications:
            tell_user_it_failed('passcrow_verify failed')
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
            tell_user_it_failed('passcrow_request failed')
            return False
        
        # Next:
        #   1. Reverse the encoding done in get_recovery_data()
        #   2. Verify we can access the application data
        #   3. Ask the user to set a new password
        return True

    def passcrow_forget(self, name='FooApp Data'):
        client = self.get_passcrow_client()

        ok = client.delete(name, remote=True, quick=True)
        if not ok:
            tell_user_it_failed('passcrow_forget failed')

        return ok


if __name__ == '__main__':
    cfg = Configuration()

    print('default policy: %s' % cfg.get_passcrow_client().default_policy)

    emails = input('Please list some e-mails: ').split(' ')
    print('policy: %s' % cfg.get_passcrow_policy(emails))

    if cfg.passcrow_protect(emails):
        print('*** Protected data!')
    else:
        sys.exit(1)
    
    print()
    time.sleep(2)
    if cfg.passcrow_verify():
        print('*** Initiated verification, check your e-mail')
    else:
        sys.exit(1)

    print()
    time.sleep(1)
    codes = []
    while True:
        code = input('>>> Input code (blank when done): ').strip()
        if not code:
            break
        codes.append(code)

    print()
    time.sleep(2)
    if cfg.passcrow_recover(codes):
        print('*** Recovery succeeded')

    print()
    time.sleep(2)
    if cfg.passcrow_forget():
        print('*** Deleted from server(s)')

    os.system('rm -rf /tmp/passcrow')
