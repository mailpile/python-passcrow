import hashlib
import os
import sys
import time
import traceback

import appdirs

from .proto import *

from .handlers.email import MailtoHandler
from .payments import PaymentFree, PaymentHashcash
from .secret_share import random_int
from .storage import FileSystemStorage
from .util import cute_str, _json_object, _json_object_prop


if os.getuid() == 0 and sys.platform != 'win32':
    DEFAULT_CONFIG_DIR = '/etc/passcrow'
    DEFAULT_DATA_DIR = '/var/spool/passcrow'
else:
    DEFAULT_CONFIG_DIR = appdirs.user_config_dir('passcrow')
    DEFAULT_DATA_DIR = appdirs.user_data_dir('passcrow')


DEFAULT_EXPIRATION = 10 * 366 * 24 * 3600  # 10ish years
DEFAULT_VRFY_TIMEOUT = 1800
DEFAULT_MAX_REQ_BYTES = 4096  # One HDD block, enough for ephemeral recovery

DEFAULT_FREE_TIME = 25 * 3600
DEFAULT_HASHCASH_PARAMS = [
    (11,    183*24*3600),    # Etd time: 1s  (on my Intel Core i5-1035G1)
    (12,    366*24*3600),    #           2s
    (13,  2*366*24*3600),    #           4s
    (14,  5*366*24*3600),    #           8s
    (15, 10*366*24*3600)]    #          16s


class JsonError(_json_object):
    _KEYS = {'error': str}
    error = property(*_json_object_prop('error'))


class PasscrowServer:
    STORAGE_TABLES = {
        'escrow': ['data'],
        'vcodes': ['data'],
        'rlimit': ['data']}

    def __init__(self, storage,
            log=None,
            handlers=None,
            payments=None,
            warnings_to=None,
            country_code=None,
            about_url=None,
            expiration=None,
            max_request_bytes=None,
            vrfy_timeout=None):
        self.log = log or print
        self.storage = storage

        self.country_code = country_code or '??'
        self.about_url = about_url or PASSCROW_ABOUT_URL
        self.expiration = expiration or DEFAULT_EXPIRATION
        self.vrfy_timeout = vrfy_timeout or DEFAULT_VRFY_TIMEOUT
        self.max_request_bytes = max_request_bytes or DEFAULT_MAX_REQ_BYTES

        if not payments:
            payments = [PaymentFree(min(self.expiration, DEFAULT_FREE_TIME))]
            for bits, exp in DEFAULT_HASHCASH_PARAMS:
                if exp < self.expiration:
                    payments.append(PaymentHashcash(self.storage, bits, exp))
                else:
                    payments.append(
                        PaymentHashcash(self.storage, bits, self.expiration))
                    break
        self.payments = dict((p.scheme_id, p) for p in payments)
        self.handlers = handlers or {'mailto': MailtoHandler()}
        self.warnings_to = warnings_to
        self.endpoints = {
            'policy': self.generate_Policy,
            'escrowrequest': self.process_EscrowRequest,
            'deletionrequest': self.process_DeletionRequest,
            'recoveryrequest': self.process_RecoveryRequest,
            'verificationrequest': self.process_VerificationRequest}

        for table, columns in self.STORAGE_TABLES.items():
            self.storage.prepare_table(table, columns)

    def handle(self, user_info, rpc_method, rdata):
        try:
            if isinstance(rdata, dict):
                json_data = rdata
            else:
                if len(rdata) > self.max_request_bytes:
                    return JsonError(error='Request too large')
                json_data = json.loads(rdata or '{}')
        except:
            return JsonError(error='Bad request')
        
        rl_id = hashlib.md5(bytes(str(user_info), 'utf-8')).hexdigest()
        try:
            self.storage.fetch('rlimit', '0-%s' % rl_id)
            return JsonError(error='Sorry, rate limited.')
        except KeyError:
            self.storage.insert('rlimit', b'ping',
                row_id=rl_id,
                expiration=int(time.time() + 1))

        try:
            self.log('%s method=%s' % (user_info, rpc_method))
            return self.endpoints[rpc_method](json_data)
        except KeyError:
            return JsonError(error=('Unsupported: %s' % rpc_method))

    def generate_Policy(self, request_dict):
        po = PolicyObject()
        po.country_code = self.country_code
        po.about_url = self.about_url
        po.kinds = sorted(self.handlers.keys())
        po.max_request_bytes = self.max_request_bytes
        po.max_expiration_seconds = self.expiration
        po.max_timeout_seconds = self.vrfy_timeout
        po.payment_schemes = [
            p.get_policy(request_dict) for p in self.payments.values()]
        return po

    def _take_payment(self, token, data):
        try:
            scheme, cash = token.split(':', 1)
            return self.payments[scheme].process(cash, data)
        except (ValueError, KeyError):
            return 0

    def process_EscrowRequest(self, request_dict):
        resp = EscrowResponse()
        try:
            req = EscrowRequest(request_dict)
            escrow_data = ''.join(req.escrow_data)

            # Note: as a side-effect, this verifies that we can actually
            # decrypt content from this client, which is important since
            # the encrypted EscrowRequest cannot be decrypted until (much)
            # later.
            reqp = req.get_parameters()

            # Check whether we support this kind of Identity
            if reqp.kind not in self.handlers:
                resp.error = 'Unsupported kind of Identity: %s' % reqp.kind
                return resp

            # Calculate expiration as a minimum of what is requested, our
            # global maximum, and whatever was "paid for" in parameters.
            now = int(time.time())
            pay_exp = self._take_payment(reqp.payment, escrow_data)
            resp.expiration = min(
                reqp.expiration, now + min(pay_exp, self.expiration))
            if resp.expiration <= now:
                resp.error = 'Insufficient payment'
                return resp

            # If the user has requested service uptime warnings, add them
            # to our "mailing list" for such things.
            if 'warnings-to' in reqp and reqp.warnings_to and self.warnings_to:
                self.warnings_to(reqp.warnings_to, resp.expiration)

            # If we get this far, we know we can decrypt data from this
            # client and verify their Identity. And they've paid!
            resp.escrow_data_id = _id = self.storage.insert('escrow',
                escrow_data,
                row_id=reqp.prefer_id if ('prefer-id' in reqp) else None,
                expiration=resp.expiration)

            # If we've accepted the proposed ID, just use it
            if 'prefer-id' in reqp and reqp.prefer_id in _id:
                resp.escrow_data_id = reqp.prefer_id


            return resp
        except KeyboardInterrupt:
            raise
        except Exception as e:
            self.log('process_EscrowRequest error: %s' % e)
            resp.error = 'Internal Error'
        return resp

    def process_DeletionRequest(self, request_dict):
        resp = DeletionResponse()
        try:
            req = DeletionRequest(request_dict)
            self.storage.delete('escrow', req.escrow_data_id)
            self.storage.delete('vcodes', req.escrow_data_id)
            return resp
        except KeyboardInterrupt:
            raise
        except Exception as e:
            self.log('process_DeletionRequest error: %s' % e)
            resp.error = 'Internal Error'
        return resp

    def process_VerificationRequest(self, request_dict):
        resp = VerificationResponse()
        try:
            req = VerificationRequest(request_dict)
            resp.escrow_data_id = _id = req.escrow_data_id
            if len(req.prefix) > 1:
                raise ValueError('Bad prefix: %s' % req.prefix)

            esd = EscrowRequestData()
            esd.encrypted_data = self.storage.fetch('escrow', _id)[0]
            esd.decrypt(base64.b64decode(req.escrow_data_key))
            kind = esd.verify.split(':')[0]
            if kind not in self.handlers:
                raise ValueError('Unsupported kind of Identity: %s' % kind)
            handler = self.handlers[kind]

            tmo = esd.timeout if ('timeout' in esd) else self.vrfy_timeout
            tmo = min(tmo, self.vrfy_timeout)
            vcode = '%s-%6.6d' % (req.prefix, random_int(1000000))
            resp.expiration = int(time.time()) + tmo
            self.storage.delete('vcodes', _id)
            self.storage.insert('vcodes', vcode,
                row_id=_id,
                expiration=resp.expiration)

            resp.hint = handler.send_code(
                self, esd.verify, esd.description, vcode, tmo)

            return resp
        except KeyboardInterrupt:
            raise
        except Exception as e:
            self.log('process_VerificationRequest error: %s' % e)
            resp.error = 'Internal Error'
        return resp

    def process_RecoveryRequest(self, request_dict):
        resp = RecoveryResponse()
        try:
            req = RecoveryRequest(request_dict)
            resp.escrow_data_id = _id = req.escrow_data_id

            vcode = str(self.storage.fetch('vcodes', _id)[0].strip(), 'utf-8')
            if req.verification.strip().upper() != vcode.upper():
                resp.error = 'Incorrect verfication code'
                return resp

            esd = EscrowRequestData()
            esd.encrypted_data = self.storage.fetch('escrow', _id)[0]
            esd.decrypt(base64.b64decode(req.escrow_data_key))

            resp.escrow_secret = esd.secret
            return resp
        except KeyboardInterrupt:
            raise
        except Exception as e:
            self.log('process_RecoveryRequest error: %s' % e)
            resp.error = 'Internal Error'
        return resp

    @classmethod
    def Init(cls, user, config_file, data_dir, force=False):
        import pwd
        user_info = pwd.getpwnam(user)
        if isinstance(data_dir, str):
            data_dir = bytes(data_dir, 'utf-8')
        if isinstance(config_file, str):
            config_file = bytes(config_file, 'utf-8')

        if not force:
            if not user_info.pw_uid:
                raise ValueError('Passcrow server should not run as root')
            if config_file[-3:] not in (b'.py', '.py'):
                raise ValueError('Config file name should end in .py')
            if os.path.exists(config_file):
                raise ValueError(
                    'Cravenly refusing to overwrite existing config') 

        config_file = os.path.normpath(os.path.abspath(config_file))
        for dpath, mode in (
                (os.path.dirname(config_file), 0o755),
                (data_dir,                     0o700)):
            if dpath and not os.path.isdir(dpath):
                os.mkdir(dpath, mode)

        os.chown(data_dir, user_info.pw_uid, user_info.pw_gid)
        with open(config_file, 'w') as fd:
            fd.write("""\
## Passcrow Server configuration
#
# This configuration file must be valid Python code. In addition to setting
# variables, plugins are loaded and configured below.
#
###############################################################################

# This is where the default escrow database is stored.
data_dir = %s 


# Server description.
#
# The URL should explain why you are providing Passcrow services to the
# public and something about who you are. Why should users trust you?
# What kind of guarantees (or lack thereof) do you provide?
#
# The country code may be of use to users who have concerns about the
# regulatory domain of their data, smart clients might use this to automate
# spreading shared secrets over multiple countries.
#
about_url = 'https://passcrow.example.org/'
country_code = '%s'


# Server limits; these are upper bounds which constrain what clients can
# request. In particular, we would like expiration to be measured in years
# or even decades, but this is all pretty new and it makes sense to start
# modestly.
#
max_request_bytes = 4096             # Plenty for Ephemeral recovery
expiration        = 366 * 24 * 3600  # Max time-to-live for escrowed data
vrfy_timeout      = 24 * 3600        # Max time-to-live for verification codes


# Verification handlers
#
from passcrow.handlers.email import MailtoHandler

mailto_handler = MailtoHandler(
#
# Uncomment and update SMTP server settings:
#
#   smtp_server     = 'localhost:465',
#   smtp_login      = 'username',
#   smtp_password   = 'password',
#
# OR, uncomment this line to shell out to local mail tools:
#
#   sendmail_binary = '/usr/sbin/sendmail',
#
# Finally, set the From-address of outgoing mail.
#
    mail_from       = 'Passcrow <noreply@example.org>')


# Use a Twilio account to send SMS messages
#sms_handler = passcrow.handlers.TwilioSmsHandler(
#    api_key = '12341241234'),


handlers = {
#   'sms': sms_handler,        # Uncomment to enable sms: verification
#   'tel': sms_handler,        # Uncomment to enable tel: verfication
    'mailto': mailto_handler}

#EOF#
""" % (
                cute_str(data_dir, quotes="'"),
                os.getenv('LANG', '??').split('.')[0].split('_')[-1]))

        return config_file


    @classmethod
    def FromConfig(cls, args):
        SERVER_SETTINGS = {
            'log': ValueError,
            'handlers': ValueError,
            'payments': ValueError,
            'warnings_to': ValueError,
            'country_code': str,
            'about_url': str,
            'expiration': int,
            'max_request_bytes': int,
            'vrfy_timeout': int}

        data_dir = DEFAULT_DATA_DIR
        config_file = os.path.join(DEFAULT_CONFIG_DIR, 'server_config.py')
        if args:
            if os.path.isdir(args[0]):
                data_dir = args.pop(0)
                config_file = os.path.join(data_dir, 'server_config.py')
            elif os.path.exists(args[0]) and args[0][-3:] == '.py':
                config_file = args.pop(0)

        config = {'data_dir': data_dir}
        try:
            with open(config_file, 'rb') as cfd:
                exec(cfd.read(), globals(), config)
        except (IOError, OSError) as e:
            sys.stderr.write('%s\n' % (e,))
            return None
        except Exception as e:
            sys.stderr.write('Error in %s: %s' % (
                cute_str(config_file),
                traceback.format_exc().rsplit('File "<string>", ', 1)[1]))
            return None

        while args:
            opt, arg = args.pop(0), None
            if '=' in opt:
                 opt, arg = opt.split('=', 1)
            if opt[:2] != '--' or opt[2:] not in SERVER_SETTINGS:
                raise ValueError('Invalid option: %s' % opt)
            ss = opt[2:]
            config[ss] = SERVER_SETTINGS[ss](arg or args.pop(0))

        data_dir = config['data_dir']
        storage = config.get('storage')
        if storage is None:
            storage = FileSystemStorage(data_dir)

        return cls(storage,
            **dict((k, config.get(k)) for k in SERVER_SETTINGS))

    def cli_cleanup(self):
        for table in self.STORAGE_TABLES:
            self.storage.expire_table(table)
        return True


if __name__ == '__main__':
    try:
        command = sys.argv[1]
        server = PasscrowServer.FromConfig(sys.argv[2:])
        if not hasattr(server, 'cli_' + command):
            raise ValueError('Invalid command')
    except (IndexError, ValueError):
        sys.stderr.write("""\
Usage: python3 -m passcrow.server CMD /path/to/config.py [<SERVER-OPTS>]

Where CMD is one of:

    cleanup      Perform regular maintenance (expire old data, etc.)

""")
        sys.exit(1)
    sys.exit(0 if getattr(server, 'cli_' + command)() else 1)
