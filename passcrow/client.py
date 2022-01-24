import datetime
import base64
import copy
import datetime
import json
import os
import random
import re
import time
import traceback
import urllib.request

import appdirs

from .aes_utils import random_aesgcm_key, derive_aesgcm_key
from .aes_utils import aesgcm_key_to_int, aesgcm_key_from_int
from .handlers.validators import *
from .util import pmkdir, _json_list, _json_object, _json_object_prop
from .util import _encrypted_json_object
from .proto import *
from .secret_share import random_int, make_random_shares, recover_secret
from .payments import make_payment


SHARED_CONFIG_DIR = appdirs.user_config_dir('passcrow', roaming=False)
SHARED_DATA_DIR = appdirs.user_data_dir('passcrow', roaming=False)

DEFAULT_N = 3
DEFAULT_M = 4

DEFAULT_SLEEP_MIN = 0
DEFAULT_SLEEP_MAX = 600

DEFAULT_PACK_DESC = 'Created using python Passcrow'
DEFAULT_VERIFY_DESC = 'Passcrow Data'

DEFAULT_EXP_DAYS = 365  # Default requested escrow expiration
DEFAULT_TMO_MINS = 30   # Default requested verification timeout

VERIFICATION_PREFIXES = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'

EPHEMERAL_ONLY = 1
EPHEMERAL_BOTH = 2


class ServerError(Exception):
     pass


class EncryptedBlob(_encrypted_json_object):
    _KEYS = {"data": str}
    data = property(*_json_object_prop('data'))


class EscrowRecord(_json_object):
    _KEYS = {
        "kind": str,
        "server": str,
        "response": EscrowResponse,
        "recovery-key": str}

    kind = property(*_json_object_prop('kind'))
    server = property(*_json_object_prop('server'))
    response = property(*_json_object_prop('response'))
    recovery_key = property(*_json_object_prop('recovery-key'))


class RecoveryPack(_encrypted_json_object):
    _KEYS = {
        "name": str,
        "secret": str,
        "created-ts": int,
        "is-ephemeral": bool,
        "ephemeral-id": str,
        "description": str,
        "min-shares": int,
        "shares": _json_list(str),
        "escrow": _json_list(EscrowRecord)}

    name = property(*_json_object_prop('name'))
    secret = property(*_json_object_prop('secret'))
    created_ts = property(*_json_object_prop('created-ts'))
    is_ephemeral = property(*_json_object_prop('is-ephemeral'))
    ephemeral_id = property(*_json_object_prop('ephemeral-id'))
    description = property(*_json_object_prop('description'))
    min_shares = property(*_json_object_prop('min-shares'))
    shares = property(*_json_object_prop('shares'))
    escrow = property(*_json_object_prop('escrow'))

    kinds = property(lambda s: sorted([e.kind for e in s.escrow]))

    created = property(
        lambda s: datetime.datetime.fromtimestamp(s.created_ts))

    expires_ts = property(
        lambda s: min(e.response.expiration for e in s.escrow))

    expires = property(
        lambda s: datetime.datetime.fromtimestamp(s.expires_ts))

    def prefixed_escrow_list(self):
        if 'ephemeral-id' in self:
            escrowed = self.escrow[:-1]
        else:
            escrowed = self.escrow
        prefixes = list(VERIFICATION_PREFIXES)
        return [(prefixes.pop(0), esc) for esc in escrowed]

    def save(self, filename):
        with open(filename, 'wb') as fd:
            fd.write(bytes(str(self), 'utf-8'))

    def load(self, filename):
        with open(filename, 'rb') as fd:
            self.update(json.load(fd))
        return self

    @classmethod
    def ephemeral_escrow_id(cls, key):
        user_key = bytes(key, 'latin-1') if isinstance(key, str) else key
        return str(base64.b16encode(
                derive_aesgcm_key(user_key, salt=b'Escrow ID', length=128)
            ).lower(), 'latin-1')

    @classmethod
    def ephemeral_escrow_key(cls, key, b64=False):
        user_key = bytes(key, 'latin-1') if isinstance(key, str) else key
        escrow_key = derive_aesgcm_key(user_key, salt=b'Escrow Key')
        if b64:
            return str(base64.b64encode(escrow_key), 'latin-1')
        return escrow_key

    def make_ephemeral(self):
        user_key = ''
        while len(user_key) < 16:
            user_key = (base64.b64encode(random_aesgcm_key(length=256))
                .replace(b'/', b'').replace(b'+', b'')
                .replace(b'1', b'').replace(b'l', b'')
                .replace(b'O', b'').replace(b'0', b''))[:16]
        user_key = b'%s-%s-%s-%s' % (
            user_key[:4], user_key[4:8], user_key[8:12], user_key[12:16])

        self.encrypt(derive_aesgcm_key(user_key), compress=True)
        ed, self.encrypted_data = self.encrypted_data, None
        return (str(user_key, 'latin-1'), ed)

    def decrypt_ephemeral(self, ephemeral_id, data):
        user_key = bytes(ephemeral_id.split(':')[-1], 'latin-1')
        self.encrypted_data = data
        self.decrypt(derive_aesgcm_key(user_key), decompress=True)
        self.name = str(user_key, 'latin-1')
        return self


class PasscrowServerPolicy:
    """
    Server policies are expressed as text like so:

        <KIND_LIST> via <SERVER_NAME>

    Where the KIND_LIST is a comma separated list of protocols such
    as `mailto`, `tel` or `sms`.
    """
    def __init__(self):
        self.kinds = []
        self.server = None

    def __str__(self):
        return '%s via %s' % (', '.join(self.kinds), self.server)

    def parse(self, text):
        kinds, self.server = text.split(' via ', 1)
        self.kinds = kinds.replace(' ', '').split(',')
        return self


class PasscrowIdentityPolicy:
    """
    Verification policies are expressed as text like so:

        <ID>[, warn=<ID>][, notify=<ID>][ via <HELPER_NAME>]

    Example:

        mailto:a@a.org via passcrow.example.org
        mailto:a@a.org, warn=-, notify=b@b.com via passcrow.org

    An <ID> is contact URL, such as mailto:bre@example.org or
    tel:+3545885522. For convenience, white-space is collapsed and
    URL prefixes are added automatically to bare e-mail addresses
    and phone numbers. The commas, and order of elements, and the
    word "via" must be exactly as shown above.

    If the server is omitted from a policy, an appropriate one will
    be chosen from the user's Passcrow defaults.
    """
    def __init__(self):
        self.id = None
        self.warn = None
        self.notify = None
        self.server = None
        self.timeout = None
        self.expiration = None

    usable = property(lambda s: s.server and s.id)

    def __str__(self):
        txt = self.id
        if self.warn:
            txt += ', warn=' + self.warn
        if self.notify:
            txt += ', notify=' + self.notify
        if self.server:
            txt += ' via ' + self.server
        return txt

    def _default_pip(self, defaults):
        if not defaults or not defaults.idps:
            return None
        for pip in defaults.idps:
            if pip.id == self.id:
                return copy.copy(pip)
        pip = defaults.idps.pop(0)
        defaults.idps.append(pip)
        return copy.copy(pip)

    def _choose_server(self, pip, defaults):
        if pip.server:
            return pip
        kinds = set([self.id.kind])
        if self.notify:
            kinds.add(self.notify.kind)
        if self.warn:
            kinds.add(self.warn.kind)
        for psp in defaults.servers:
            psp_kinds = set(psp.kinds)
            if not (kinds - psp_kinds):
                pip.server = psp.server
                break
        return pip

    def get_timeout(self):
        if self.timeout is not None:
            return self.timeout
        return (DEFAULT_TMO_MINS * 60)

    def parse(self, txt, defaults=None):
        self.id = re.sub(r'\s+', ' ', str(txt).strip())
        if ' via ' in txt:
            self.id, self.server = self.id.rsplit(' via ', 1)
        if ', notify=' in self.id:
            self.id, self.notify = self.id.rsplit(', notify=')
        if ', warn=' in self.id:
            self.id, self.warn = self.id.rsplit(', warn=')

        dpip = self._default_pip(defaults)

        if self.notify == '-':
            self.notify = None
        elif dpip and not self.notify:
            self.notify = dpip.notify

        if self.warn == '-':
            self.warn = None
        elif dpip and not self.warn:
            self.warn = dpip.warn

        self.id = Identity(self.id)
        self.warn = Identity(self.warn) if self.warn else None
        self.notify = Identity(self.notify) if self.notify else None

        if dpip and not self.server:
            dpip = self._choose_server(dpip, defaults)
            self.server = dpip.server

        return self


class PasscrowClientPolicy:
    def __init__(self, idps=None,
            n=None, m=None,
            servers=None,
            expiration_days=None,
            timeout_minutes=None):
        self.idps = idps or []
        # Set our default ratio
        self.n = DEFAULT_N if (n is None) else n
        self.m = DEFAULT_M if (m is None) else m
        # This is for default policies only
        self.servers = servers or []
        self.expiration_days = expiration_days
        self.timeout_minutes = timeout_minutes

    def absolute_ratio(self, reserve=0):
        available = len(self.idps) - reserve
        if available == 1:   # Zero is never OK
            return 1, 1
        if (0 < self.n <= self.m) and (self.m == available):
            return self.n, self.m

        # Adjust to match the actual number of identities we have.
        adjust = float(available) / self.m
        rm = available
        rn = max(1, round(self.n * adjust))  # Zero is never OK

        return rn, rm

    def __str__(self):
        text = '%d/%d of %s' % (
            self.n,
            self.m,
            ', '.join(str(i) for i in self.idps))
        if self.servers:
            text += ' (%s)' % ', '.join(str(sp) for sp in self.servers)
        return text


def _default_urlopen(url, data=None, headers={}):
    return urllib.request.urlopen(
        urllib.request.Request(url, data=data, headers=headers))


class PasscrowClient:

    PACK_SUFFIX = b'.passcrow'

    def __init__(self,
            config_dir=None, data_dir=None, env_override=True,
            default_ids=None,
            default_n=None,
            default_m=None,
            default_expiration_days=None,
            default_timeout_minutes=None,
            create_dirs=False, logger=None,
            sleep_min=None, sleep_max=None,
            sleep_func=None,
            urlopen_func=None):
        self.log = logger or print
        self.config_dir = config_dir or SHARED_CONFIG_DIR
        self.data_dir = data_dir or SHARED_DATA_DIR
        self.sleep_min = DEFAULT_SLEEP_MIN if sleep_min is None else sleep_min
        self.sleep_max = DEFAULT_SLEEP_MAX if sleep_max is None else sleep_max
        self.expiration_days = default_expiration_days or DEFAULT_EXP_DAYS
        self.timeout_minutes = default_timeout_minutes or DEFAULT_TMO_MINS
        self.default_policy = PasscrowClientPolicy(
             idps=default_ids or [], n=default_n, m=default_m)

        self.sleep = sleep_func or time.sleep
        self.urlopen = urlopen_func or _default_urlopen

        # FIXME: Cache these on disk, load on startup
        self.server_policies = {}

        if env_override:
            self.config_dir = os.getenv('PASSCROW_HOME', self.config_dir)
            self.data_dir = os.getenv('PASSCROW_HOME', self.data_dir)
            self.config_dir = os.getenv('PASSCROW_CONFIG', self.config_dir)
            self.data_dir = os.getenv('PASSCROW_DATA', self.data_dir)

        for path in (self.config_dir, self.data_dir):
            if not os.path.exists(path):
                if not create_dirs:
                    raise OSError('Directory not found: %s' % path)
                pmkdir(path, 0o700)
                self.log('%s: Created %s' % (self, path))
        try:
            self.load_default_policy()
        except (OSError, IOError):
            pass

    def __str__(self):
        if self.config_dir != self.data_dir:
            where = 'config=%s, data=%s' % (self.config_dir, self.data_dir)
        else:
            where = 'home=%s' % self.config_dir
        return ('PasscrowClient(%s)' % where)

    def _get_server_policy(self, server):
        if server not in self.server_policies:
            class Policy(dict):
                pass
            po = PolicyObject(self._rpc(server, Policy()))
            self.server_policies[server] = po
            self.sleep(1.5)  # Play nice with rate limits
        return self.server_policies[server]

    def _packfilename(self, name):
        data_dir = bytes(self.data_dir, 'utf-8')
        try:
            fn = bytes(name, 'us-ascii')
            if b'\\' in fn or b'/' in fn or b':' in fn or fn[:1] == b'.':
                raise ValueError('nope')
        except (ValueError, UnicodeEncodeError):
            fn = b'_' + base64.b32encode(bytes(name, 'utf-8'))
        return os.path.join(data_dir, fn + self.PACK_SUFFIX)

    def __iter__(self):
        data_dir = bytes(self.data_dir, 'utf-8')
        for fn in sorted(os.listdir(data_dir)):
            if fn.endswith(self.PACK_SUFFIX):
                pn = fn[:-len(self.PACK_SUFFIX)]
                if pn[:1] in (b'_'):
                    name = str(base64.b32decode(pn[1:]), 'utf-8')
                else:
                    name = str(pn, 'utf-8')
                yield (name, RecoveryPack().load(self._packfilename(name)))

    def _make_payment(self, idp, expiration, data):
        policy = self._get_server_policy(idp.server)
        plist = sorted([(p.expiration_seconds, p)
            for p in policy.payment_schemes])
        avail = [pp for exp, pp in plist if exp >= expiration]
        if not avail:
            max_exp, unit = plist[-1][0] / 60, 'minutes'
            if max_exp > 120:
                max_exp /= 60
                unit = 'hours'
            if max_exp > 72:
                max_exp /= 24
                unit = 'days'
            raise ValueError('Maximum server escrow time is too short: %d %s'
                % (max_exp, unit))
        return make_payment(avail[0], data)

    def _make_escrow_request(self, share, description, idp, policy,
            escrow_key=None, escrow_id=None):
        erd = EscrowRequestData()
        erd.description = description
        erd.secret = share
        erd.verify = idp.id
        erd.timeout = idp.get_timeout()
        if idp.notify:
            erd.notify = idp.notify
        erd.encrypt(escrow_key or random_aesgcm_key())

        erp = EscrowRequestParameters()
        erp.kind = idp.id.split(':')[0]
        erp.expiration = (policy.expiration_days or self.expiration_days)
        erp.expiration *= (24 * 3600)
        erp.payment = self._make_payment(idp, erp.expiration, str(erd))
        erp.expiration += int(time.time())
        if idp.warn:
            erp.warnings_to = idp.warn
        if escrow_id:
            erp.prefer_id = escrow_id
        erp.encrypt(random_aesgcm_key())

        er = EscrowRequest()
        er.parameters = erp
        er.parameters_key = erp.encryption_key
        er.escrow_data = [erd]
        return er, erd.encryption_key

    def _rpc(self, server, request):
        rpc_method = type(request).__name__.lower()
        return json.load(
            self.urlopen(
                'https://%s/passcrow/%s' % (server, rpc_method),
                data=bytes(str(request), 'latin-1'),
                headers={'Content-type': 'application/json'}))

    def _rpc_task_loop(self, tasks, prep, post, fmt_fail, failures, quick):
        sleeptime = 0
        max_tries = len(tasks) + 3
        while tasks and len(failures) < max_tries:
            self.sleep(sleeptime)  # Has to happen before prep, since hashcash
                                   # work (in prep) is time critical.
            task = tasks.pop(0)
            server, req, extras = prep(task, sleeptime)
            try:
                resp = self._rpc(server, req)
                if 'error' in resp:
                    raise ServerError(resp['error'])
                post(task, server, req, resp, extras)
            except KeyboardInterrupt:
                raise
            except Exception as e:
                failures.append(fmt_fail(task, server, req, extras, e))
                tasks.append(task)
                self.log(failures[-1])

            sleeptime = random.randint(self.sleep_min, self.sleep_max)
            if quick:
                sleeptime = 1
        return (not tasks)

    def pack(self, name):
        try:
            return RecoveryPack().load(self._packfilename(name))
        except (OSError, FileNotFoundError) as ose:
            if ':' in name:
                try:
                    server, user_key = name.split(':')
                    rec_id = RecoveryPack.ephemeral_escrow_id(user_key)
                    rec_key = RecoveryPack.ephemeral_escrow_key(user_key, b64=True)
                    return RecoveryPack().update({
                        'name': name,
                        'shares': [],
                        'escrow': [{
                            'kind': 'ephemeral',
                            'server': server,
                            'recovery-key': rec_key,
                            'response': EscrowResponse().update({
                                'escrow-data-id': rec_id})
                        }],
                        'is-ephemeral': True,
                        'min-shares': 1})
                except (ValueError, KeyError):
                    pass
            raise OSError(ose)

    def protect(self, name, secret, policy,
            quick=False,
            ephemeral=False,
            pack_description=DEFAULT_PACK_DESC,
            verify_description=DEFAULT_VERIFY_DESC):
        # Create our RecoveryPack object
        recovery_pack = RecoveryPack()
        recovery_pack.name = name
        recovery_pack.created_ts = time.time()
        recovery_pack.description = pack_description

        # Create random encryption key
        aes_key = random_aesgcm_key()
        aes_key_int = aesgcm_key_to_int(aes_key)

        # Add aes(A, secret) to recovery pack
        secret = bytes(secret, 'utf-8') if isinstance(secret, str) else secret
        blob = EncryptedBlob(data=str(base64.b64encode(secret), 'latin-1'))
        recovery_pack.secret = blob.encrypt(aes_key)

        # Make sure we have usable N-of-M values; Shamir's Secret Sharing
        # requires an N of at least 3, so we may need to generate some extra
        # shares that we store in the local recovery pack.
        if ephemeral and len(policy.idps) < 2:
            raise ValueError(
                'Ephemeral protection requires at least 2 identities')
        reserve = 1 if ephemeral else 0
        n, m = policy.absolute_ratio(reserve=reserve)
        recovery_pack.min_shares = n
        if m > len(VERIFICATION_PREFIXES):
            raise ValueError(
                'Cannot reasonably handle >%d shares'
                % len(VERIFICATION_PREFIXES))
        extra = max(0, 3 - n)
        n += extra
        m += extra
        # Split A into M parts, with N required, using Shamir's Secret Sharing
        shares = make_random_shares(aes_key_int, n, m)
        self.log(
            'Prepared %d shares (%d local, %d required) for secret %s'
            % (len(shares), extra, n, name))
        recovery_pack.shares = shares[-extra:]
        shares = shares[:-extra]

        # For each ID policy, as server to store Cn, add Hn to pack
        escrowed = []
        failures = []
        def prep(task, delay):
            idp, share, mer_kwargs = task
            self.log(
                'Slept %3.3ds. Escrow share %s for %s with %s'
                % (delay, share.split('-')[0], idp.id, idp.server))
            erec = EscrowRecord()
            erec.kind = idp.id.split(':')[0]
            erec.server = idp.server
            ereq, erec.recovery_key = self._make_escrow_request(
                share, verify_description, idp, policy, **mer_kwargs)
            return (idp.server, ereq, erec)
        def post(task, server, req, resp, erec):
            erec.response = EscrowResponse(resp)
            escrowed.append(erec)
        def post_ephemeral(task, server, req, resp, erec):
            erec.response = r = EscrowResponse(resp)
            escrowed.append(erec)
            if r.escrow_data_id != task[-1]['escrow_id']:
                raise ValueError('Server refused ephemeral escrow ID')
        def fmt_fail(task, server, req, extras, e):
            return '%s via %s: %s' % (task[0].id, server, e)

        tasks = [(idp, shares.pop(0), {}) for idp in policy.idps[reserve:]]
        ok = self._rpc_task_loop(tasks, prep, post, fmt_fail, failures, quick)
        recovery_pack.escrow = escrowed
        if not ok:
            return False

        if ephemeral:
            user_key, epack = recovery_pack.make_ephemeral()
            mer_kwargs = {
                'escrow_id': recovery_pack.ephemeral_escrow_id(user_key),
                'escrow_key': recovery_pack.ephemeral_escrow_key(user_key)}
            ok = self._rpc_task_loop(
                [(policy.idps[0], epack, mer_kwargs)],
                prep, post_ephemeral, fmt_fail, failures, quick)
            if ok:
                e = escrowed[-1]
                if ephemeral == EPHEMERAL_BOTH:
                    recovery_pack.escrow = escrowed
                    recovery_pack.ephemeral_id = '%s:%s' % (e.server, user_key)
                    recovery_pack.save(self._packfilename(name))
                e.recovery_key = user_key
                return e
            else:
                return False
        else:
            # Write recovery pack to local database
            recovery_pack.save(self._packfilename(name))

        return True

    def delete(self, name, remote=True, quick=False):
        path = self._packfilename(name)
        ok, failures = True, []
        if remote:
            def prep(esc, delay):
                dreq = DeletionRequest()
                dreq.escrow_data_id = _id = esc.response.escrow_data_id
                self.log(
                    'Slept %3.3ds. Deleting %s from escrow on %s'
                    % (delay, _id, esc.server))
                return esc.server, dreq, _id
            def post(esc, server, dreq, resp, _id):
                response = DeletionResponse(resp)
            def fmt_fail(esc, server, dreq, _id, e):
                return '%s via %s: %s' % (_id, server, e)

            pack = self.pack(name)
            escrowed = copy.copy(pack.escrow)
            ok = self._rpc_task_loop(
                escrowed, prep, post, fmt_fail, failures, quick)
        if ok and os.path.exists(path):
            try:
                os.remove(path)
            except (OSError, IOError) as e:
                failures.append(e)
        return (not failures)

    def verify(self, pack, quick=False, now=None):
        ok, failures = True, []
        responses = {}
        def prep(prefix_esc, delay):
            vreq = VerificationRequest()
            vreq.prefix, esc = prefix_esc
            vreq.escrow_data_id = _id = esc.response.escrow_data_id
            vreq.escrow_data_key = esc.recovery_key
            self.log(
                'Slept %3.3ds. Verifying %s on %s for %s'
                % (delay, _id, esc.server, pack.name))
            return esc.server, vreq, _id
        def post(prefix_esc, server, vreq, resp, _id):
            responses[prefix_esc[0]] = VerificationResponse(resp)
        def fmt_fail(prefix_esc, server, vreq, _id, e):
            return '%s on %s: %s' % (_id, server, e)

        tasks = pack.prefixed_escrow_list()
        task_dict = dict(tasks)
        self._rpc_task_loop(
            tasks, prep, post, fmt_fail, failures, quick)

        if len(responses) >= pack.min_shares:
            def _info(pfx):
                responses[pfx].prefix = pfx
                responses[pfx].kind = task_dict[pfx].kind
                return responses[pfx]
            return [_info(k) for k in responses]
        else:
            return None

    def recover(self, pack, codes, quick=False):
        ok, failures = True, []
        shares = []
        def prep(vcode_esc, delay):
            rreq = RecoveryRequest()
            rreq.verification, esc = vcode_esc
            rreq.escrow_data_id = _id = esc.response.escrow_data_id
            rreq.escrow_data_key = esc.recovery_key
            self.log(
                'Slept %3.3ds. Verifying %s on %s with %s for %s'
                % (delay, _id, esc.server, rreq.verification, pack.name))
            return esc.server, rreq, _id
        def post(vcode_esc, server, vreq, resp, _id):
            response = RecoveryResponse(resp)
            shares.append(response.escrow_secret)
        def fmt_fail(prefix_esc, server, vreq, _id, e):
            return '%s on %s: %s' % (_id, server, e)

        codes = dict((code[:1].upper(), code) for code in codes)
        tasks = [(codes[c], esc)
            for c, esc in pack.prefixed_escrow_list()
            if c in codes]
        self._rpc_task_loop(
            tasks, prep, post, fmt_fail, failures, quick)

        if len(shares) >= pack.min_shares:
            if (shares[0] == shares[-1]) and 'is-ephemeral' in pack:
                ep = RecoveryPack()
                ep.decrypt_ephemeral(pack.name, shares[0])
                # Write ephemeral recovery pack to local database
                ep.save(self._packfilename(ep.name))
                return ep

            shares.extend(pack.shares)
            aes_key = aesgcm_key_from_int(recover_secret(shares))

            eb = EncryptedBlob()
            eb.encrypted_data = pack.secret
            eb.decrypt(aes_key)

            return base64.b64decode(eb.data)
        else:
            raise KeyError('Recovery failed')

    def default_policy_filename(self):
        return os.path.join(self.config_dir, 'policy.rc')

    def load_default_policy(self):
        n, m = DEFAULT_N, DEFAULT_M
        idps = []
        servers = []
        expiration_days = None
        timeout_minutes = None
        with open(self.default_policy_filename(), 'r') as fd:
            for line in (l.strip() for l in fd):
                if line[:1] == '#' or not line:
                    continue
                line = line.split('#')[0]

                op, what = (l.strip() for l in line.split(':', 1))
                if op == 'ratio':
                    n, m = (int(i) for i in what.split('/'))
                elif op == 'id':
                    idps.append(PasscrowIdentityPolicy().parse(what))
                elif op == 'server':
                    servers.append(PasscrowServerPolicy().parse(what))
                elif op == 'expiration_days':
                    expiration_days = int(what)
                elif op == 'timeout_minutes':
                    timeout_minutes = int(what)
                else:
                    raise ValueError('Unknown setting: %s' % op)
        self.default_policy = PasscrowClientPolicy(
            idps=idps, n=n, m=m, servers=servers)
        if expiration_days:
            self.expiration_days = expiration_days
            self.default_policy.expiration_days = expiration_days
        if timeout_minutes:
            self.timeout_minutes = timeout_minutes
            self.default_policy.timeout_minutes = timeout_minutes

    def save_default_policy(self):
        dp = self.default_policy
        fn = self.default_policy_filename()
        with open(fn, 'w') as fd:
            fd.write("""\
## Default Passcrow policy ##%47.47s
#
# This policy may be used to fill in the blanks when constructing policies
# based on application defaults or user input.
#
""" % ('(%s)' % datetime.datetime.now().ctime()))
            if dp:
                fd.write('## Your settings ##\n')
                if dp.n and dp.m:
                    fd.write('ratio: %d/%d\n' % (dp.n, dp.m))
                for idp in dp.idps:
                    fd.write('id: %s\n' % idp)
                for hs in dp.servers:
                    fd.write('server: %s\n' % hs)
                if dp.expiration_days:
                    fd.write('expiration_days: %s\n' % dp.expiration_days)
                if dp.timeout_minutes:
                    fd.write('timeout_minutes: %s\n' % dp.timeout_minutes)
                fd.write('\n')
            fd.write("""\
## Examples ##                 (Remove the leading # to activate an exmaple)
#
# This determines how many identities must be verified for recovery to
# succeed. If the ratio does not exactly match how many identities are
# available, the client will do its best to approximate.
#
#ratio: 2/3
#
# See `passcrow help protect` for a description of verifications policies;
# identities and servers.
#
#id: user@example.org
#id: user@example.org, notify=bre@example.org
#id: user@example.org via passcrow.example.org
#id: +9995885522 via sms.passcrow.example.org
#
# The only public server at the moment is `passcrow-test.mailpile.is`, which
# is only intended for experimentation. It makes no guarantees about security
# and deletes all data after 30 days, no matter what expiration has been
# requested (or promised).
#
#server: mailto via passcrow-test.mailpile.is
#server: sms, tel via sms.passcrow.example.org
#
#expiration_days: 365   # How long we request key fragments persist in escrow
#timeout_minutes: 30    # How long we need to receive verification codes
#
""")
            fd.write(('#\n# ' +
                PasscrowIdentityPolicy.__doc__.strip() +
                '\n\n\n# ' +
                PasscrowServerPolicy.__doc__.strip() +
                '\n').replace('\n   ', '\n').replace('\n', '\n#'))
        return fn
