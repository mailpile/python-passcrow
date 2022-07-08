import datetime
import re
import smtplib
import time

from subprocess import Popen, PIPE

from email.utils import make_msgid, formatdate

from ..messages import *


# This is not a proper e-mail validator; but it will prevent us from
# accepting addresses which might break things. FIXME?
WEAK_EMAIL_RE = re.compile(r'^\S+@[A-Za-z0-9][A-Za-z0-9-\.]*[A-Za-z0-9]$')


def validate_email_identity(mailto):
    proto, email = mailto.split(':', 1)
    if proto not in ('mailto', 'email'):
        raise ValueError('Not a mailto: or email: identity (%s)' % mailto)
    if '@' not in email:
        raise ValueError('E-mail addresses must have an @ sign (%s)' % mailto)
    if not WEAK_EMAIL_RE.match(email):
        raise ValueError(
            'That does not look like an e-mail address (%s)' % mailto)
    return mailto


def make_email_hint(email):
    userpart, domain = email.split('@', 1)
    userpart = userpart.split(':')[-1]
    u1 = userpart[:max(1, len(userpart)//3)]
    if domain in ('gmail.com', 'hotmail.com'):
       # These domains have so many users they don't need to be anonymized,
       # and helping the user recognize them feels like a usability win.
       d1, d2 = '', domain
    else:
       d1 = domain[0]
       d2 = domain[-(2*(len(domain)-1))//3:]
    return '%s*@%s*%s' % (u1, d1, d2)


class EmailHandler:
    DEFAULT_OUTER_TEMPLATE = """\
To: %(to)s
From: %(from)s
Subject: %(subject)s
Date: %(date)s
Message-Id: %(message_id)s
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8
User-Agent: Passcrow Server <%(about_url)s>

%(message)s

-- 
%(signature)s
"""

    def __init__(self,
            smtp_server=None,
            smtp_login=None,
            smtp_password=None,
            sendmail_binary=None,
            outer_template=None,
            mail_from=None):

        if sendmail_binary and smtp_server:
            raise ValueError(
                'Please provide a sendmail binary or SMTP server, not both')

        if not sendmail_binary and not smtp_server:
            sendmail_binary = '/usr/sbin/sendmail'

        if not mail_from:
            if sendmail_binary:
                import socket, os, pwd
                mail_from = ('Passcrow <%s@%s>' % (
                   os.getenv('USER', pwd.getpwuid(os.getuid()).pw_name),
                   os.getenv('HOSTNAME', socket.gethostname())))

        self.smtp_server = smtp_server
        self.smtp_login = smtp_login
        self.smtp_password = smtp_password
        self.sendmail_binary = sendmail_binary
        self.mail_from = mail_from
        self.outer_template = outer_template or self.DEFAULT_OUTER_TEMPLATE

    def subject(self, server, language, description, vcode):
        fmt = VERIFICATION_SUBJECT.get(language)
        return ((fmt or VERIFICATION_SUBJECT['en']) % {
                'description': description,
                'vcode': vcode
            }).strip()

    def body(self, server, language, description, vcode, tmo_seconds):
        fmt = VERIFICATION_BODY_LONG.get(language)
        return ((fmt or VERIFICATION_BODY_LONG) % {
                'description': description,
                'vcode': vcode,
                'timeout_seconds': tmo_seconds,
                'timeout_minutes': (tmo_seconds // 60)
            }).strip()

    def signature(self, server, language):
        fmt = VERIFICATION_BODY_SIGNATURE.get(language)
        return ((fmt or VERIFICATION_BODY_SIGNATURE['en']) % {
                'about_url': server.about_url
            }).strip()

    def _send_via_sendmail(self, server, email, message):
        message = bytes(message, 'utf-8')

        proc = Popen([self.sendmail_binary, email],
            stdin=PIPE, stdout=PIPE, stderr=PIPE)
        (so, se) = proc.communicate(input=message)

        output = str(so + se, 'utf-8')
        server.log('sendmail(%d bytes to %s)=>%d %s'
            % (len(message), email, proc.returncode, output or '(no output)'))

        if proc.returncode != 0:
            raise IOError(se)

    def _send_via_smtp(self, server, email, message):
        message = bytes(message, 'utf-8')
        pmap = {
            25: smtplib.SMTP,
            587: smtplib.SMTP,
            465: smtplib.SMTP_SSL}

        if ':' in self.smtp_server:
            host, port = self.smtp_server.split(':')
            ports = [int(port)]
        else:
            host, ports = self.smtp_server, [465, 587, 25]

        err = 'Failed?'
        for tries, port in enumerate(ports + ports):
            try:
                smtp_cls = pmap.get(port, smtplib.SMTP)
                server.log('SMTP connect(%d) %s(%s, %d)'
                    % (tries, smtp_cls.__name__, host, port))
                with smtp_cls(host, port) as srv:
                    if smtp_cls != smtplib.SMTP_SSL:
                        srv.starttls()
                    if self.smtp_login:
                        srv.login(self.smtp_login, self.smtp_password)
                    srv.sendmail(self.mail_from, email, message)
                    return True
            except smtplib.SMTPAuthenticationError:
                err = 'SMTP login failed'
                break
            except (smtplib.SMTPException, IOError) as e:
                if tries == len(ports)-1:
                    time.sleep(2)
                err = e

        raise IOError('Failed to send: %s' % err)

    def send_code(self, server, lang, email, description, vcode, tmo_seconds):
        email = validate_email_identity(email).split(':', 1)[-1]
        message = self.outer_template % {
            'to': email,
            'from': self.mail_from,
            'subject': self.subject(server, lang, description, vcode),
            'message': self.body(server, lang, description, vcode, tmo_seconds),
            'signature': self.signature(server, lang),
            'about_url': server.about_url,
            'message_id': make_msgid(),
            'date': formatdate()}

        if self.sendmail_binary:
            self._send_via_sendmail(server, email, message)
        else:
            self._send_via_smtp(server, email, message)

        return make_email_hint(email)


class MailtoHandler(EmailHandler):
    pass


from ..proto import register_identity_kind
register_identity_kind('mailto', validate_email_identity, 'e-mail to')
register_identity_kind('email', validate_email_identity, 'e-mail to')
