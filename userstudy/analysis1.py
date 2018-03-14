"""
crypto/privacy/security policy

This module attempts to collect in one place all of the different
security related decisions made by the app, in order to facilitate
review and testing.

"""
import copy
import hashlib
import json
import ssl
import time




##[ Securely download content from the web ]#################################

def secure_urlget(session, url, data=None, timeout=30, anonymous=False):
    from mailpile.conn_brokers import Master as ConnBroker
    from urllib2 import urlopen

    if session.config.prefs.web_content not in ("on", "anon"):
        raise IOError("Web content is disabled by policy")

    if url[:5].lower() not in ('http:', 'https'):
        raise IOError('Non-HTTP URLs are forbidden: %s' % url)

    if url.startswith('https:'):
        conn_need, conn_reject = [ConnBroker.OUTGOING_HTTPS], []
    else:
        conn_need, conn_reject = [ConnBroker.OUTGOING_HTTP], []

    if session.config.prefs.web_content == "anon" or anonymous:
        conn_reject += [ConnBroker.OUTGOING_TRACKABLE]

    with ConnBroker.context(need=conn_need, reject=conn_reject) as ctx:
        # Flagged #nosec, because the URL scheme is constrained above
        return urlopen(url, data=None, timeout=timeout).read()  # nosec


##[ Common web-server security code ]########################################

CSRF_VALIDITY = 48 * 3600  # How long a CSRF token remains valid

def http_content_security_policy(http_server):
    """
    Calculate the default Content Security Policy string.

    This provides an important line of defense against malicious
    Javascript being injected into our web user-interface.
    """
    # FIXME: Allow deviations in config, for integration purposes
    # FIXME: Clean up Javascript and then make this more strict
    return ("default-src 'self' 'unsafe-inline' 'unsafe-eval'; "
            "img-src 'self' data:")


def make_csrf_token(secret, session_id, ts=None):
    """
    Generate a hashed token from the current timestamp, session ID and
    the server secret, to avoid CSRF attacks.
    """
    ts = '%x' % (ts if (ts is not None) else time.time())
    payload = [secret, session_id, ts]
    return '%s-%s' % (ts, b64w(sha512b64('-'.join(payload))))


def valid_csrf_token(secret, session_id, csrf_token):
    """
    Check the validity of a CSRF token.
    """
    try:
        when = int(csrf_token.split('-')[0], 16)
        return ((when > time.time() - CSRF_VALIDITY) and
                (csrf_token == make_csrf_token(secret, session_id, ts=when)))
    except (ValueError, IndexError):
        return False


##[ Secure-ish handling of passphrases ]#####################################

Scrypt = PBKDF2HMAC = None
try:
    # Depending on whether Cryptography is installed (and which version),
    # this may all fail, all succeed or succeed in part.
    import cryptography.hazmat.backends
    import cryptography.hazmat.primitives.hashes
    from cryptography.exceptions import UnsupportedAlgorithm
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
except ImportError:
    pass


def stretch_with_pbkdf2(password, salt, params):
    return b64w(PBKDF2HMAC(
        backend=cryptography.hazmat.backends.default_backend(),
        algorithm=cryptography.hazmat.primitives.hashes.SHA256(),
        salt=salt,
        iterations=int(params['iterations']),
        length=32).derive(password).encode('base64'))


def stretch_with_scrypt(password, salt, params):
    return b64w(Scrypt(
        backend=cryptography.hazmat.backends.default_backend(),
        salt=salt,
        n=int(params['n']),
        r=int(params['r']),
        p=int(params['p']),
        length=32).derive(password).encode('base64'))


# These are our defaults, based on recommendations found on The Internet.
# The parameters actually used should be stored along with the output so
# we can change them later if they're found to be too weak or flawed in
# some other way.
KDF_PARAMS = {
    'pbkdf2': {
        'iterations': 400000
    },
    'scrypt': {
        'n': 2**17,
        'r': 8,
        'p': 1
    }
}


class SecurePassphraseStorage(object):
    """
    This is slightly obfuscated in-memory storage of passphrases.

    The data is currently stored as an array of integers, which takes
    advantage of Python's internal shared storage for small numbers.
    This is not secure against a determined adversary, but at least the
    passphrase won't be written in the clear to core dumps or swap.

    >>> sps = SecurePassphraseStorage(passphrase='ABC')
    >>> sps.data
    [65, 66, 67]

    To copy a passphrase:

    >>> sps2 = SecurePassphraseStorage().copy(sps)
    >>> sps2.data
    [65, 66, 67]

    To check passphrases for validity, use compare():

    >>> sps.compare('CBA')
    False
    >>> sps.compare('ABC')
    True

    To extract the passphrase, use the get_reader() method to get a
    file-like object that will return the characters of the passphrase
    one byte at a time.

    >>> rdr = sps.get_reader()
    >>> rdr.seek(1)
    >>> [rdr.read(5), rdr.read(), rdr.read(), rdr.read()]
    ['B', 'C', '', '']

    If an expiration time is set, trying to access the passphrase will
    make it evaporate.

    >>> sps.expiration = time.time() - 5
    >>> sps.get_reader() is None
    True
    >>> sps.data is None
    True
    """
    # FIXME: Replace this with a memlocked ctype buffer, whenever possible

    def __init__(self, passphrase=None, stretched=False):
        self.generation = 0
        self.expiration = -1
        self.is_stretched = stretched
        self.stretch_cache = {}
        if passphrase is not None:
            self.set_passphrase(passphrase)
        else:
            self.data = None

    def copy(self, src):
        self.data = src.data
        self.expiration = src.expiration
        self.generation += 1
        return self

    def is_set(self):
        return (self.data is not None)

    def stretches(self, salt, params=None):
        if self.is_stretched:
            yield (self.is_stretched, self)
            return

        if params is None:
            params = KDF_PARAMS

        for which, name, stretch in (
                (Scrypt, 'scrypt', stretch_with_scrypt),
                (PBKDF2HMAC, 'pbkdf2', stretch_with_pbkdf2), ):
            if which:
                try:
                    how = params[name]
                    name += ' ' + json.dumps(how, sort_keys=True)
                    sc_key = '%s/%s' % (name, salt)
                    if sc_key not in self.stretch_cache:
                        pf = intlist_to_string(self.data).encode('utf-8')
                        self.stretch_cache[sc_key] = SecurePassphraseStorage(
                            stretch(pf, salt, how), stretched=name)
                    yield (name, self.stretch_cache[sc_key])
                except (KeyError, AttributeError, UnsupportedAlgorithm):
                    pass

        yield ('clear', self)

    def stretched(self, salt, params=None):
        for name, stretch in self.stretches(salt, params=params):
            return stretch

    def set_passphrase(self, passphrase):
        # This stores the passphrase as a list of integers, which is a
        # primitive in-memory obfuscation relying on how Python represents
        # small integers as globally shared objects. Better Than Nothing!
        self.data = string_to_intlist(passphrase)
        self.stretch_cache = {}
        self.generation += 1

    def compare(self, passphrase):
        if (self.expiration > 0) and (time.time() > self.expiration):
            self.data = None
            return False
        return (self.data is not None and
                self.data == string_to_intlist(passphrase))

    def read_byte_at(self, offset):
        if self.data is None or offset >= len(self.data):
            return ''
        return chr(self.data[offset])

    def get_passphrase(self):
        if self.data is None:
            return ''
        return intlist_to_string(self.data)

    def get_reader(self):
        class SecurePassphraseReader(object):
            def __init__(self, sps):
                self.storage = sps
                self.offset = 0

            def seek(self, offset, whence=0):
                safe_assert(whence == 0)
                self.offset = offset

            def read(self, ignored_bytecount=None):
                one_byte = self.storage.read_byte_at(self.offset)
                self.offset += 1

                return one_byte

            def close(self):
                pass

        if (self.expiration > 0) and (time.time() > self.expiration):
            self.data = None
            return None
        elif self.data is not None:
            return SecurePassphraseReader(self)
        else:
            return None


##[ TLS/SSL security code ]##################################################
#
# We monkey-patch ssl.wrap_socket and ssl.SSLContext.wrap_socket so we can
# implement and enforce our own policies here.
#
KNOWN_TLS_HOSTS = {}


def tls_sock_cert_sha256(sock=None, cert=None):
    if cert is None:
        try:
            peer_cert = sock.getpeercert(binary_form=True)
        except ValueError:
            return None
    else:
        peer_cert = cert

    if peer_cert:
        return unicode(
            hashlib.sha256(peer_cert).digest().encode('base64').strip())
    else:
        return None


def tls_configure(sock, context, args, kwargs):
    # FIXME: We should convert positional arguments to named ones, to
    #        make sure everything Just Works.
    #
    # Pop off any positional arguments that just want defaults
    args = list(args)
    while args and args[-1] is None:
        args.pop(-1)

    kwargs = copy.copy(kwargs)
    if (not hasattr(ssl, 'OP_NO_SSLv3')) and not context:
        # This build/version of Python is insecure!
        # Force the protocol version to TLSv1.
        kwargs['ssl_version'] = kwargs.get('ssl_version', ssl.PROTOCOL_TLSv1)

    # Per-site configuration, SNI and TOFU!
    hostname = None
    accept_certs = []
    if 'server_hostname' in kwargs:
        hostname = '%s:%s' % (kwargs['server_hostname'], sock.getpeername()[1])
        tls_settings = KNOWN_TLS_HOSTS.get(md5_hex(hostname))

        # These defaults allow us to do certificate TOFU
        if tls_settings is not None:
            accept_certs = [c for c in tls_settings.accept_certs]
        kwargs['cert_reqs'] = ssl.CERT_NONE
        if context:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

        # Attempt to configure for Certificate Authorities
        use_web_ca = kwargs.get('use_web_ca',
            tls_settings is None or tls_settings.use_web_ca)
        if use_web_ca:
            try:
                if context:
                    context.load_default_certs()
                    context.verify_mode = ssl.CERT_REQUIRED
                    context.check_hostname = True
                    accept_certs = None
                elif 'ca_certs' in kwargs:
                    kwargs['cert_reqs'] = ssl.CERT_REQUIRED
                    accept_certs = None
                elif hasattr(ssl, 'get_default_verify_paths'):
                    kwargs['cert_reqs'] = ssl.CERT_REQUIRED
                    kwargs['ca_certs'] = ssl.get_default_verify_paths().cafile
                    accept_certs = None
                else:
                    # Fall back to TOFU.
                    pass
            except (NameError, AttributeError):
                # Old Python: Fall back to TOFU
                pass

        if context:
            del kwargs['cert_reqs']
        else:
            # The context-less ssl.wrap_socket() doesn't understand this
            # argument, so get rid of it.
            del kwargs['server_hostname']

    if 'use_web_ca' in kwargs:
        del kwargs['use_web_ca']

    return tuple(args), kwargs, hostname, accept_certs


def tls_new_context():
    if hasattr(ssl, 'OP_NO_SSLv3'):
        return ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    else:
        return ssl.SSLContext(ssl.PROTOCOL_TLSv1)


def tls_cert_tofu(wrapped, accept_certs, sname):
    global KNOWN_TLS_HOSTS
    cert = tls_sock_cert_sha256(wrapped)
    if accept_certs and cert not in accept_certs:
        raise ssl.CertificateError('Unrecognized certificate: %s' % cert)

    skey = md5_hex(sname)
    if skey not in KNOWN_TLS_HOSTS:
        KNOWN_TLS_HOSTS[skey] = {'server': sname}
        KNOWN_TLS_HOSTS[skey].use_web_ca = (accept_certs is None)
    if cert not in KNOWN_TLS_HOSTS[skey].accept_certs:
        KNOWN_TLS_HOSTS[skey].accept_certs.append(cert)


def tls_context_wrap_socket(org_wrap, context, sock, *args, **kwargs):
    args, kwargs, sname, accept_certs = tls_configure(sock, context, args, kwargs)
    tofu = kwargs.get('tofu', True)
    if 'tofu' in kwargs: del kwargs['tofu']
    wrapped = org_wrap(context, sock, *args, **kwargs)
    if tofu:
        tls_cert_tofu(wrapped, accept_certs, sname)
    return wrapped


def tls_wrap_socket(org_wrap, sock, *args, **kwargs):
    args, kwargs, sname, accept_certs = tls_configure(sock, None, args, kwargs)
    tofu = kwargs.get('tofu', True)
    if 'tofu' in kwargs: del kwargs['tofu']
    wrapped = org_wrap(sock, *args, **kwargs)
    if tofu:
        tls_cert_tofu(wrapped, accept_certs, sname)
    return wrapped


##[ Key Trust ]#############################################################

def evaluate_signature_key_trust(config, email, tree):
    """
    This uses historic data from the search engine to refine and expand
    upon the states we get back from GnuPG.

    The new potential signature states are:

      unsigned  We expected a signature from this sender but found none
      changed   The signature was made with a key we've rarely seen before
      signed    The signature was made with a key we've often seen before

    The first state depends on the user's ratio of signed to unsigned
    messages, the second two depend on how frequently we've seen a given
    key used for signatures vs. the total number of signatures.

    These states will supercede the states we get from GnuPG like so:

      * `none` becomes `unsigned`
      * `unknown` or `unverified` may become `changed`
      * `unverified` may become `signed`

    The constants used in this algorithm can be found and tweaked in the
    `prefs.key_trust` section of the configuration file.
    """
    sender = email.get_sender()
    if not sender:
        return

    days = config.prefs.key_trust.window_days
    msgts = long(email.get_msg_info(config.index.MSG_DATE), 36)
    scope = ['dates:%d..%d' % (msgts - (days * 24 * 3600), msgts),
             'from:%s' % sender]

    messages_per_key = {}
    def count(name, terms):
        if name not in messages_per_key:
            msgs = config.index.search(config.background, scope + terms)
            messages_per_key[name] = len(msgs)
        return messages_per_key[name]

    signed = lambda: count('signed', ['has:signature'])
    if signed() < config.prefs.key_trust.threshold:
        return

    total = lambda: count('total', [])
    swr = config.prefs.key_trust.sig_warn_pct / 100.0
    ktr = config.prefs.key_trust.key_trust_pct / 100.0
    knr = config.prefs.key_trust.key_new_pct / 100.0

    def update_siginfo(si):
        stat = si["status"]
        keyid = si.get('keyinfo', '')[-16:].lower()

        # Unsigned message: if the ratio of total signed messages is
        # above config.prefs.sig_warn_pct percent, we EXPECT signatures
        # and warn the user if they're not present.
        if (stat == 'none') and (signed() > swr * total()):
            si["status"] = 'unsigned'

        # Signed by unverified key: Signal that we trust this key if
        # this is the key we've seen most of the time for this user.
        # This is TOFU-ish.
        elif (keyid and
                ('unverified' in stat) and
                (count(keyid, ['sig:%s' % keyid]) > ktr * signed())):
            si["status"] = stat.replace('unverified', 'signed')

        # Signed by a key we have seen very rarely for this user. Gently
        # warn the user that something unsual is going on.
        elif (keyid and
                ('unverified' in stat or 'unknown' in stat) and
                (count(keyid, ['sig:%s' % keyid]) < knr * signed())):
            changed = "mixed-changed" if ("mixed" in stat) else "changed"
            si["status"] = changed

        # FIXME: Compare email timestamp with the signature timestamp.
        #        If they differ by a great deal, treat the signature as
        # invalid? This would make it much harder to copy old signed
        # content (undetected) into new messages.

    if 'crypto' in tree:
        update_siginfo(tree['crypto']['signature'])

    for skey in ('text_parts', 'html_parts', 'attachments'):
        for i, part in enumerate(tree[skey]):
            if 'crypto' in part:
                update_siginfo(part['crypto']['signature'])

    return tree


##[ Setup ]#################################################################

if __name__ != "__main__":
    if hasattr(ssl, 'SSLContext'):
        ssl.SSLContext.wrap_socket = monkey_patch(
            ssl.SSLContext.wrap_socket, tls_context_wrap_socket)
        def add_tls_context(unused_org_wrap, sock, *args, **kwargs):
            try:
                return tls_new_context().wrap_socket(sock, *args, **kwargs)
            except:
                raise
        ssl.wrap_socket = monkey_patch(ssl.wrap_socket, add_tls_context)
    else:
        ssl.wrap_socket = monkey_patch(ssl.wrap_socket, tls_wrap_socket)


##[ Tests ]##################################################################

if __name__ == "__main__":
    import doctest
    import sys
    result = doctest.testmod(optionflags=doctest.ELLIPSIS)
    print '%s' % (result, )
    if result.failed:
        sys.exit(1)


def _explain_encryption(sock):
    try:
        algo, proto, bits = sock.cipher()
        return (
            _('%(tls_version)s (%(bits)s bit %(algorithm)s)')
        ) % {
            'bits': bits,
            'tls_version': proto,
            'algorithm': algo}
    except (ValueError, AttributeError):
        return _('no encryption')


class Capability(object):
    """
    These are constants defining different types of outgoing or incoming
    connections. Brokers use these to describe what sort of connections they
    are capable of handling, and calling code uses these to describe the
    intent of network connection.
    """
    OUTGOING_RAW = 'o:raw'      # Request this to avoid meddling brokers
    OUTGOING_ENCRYPTED = 'o:e'  # Request this if sending encrypted data
    OUTGOING_CLEARTEXT = 'o:c'  # Request this if sending clear-text data
    OUTGOING_TRACKABLE = 'o:t'  # Reject this to require anonymity
    OUTGOING_SMTP = 'o:smtp'    # These inform brokers what protocol is being
    OUTGOING_IMAP = 'o:imap'    # .. used, to allow protocol-specific features
    OUTGOING_POP3 = 'o:pop3'    # .. such as enabling STARTTLS or upgrading
    OUTGOING_HTTP = 'o:http'    # .. HTTP to HTTPS.
    OUTGOING_HTTPS = 'o:https'  # ..
    OUTGOING_SMTPS = 'o:smtps'  # ..
    OUTGOING_POP3S = 'o:pop3s'  # ..
    OUTGOING_IMAPS = 'o:imaps'  # ..

    INCOMING_RAW = 20
    INCOMING_LOCALNET = 21
    INCOMING_INTERNET = 22
    INCOMING_DARKNET = 23
    INCOMING_SMTP = 24
    INCOMING_IMAP = 25
    INCOMING_POP3 = 26
    INCOMING_HTTP = 27
    INCOMING_HTTPS = 28

    ALL_OUTGOING = set([OUTGOING_RAW, OUTGOING_ENCRYPTED, OUTGOING_CLEARTEXT,
                        OUTGOING_TRACKABLE,
                        OUTGOING_SMTP, OUTGOING_IMAP, OUTGOING_POP3,
                        OUTGOING_SMTPS, OUTGOING_IMAPS, OUTGOING_POP3S,
                        OUTGOING_HTTP, OUTGOING_HTTPS])

    ALL_OUTGOING_ENCRYPTED = set([OUTGOING_RAW, OUTGOING_TRACKABLE,
                                  OUTGOING_ENCRYPTED,
                                  OUTGOING_HTTPS, OUTGOING_SMTPS,
                                  OUTGOING_POP3S, OUTGOING_IMAPS])

    ALL_INCOMING = set([INCOMING_RAW, INCOMING_LOCALNET, INCOMING_INTERNET,
                        INCOMING_DARKNET, INCOMING_SMTP, INCOMING_IMAP,
                        INCOMING_POP3, INCOMING_HTTP, INCOMING_HTTPS])


class CapabilityFailure(IOError):
    """
    This exception is raised when capability requirements can't be satisfied.
    It extends the IOError, so unaware code just thinks the network is lame.

    >>> try:
    ...     raise CapabilityFailure('boo')
    ... except IOError:
    ...     print 'ok'
    ok
    """
    pass


class Url(str):
    def __init__(self, *args, **kwargs):
        str.__init__(self, *args, **kwargs)
        self.encryption = None
        self.anonymity = None
        self.on_internet = False
        self.on_localnet = False
        self.on_darknet = None


class BrokeredContext(object):
    """
    This is the context returned by the BaseConnectionBroker.context()
    method. It takes care of monkey-patching the socket.create_connection
    method and then cleaning the mess up afterwards, and collecting metadata
    from the brokers describing what sort of connection was established.

    WARNING: In spite of our best efforts (locking, etc.), mixing brokered
             and unbrokered code will not work well at all. The patching
             approach also limits us to initiating one outgoing connection
             at a time.
    """
    def __init__(self, broker, need=None, reject=None, oneshot=False):
        self._broker = broker
        self._need = need
        self._reject = reject
        self._oneshot = oneshot
        self._monkeys = []
        self._reset()

    def __str__(self):
        hostport = '%s:%s' % (self.address or ('unknown', 'none'))
        if self.error:
            return _('Failed to connect to %s: %s') % (hostport, self.error)

        if self.anonymity:
            network = self.anonymity
        elif self.on_darknet:
            network = self.on_darknet
        elif self.on_localnet:
            network = _('the local network')
        elif self.on_internet:
            network = _('the Internet')
        else:
            return _('Attempting to connect to %(host)s') % {'host': hostport}

        return _('Connected to %(host)s over %(network)s with %(encryption)s.'
                 ) % {
            'network': network,
            'host': hostport,
            'encryption': self.encryption or _('no encryption')
        }

    def _reset(self):
        self.error = None
        self.address = None
        self.encryption = None
        self.anonymity = None
        self.on_internet = False
        self.on_localnet = False
        self.on_darknet = None

    def _unmonkey(self):
        if self._monkeys:
            (socket.create_connection, ) = self._monkeys
            self._monkeys = []
            monkey_lock.release()

    def __enter__(self, *args, **kwargs):
        monkey_lock.acquire()
        self._monkeys = (socket.create_connection, )
        def create_brokered_conn(address, *a, **kw):
            self._reset()
            try:
                return self._broker.create_conn_with_caps(
                    address, self, self._need, self._reject, *a, **kw)
            finally:
                if self._oneshot:
                    self._unmonkey()
        socket.create_connection = create_brokered_conn
        return self

    def __exit__(self, *args, **kwargs):
        self._unmonkey()


class BaseConnectionBroker(Capability):
    """
    This is common code used by most of the connection brokers.
    """
    SUPPORTS = []

    def __init__(self, master=None):
        self.supports = list(self.SUPPORTS)[:]
        self.master = master
        self._config = None
        self._debug = master._debug if (master is not None) else None

    def configure(self):
        self.supports = list(self.SUPPORTS)[:]

    def set_config(self, config):
        self._config = config
        self.configure()

    def config(self):
        if self._config is not None:
            return self._config
        if self.master is not None:
            return self.master.config()
        return None

    def _raise_or_none(self, exc, why):
        if exc is not None:
            raise exc(why)
        return None

    def _check(self, need, reject, _raise=CapabilityFailure):
        for n in need or []:
            if n not in self.supports:
                if self._debug is not None:
                    self._debug('%s: lacking capabilty %s' % (self, n))
                return self._raise_or_none(_raise, 'Lacking %s' % n)
        for n in reject or []:
            if n in self.supports:
                if self._debug is not None:
                    self._debug('%s: unwanted capabilty %s' % (self, n))
                return self._raise_or_none(_raise, 'Unwanted %s' % n)
        if self._debug is not None:
            self._debug('%s: checks passed!' % (self, ))
        return self

    def _describe(self, context, conn):
        return conn

    def debug(self, val):
        self._debug = val
        return self

    def context(self, need=None, reject=None, oneshot=False):
        return BrokeredContext(self, need=need, reject=reject, oneshot=oneshot)

    def create_conn_with_caps(self, address, context, need, reject,
                              *args, **kwargs):
        if context.address is None:
            context.address = address
        conn = self._check(need, reject)._create_connection(context, address,
                                                            *args, **kwargs)
        return self._describe(context, conn)

    def create_connection(self, address, *args, **kwargs):
        n = kwargs.get('need', None)
        r = kwargs.get('reject', None)
        c = kwargs.get('context', None)
        for kw in ('need', 'reject', 'context'):
            if kw in kwargs:
                del kwargs[kw]
        return self.create_conn_with_caps(address, c, n, r, *args, **kwargs)

    # Should implement socket.create_connection or an equivalent.
    # Context, if not None, should be informed with metadata about the
    # connection.
    def _create_connection(self, context, address, *args, **kwargs):
        raise NotImplementedError('Subclasses override this')

    def get_urls(self, listening_fd,
                 need=None, reject=None, **kwargs):
        try:
            return self._check(need, reject)._get_urls(listening_fd, **kwargs)
        except CapabilityFailure:
            return []

    # Returns a list of Url objects for this listener
    def _get_urls(self, listening_fd,
                  proto=None, username=None, password=None):
        raise NotImplementedError('Subclasses override this')


class TcpConnectionBroker(BaseConnectionBroker):
    """
    The basic raw TCP/IP connection broker.

    The only clever thing this class does, is to avoid trying to connect
    to .onion addresses, preventing that from leaking over DNS.
    """
    SUPPORTS = (
        # Normal TCP/IP is not anonymous, and we do not have incoming
        # capability unless we have a public IP.
        (Capability.ALL_OUTGOING) |
        (Capability.ALL_INCOMING - set([Capability.INCOMING_INTERNET]))
    )
    LOCAL_NETWORKS = ['localhost', '127.0.0.1', '::1']
    FIXED_NO_PROXY_LIST = ['localhost', '127.0.0.1', '::1']
    DEBUG_FMT = '%s: Raw TCP conn to: %s'

    def configure(self):
        BaseConnectionBroker.configure(self)
        # FIXME: If our config indicates we have a public IP, add the
        #        INCOMING_INTERNET capability.

    def _describe(self, context, conn):
        (host, port) = conn.getpeername()[:2]
        if host.lower() in self.LOCAL_NETWORKS:
            context.on_localnet = True
        else:
            context.on_internet = True
        context.encryption = None
        return conn

    def _in_no_proxy_list(self, address):
        no_proxy = (self.FIXED_NO_PROXY_LIST +
                    [a.lower().strip()
                     for a in self.config().sys.proxy.no_proxy.split(',')])
        return (address[0].lower() in no_proxy)

    def _avoid(self, address):
        if (self.config().sys.proxy.protocol not in  ('none', 'unknown')
                and not self.config().sys.proxy.fallback
                and not self._in_no_proxy_list(address)):
            raise CapabilityFailure('Proxy fallback is disabled')

    def _broker_avoid(self, address):
        if address[0].endswith('.onion'):
            raise CapabilityFailure('Cannot connect to .onion addresses')

    def _conn(self, address, *args, **kwargs):
        clean_kwargs = dict((k, v) for k, v in kwargs.iteritems()
                            if not k.startswith('_'))
        return org_cconn(address, *args, **clean_kwargs)

    def _create_connection(self, context, address, *args, **kwargs):
        self._avoid(address)
        self._broker_avoid(address)
        if self._debug is not None:
            self._debug(self.DEBUG_FMT % (self, address))
        return self._conn(address, *args, **kwargs)


class SocksConnBroker(TcpConnectionBroker):
    """
    This broker offers the same services as the TcpConnBroker, but over a
    SOCKS connection.
    """
    SUPPORTS = []
    CONFIGURED = Capability.ALL_OUTGOING
    PROXY_TYPES = ('socks5', 'http', 'socks4')
    DEFAULT_PROTO = 'socks5'

    DEBUG_FMT = '%s: Raw SOCKS5 conn to: %s'
    IOERROR_FMT = _('SOCKS error, %s')
    IOERROR_MSG = {
        'timed out': _('timed out'),
        'Host unreachable': _('host unreachable'),
        'Connection refused': _('connection refused')
    }

    def __init__(self, *args, **kwargs):
        TcpConnectionBroker.__init__(self, *args, **kwargs)
        self.proxy_config = None
        self.typemap = {}

    def configure(self):
        BaseConnectionBroker.configure(self)
        if self.config().sys.proxy.protocol in self.PROXY_TYPES:
            self.proxy_config = self.config().sys.proxy
            self.supports = list(self.CONFIGURED)[:]
            self.typemap = {
                'socks5': socks.PROXY_TYPE_SOCKS5,
                'socks4': socks.PROXY_TYPE_SOCKS4,
                'http': socks.PROXY_TYPE_HTTP,
                'tor': socks.PROXY_TYPE_SOCKS5,       # For TorConnBroker
                'tor-risky': socks.PROXY_TYPE_SOCKS5  # For TorConnBroker
            }
        else:
            self.proxy_config = None
            self.supports = []

    def _auth_args(self):
        return {
            'username': self.proxy_config.username or None,
            'password': self.proxy_config.username or None
        }

    def _avoid(self, address):
        if self._in_no_proxy_list(address):
            raise CapabilityFailure('Proxy to %s:%s disabled by policy'
                                    ) % address

    def _fix_address_tuple(self, address):
        return (str(address[0]), int(address[1]))

    def _conn(self, address, timeout=None, source_address=None, **kwargs):
        sock = socks.socksocket()
        proxytype = self.typemap.get(self.proxy_config.protocol,
                                     self.typemap[self.DEFAULT_PROTO])
        sock.setproxy(proxytype=proxytype,
                      addr=self.proxy_config.host,
                      port=int(self.proxy_config.port),
                      rdns=True,
                      **self._auth_args())
        if timeout and timeout is not socket._GLOBAL_DEFAULT_TIMEOUT:
            sock.settimeout(float(timeout))
        if source_address:
            raise CapabilityFailure('Cannot bind source address')
        try:
            address = self._fix_address_tuple(address)
            sock.connect(address)
        except socks.ProxyError as e:
            if self._debug is not None:
                self._debug(traceback.format_exc())
            code, msg = e.message
            raise IOError(_(self.IOERROR_FMT
                            ) % (_(self.IOERROR_MSG.get(msg, msg)), ))
        return sock


class TorConnBroker(SocksConnBroker):
    """
    This broker offers the same services as the TcpConnBroker, but over Tor.

    This removes the "trackable" capability, so requests that reject it can
    find their way here safely...

    This broker only volunteers to carry encrypted traffic, because Tor
    exit nodes may be hostile.
    """
    SUPPORTS = []
    CONFIGURED = (Capability.ALL_OUTGOING_ENCRYPTED
                  - set([Capability.OUTGOING_TRACKABLE]))
    REJECTS = None
    PROXY_TYPES = ('tor', )
    DEFAULT_PROTO = 'tor'

    DEBUG_FMT = '%s: Raw Tor conn to: %s'
    IOERROR_FMT = _('Tor error, %s')
    IOERROR_MSG = dict_merge(SocksConnBroker.IOERROR_MSG, {
        'bad input': _('connection refused')  # FIXME: Is this right?
    })

    def _describe(self, context, conn):
        context.on_darknet = 'Tor'
        context.anonymity = 'Tor'
        return conn

    def _auth_args(self):
        # FIXME: Tor uses the auth information as a signal to change
        #        circuits. We may have use for this at some point.
        return {}

    def _fix_address_tuple(self, address):
        host = str(address[0])
        return (KNOWN_ONION_MAP.get(host.lower(), host), int(address[1]))

    def _broker_avoid(self, address):
        # Disable the avoiding of .onion addresses added above
        pass


class TorRiskyBroker(TorConnBroker):
    """
    This differs from the TorConnBroker in that it will allow "cleartext"
    traffic to anywhere - this is dangerous, because exit nodes could mess
    with our traffic.
    """
    CONFIGURED = (Capability.ALL_OUTGOING
                  - set([Capability.OUTGOING_TRACKABLE]))
    DEBUG_FMT = '%s: Risky Tor conn to: %s'
    PROXY_TYPES = ('tor-risky', )
    DEFAULT_PROTO = 'tor-risky'


class TorOnionBroker(TorConnBroker):
    """
    This broker offers the same services as the TcpConnBroker, but over Tor.

    This removes the "trackable" capability, so requests that reject it can
    find their way here safely...

    This differs from the TorConnBroker in that it will allow "cleartext"
    traffic, since we trust the traffic never leaves the Tor network and
    we don't have hostile exits to worry about.
    """
    SUPPORTS = []
    CONFIGURED = (Capability.ALL_OUTGOING
                  - set([Capability.OUTGOING_TRACKABLE]))
    REJECTS = None
    DEBUG_FMT = '%s: Tor onion conn to: %s'
    PROXY_TYPES = ('tor', 'tor-risky')

    def _broker_avoid(self, address):
        host = KNOWN_ONION_MAP.get(address[0], address[0])
        if not host.endswith('.onion'):
            raise CapabilityFailure('Can only connect to .onion addresses')


class BaseConnectionBrokerProxy(TcpConnectionBroker):
    """
    Brokers based on this establish a RAW connection and then manipulate it
    in some way, generally to implement proxying or TLS wrapping.
    """
    SUPPORTS = []
    WANTS = [Capability.OUTGOING_RAW]
    REJECTS = None

    def _proxy_address(self, address):
        return address

    def _proxy(self, conn):
        raise NotImplementedError('Subclasses override this')

    def _wrap_ssl(self, conn):
        if self._debug is not None:
            self._debug('%s: Wrapping socket with SSL' % (self, ))
        return ssl.wrap_socket(conn)

    def _create_connection(self, context, address, *args, **kwargs):
        address = self._proxy_address(address)
        if self.master:
            conn = self.master.create_conn_with_caps(
                address, context, self.WANTS, self.REJECTS, *args, **kwargs)
        else:
            conn = TcpConnectionBroker._create_connection(self, context,
                                                          address,
                                                          *args, **kwargs)
        return self._proxy(conn)


class AutoTlsConnBroker(BaseConnectionBrokerProxy):
    """
    This broker tries to auto-upgrade connections to use TLS, or at
    least do the SSL handshake here so we can record info about it.
    """
    SUPPORTS = [Capability.OUTGOING_HTTP, Capability.OUTGOING_HTTPS,
                Capability.OUTGOING_IMAPS, Capability.OUTGOING_SMTPS,
                Capability.OUTGOING_POP3S]
    WANTS = [Capability.OUTGOING_RAW, Capability.OUTGOING_ENCRYPTED]

    def _describe(self, context, conn):
        context.encryption = _explain_encryption(conn)
        return conn

    def _proxy_address(self, address):
        if address[0].endswith('.onion'):
            raise CapabilityFailure('I do not like .onion addresses')
        if int(address[1]) != 443:
            # FIXME: Import HTTPS Everywhere database to make this work?
            raise CapabilityFailure('Not breaking clear-text HTTP yet')
        return address

    def _proxy(self, conn):
        return self._wrap_ssl(conn)


class AutoSmtpStartTLSConnBroker(BaseConnectionBrokerProxy):
    pass


class AutoImapStartTLSConnBroker(BaseConnectionBrokerProxy):
    pass


class AutoPop3StartTLSConnBroker(BaseConnectionBrokerProxy):
    pass


class MasterBroker(BaseConnectionBroker):
    """
    This is the master broker. It implements a prioritised list of
    connection brokers, each of which is tried in turn until a match
    is found. As such, more secure brokers should register themselves
    with a higher priority - if they fail, we fall back to less
    secure connection strategies.
    """
    def __init__(self, *args, **kwargs):
        BaseConnectionBroker.__init__(self, *args, **kwargs)
        self.brokers = []
        self.history = []
        self._debug = self._debugger
        self.debug_callback = None

    def configure(self):
        for prio, cb in self.brokers:
            cb.configure()

    def _debugger(self, *args, **kwargs):
        if self.debug_callback is not None:
            self.debug_callback(*args, **kwargs)

    def register_broker(self, priority, cb):
        """
        Brokers should register themselves with priorities as follows:

           - 1000-1999: Content-agnostic raw connections
           - 3000-3999: Secure network layers: VPNs, Tor, I2P, ...
           - 5000-5999: Proxies required to reach the wider Internet
           - 7000-7999: Protocol enhancments (non-security related)
           - 9000-9999: Security-related protocol enhancements

        """
        self.brokers.append((priority, cb(master=self)))
        self.brokers.sort()
        self.brokers.reverse()

    def get_fd_context(self, fileno):
        for t, fd, context in reversed(self.history):
            if fd == fileno:
                return context
        return BrokeredContext(self)

    def create_conn_with_caps(self, address, context, need, reject,
                              *args, **kwargs):
        history_event = kwargs.get('_history_event')
        if history_event is None:
            history_event = [int(time.time()), None, context]
            self.history = self.history[-50:]
            self.history.append(history_event)
            kwargs['_history_event'] = history_event
        else:
            history_event[-1] = context

        if context.address is None:
            context.address = address

        et = v = t = None
        for prio, cb in self.brokers:
            try:
                conn = cb.debug(self._debug).create_conn_with_caps(
                    address, context, need, reject, *args, **kwargs)
                if conn:
                    history_event[1] = conn.fileno()
                    return conn
            except (CapabilityFailure, NotImplementedError):
                # These are internal; we assume they're already logged
                # for debugging but don't bother the user with them.
                pass
            except:
                et, v, t = sys.exc_info()
        if et is not None:
            context.error = '%s' % v
            raise et, v, t

        context.error = _('No connection method found')
        raise CapabilityFailure(context.error)

    def get_urls(self, listening_fd, need=None, reject=None):
        urls = []
        for prio, cb in self.brokers:
            urls.extend(cb.debug(self._debug).get_urls(listening_fd))
        return urls


def DisableUnbrokeredConnections():
    """Enforce the use of brokers EVERYWHERE!"""
    def CreateConnWarning(*args, **kwargs):
        print '*** socket.create_connection used without a broker ***'
        traceback.print_stack()
        raise IOError('FIXME: Please use within a broker context')
    socket.create_connection = CreateConnWarning


class NetworkHistory(Command):
    """Show recent network history"""
    SYNOPSIS = (None, 'logs/network', 'logs/network', None)
    ORDER = ('Internals', 6)
    CONFIG_REQUIRED = False
    IS_USER_ACTIVITY = False

    class CommandResult(Command.CommandResult):
        def as_text(self):
            if self.result:
                def fmt(result):
                    dt = datetime.datetime.fromtimestamp(result[0])
                    return '%2.2d:%2.2d %s' % (dt.hour, dt.minute, result[-1])
                return '\n'.join(fmt(r) for r in self.result)
            return _('No network events recorded')

    def command(self):
        return self._success(_('Listed recent network events'),
                             result=Master.history)


