import base64
import hashlib
import hmac
import os
import re
import json
import ssl
import getpass
import secrets
import shutil
import socket
import subprocess
import sys
import threading
import gc
import atexit


def _local_dependency_dir() -> str:
    base = os.path.abspath(os.path.dirname(__file__)) if '__file__' in globals() else os.getcwd()
    return os.path.join(base, '.cloud_deps')


def ensure_pycryptodomex():
    dep_dir = _local_dependency_dir()
    if dep_dir not in sys.path:
        sys.path.insert(0, dep_dir)
    try:
        from Cryptodome.Cipher import AES as _AES
        return _AES
    except ModuleNotFoundError:
        os.makedirs(dep_dir, exist_ok=True)
        print('[*] Missing dependency: pycryptodomex')
        print('[*] Installing pycryptodomex locally...')
        base_cmd = [
            sys.executable, '-m', 'pip', 'install', '--upgrade', '--no-input',
            '--target', dep_dir, 'pycryptodomex>=3.23.0',
        ]
        attempted = [base_cmd]
        attempted.append(base_cmd[:-2] + ['--break-system-packages'] + base_cmd[-2:])
        last_error = None
        for cmd in attempted:
            try:
                subprocess.check_call(cmd)
                import importlib
                importlib.invalidate_caches()
                if dep_dir not in sys.path:
                    sys.path.insert(0, dep_dir)
                from Cryptodome.Cipher import AES as _AES
                return _AES
            except Exception as exc:
                last_error = exc
        raise RuntimeError(
            'Failed to install pycryptodomex locally. Install it manually with '
            f'"{sys.executable} -m pip install --target {dep_dir} pycryptodomex"'
        ) from last_error


AES = ensure_pycryptodomex()


def ensure_pynacl():
    dep_dir = _local_dependency_dir()
    if dep_dir not in sys.path:
        sys.path.insert(0, dep_dir)
    try:
        from nacl.public import PrivateKey as _NaclPrivateKey, PublicKey as _NaclPublicKey, SealedBox as _SealedBox
        from nacl.signing import SigningKey as _SigningKey, VerifyKey as _VerifyKey
        from nacl.exceptions import BadSignatureError as _BadSignatureError, CryptoError as _NaclCryptoError
        return _NaclPrivateKey, _NaclPublicKey, _SealedBox, _SigningKey, _VerifyKey, _BadSignatureError, _NaclCryptoError
    except ModuleNotFoundError:
        os.makedirs(dep_dir, exist_ok=True)
        print('[*] Missing dependency: pynacl')
        print('[*] Installing pynacl locally...')
        cmd = [
            sys.executable, '-m', 'pip', 'install', '--upgrade', '--no-input',
            '--target', dep_dir, 'pynacl>=1.5.0',
        ]
        try:
            subprocess.check_call(cmd)
        except Exception as exc:
            raise RuntimeError(
                'Failed to install PyNaCl locally. Install it manually with '
                f'"{sys.executable} -m pip install --target {dep_dir} pynacl"'
            ) from exc
        import importlib
        importlib.invalidate_caches()
        if dep_dir not in sys.path:
            sys.path.insert(0, dep_dir)
        from nacl.public import PrivateKey as _NaclPrivateKey, PublicKey as _NaclPublicKey, SealedBox as _SealedBox
        from nacl.signing import SigningKey as _SigningKey, VerifyKey as _VerifyKey
        from nacl.exceptions import BadSignatureError as _BadSignatureError, CryptoError as _NaclCryptoError
        return _NaclPrivateKey, _NaclPublicKey, _SealedBox, _SigningKey, _VerifyKey, _BadSignatureError, _NaclCryptoError


NaclPrivateKey, NaclPublicKey, SealedBox, SigningKey, VerifyKey, BadSignatureError, NaclCryptoError = ensure_pynacl()
import time
from collections import defaultdict, deque
from datetime import datetime
from typing import Deque, Dict, Optional, Set


HOST = '0.0.0.0'
PORT = 5000
DISPLAY_ROWS = 9
MESSAGE_BATCH_LIMIT = 9
MESSAGE_BATCH_SECONDS = 10.0
MAX_MESSAGE_QUEUE = 200
FOCUS_ACTIVITY_GRACE = 2.5
APP_SALT = b'ff6-secure-chat-v5'
MESSAGE_VERSION = 6
INNER_MESSAGE_VERSION = 1
MIN_PADDED_SIZE = 256
PAD_BUCKET = 128
MAX_TEXT_LEN = 2500000
MAX_LINE_LEN = 4000000
HANDSHAKE_TIMEOUT = 20.0
NONCE_CACHE_LIMIT = 2048
MAX_QUEUE_PER_TARGET = 20
E2E_IDENTITY_RETRY_DELAY = 1.25
E2E_IDENTITY_MAX_RETRIES = 5
BASE_DIR = os.path.abspath(os.path.dirname(__file__)) if '__file__' in globals() else os.getcwd()
APP_NAME = 'cloud'
APP_TITLE = 'Black Cloud'
APP_BANNER = r'''
 ____  _            _      ____ _                 _ 
| __ )| | __ _  ___| | __ / ___| | ___  _   _  __| |
|  _ \| |/ _` |/ __| |/ /| |   | |/ _ \| | | |/ _` |
| |_) | | (_| | (__|   < | |___| | (_) | |_| | (_| |
|____/|_|\__,_|\___|_|\_\ \____|_|\___/ \__,_|\__,_|

            .--.                                  .--.
         .-(    ).                             .-(    ).
        (___.__)__)   B L A C K   C L O U D   (___.__)__)
'''
TLS_CERT_FILE = os.path.join(BASE_DIR, 'cloud_server.crt')
TLS_KEY_FILE = os.path.join(BASE_DIR, 'cloud_server.key')
TLS_PIN_FILE = os.path.join(BASE_DIR, 'cloud_known_servers.json')
TLS_COMMON_NAME = 'cloud-local'
TLS_ALPN_PROTOCOL = 'cloud/1'
CHANNEL_SALT_FILE = os.path.join(BASE_DIR, 'cloud_channel_salts.json')
CHANNEL_AUTH_FILE = os.path.join(BASE_DIR, 'cloud_channel_auth.json')
IDENTITY_FILE = os.path.join(BASE_DIR, 'cloud_identity.json')
PEER_PINS_FILE = os.path.join(BASE_DIR, 'cloud_peer_pins.json')
LOCAL_SETTINGS_FILE = os.path.join(BASE_DIR, 'cloud_settings.enc')
IMAGE_PACKET_PREFIX = 'BCIMG1|'
IMAGE_CHUNK_PREFIX = 'BCIMGCHUNK1|'
IMAGE_CHUNK_PAYLOAD_SIZE = 4096
IMAGE_CHUNK_SEND_PAUSE_SECONDS = 0.02
IMAGE_CHUNK_TTL_SECONDS = 300.0
MAX_IMAGE_CHUNKS = 4096
MAX_IMAGE_BYTES = 5000000
IMAGE_MEMORY_LIMIT = 200
SECURE_IMAGE_WIPE_PASSES = 3
STREAM_GUARD_ENABLED = True
STRIP_IMAGE_METADATA_ENABLED = True
REMEMBER_CONNECTION_ENABLED = True
ALIAS_TAG_LEN = 8
MIN_PASSWORD_LEN = 14
RATE_LIMIT_WINDOW = 2.0
RATE_LIMIT_MAX = 18
DM_REKEY_MESSAGES = 24
TOKEN_ALLOWED = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-#')
DISPLAY_ALLOWED_CONTROL = {'\n', '\t'}
ANSI_RE = re.compile(r'\x1b\[[0-9;?]*[ -/]*[@-~]')
RFC3526_GROUP14_PRIME = int(
    'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1'
    '29024E088A67CC74020BBEA63B139B22514A08798E3404DD'
    'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245'
    'E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED'
    'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D'
    'C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F'
    '83655D23DCA3AD961C62F356208552BB9ED529077096966D'
    '670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B'
    'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9'
    'DE2BCBF6955817183995497CEA956AE515D2261898FA0510'
    '15728E5A8AACAA68FFFFFFFFFFFFFFFF',
    16,
)
RFC3526_GROUP14_GENERATOR = 2


class Colors:
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    BRIGHT_BLACK = '\033[90m'
    BRIGHT_RED = '\033[91m'
    BRIGHT_GREEN = '\033[92m'
    BRIGHT_YELLOW = '\033[93m'
    BRIGHT_BLUE = '\033[94m'
    BRIGHT_MAGENTA = '\033[95m'
    BRIGHT_CYAN = '\033[96m'
    BRIGHT_WHITE = '\033[97m'


COLOR_ENABLED = False


def enable_ansi_on_windows() -> None:
    if os.name != 'nt':
        return
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)
    except Exception:
        pass


def init_colors() -> None:
    global COLOR_ENABLED
    enable_ansi_on_windows()
    COLOR_ENABLED = sys.stdout.isatty() and os.environ.get('NO_COLOR') is None


init_colors()


def c(text: str, color: str) -> str:
    if not COLOR_ENABLED:
        return text
    return f'{color}{text}{Colors.RESET}'


def print_banner() -> None:
    banner_colors = [
        Colors.BRIGHT_WHITE,
        Colors.BRIGHT_CYAN,
        Colors.BRIGHT_BLUE,
        Colors.BRIGHT_MAGENTA,
    ]
    for idx, line in enumerate(APP_BANNER.splitlines()):
        if not line.strip():
            print()
            continue
        print(c(line, Colors.BOLD + banner_colors[idx % len(banner_colors)]))
    print(c(APP_TITLE, Colors.BOLD + Colors.BRIGHT_WHITE))


STATUS_COLOR = {
    'INFO': Colors.BRIGHT_CYAN,
    'OK': Colors.BRIGHT_GREEN,
    'WARN': Colors.BRIGHT_YELLOW,
    'ERR': Colors.BRIGHT_RED,
    'SECURE': Colors.BRIGHT_MAGENTA,
}

USER_COLOR_POOL = [
    Colors.BRIGHT_CYAN,
    Colors.BRIGHT_GREEN,
    Colors.BRIGHT_YELLOW,
    Colors.BRIGHT_BLUE,
    Colors.BRIGHT_MAGENTA,
    Colors.CYAN,
    Colors.GREEN,
    Colors.YELLOW,
    Colors.BLUE,
    Colors.MAGENTA,
]


# ===================== TLS HELPERS =====================
def tls_fingerprint_from_der(cert_der: bytes) -> str:
    return hashlib.sha256(cert_der).hexdigest().upper()


def load_tls_pins() -> dict:
    try:
        with open(TLS_PIN_FILE, 'r', encoding='utf-8') as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except FileNotFoundError:
        return {}
    except Exception:
        return {}


def save_tls_pins(pins: dict) -> None:
    tmp = TLS_PIN_FILE + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as fh:
        json.dump(pins, fh, indent=2, sort_keys=True)
    os.replace(tmp, TLS_PIN_FILE)


def ensure_server_certificate() -> tuple[str, str]:
    if os.path.exists(TLS_CERT_FILE) and os.path.exists(TLS_KEY_FILE):
        return TLS_CERT_FILE, TLS_KEY_FILE

    openssl_bin = shutil.which('openssl')
    if not openssl_bin:
        raise RuntimeError('TLS certificate missing and openssl is not installed')

    cmd = [
        openssl_bin, 'req', '-x509', '-newkey', 'rsa:3072',
        '-keyout', TLS_KEY_FILE, '-out', TLS_CERT_FILE,
        '-sha256', '-days', '3650', '-nodes',
        '-subj', f'/CN={TLS_COMMON_NAME}',
        '-addext', f'subjectAltName=DNS:{TLS_COMMON_NAME},IP:127.0.0.1,IP:::1',
        '-addext', 'extendedKeyUsage=serverAuth',
    ]
    subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        os.chmod(TLS_KEY_FILE, 0o600)
    except OSError:
        pass
    return TLS_CERT_FILE, TLS_KEY_FILE


def configure_tls_context(ctx: ssl.SSLContext) -> ssl.SSLContext:
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    except Exception:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if hasattr(ssl, 'OP_NO_COMPRESSION'):
        ctx.options |= ssl.OP_NO_COMPRESSION
    if hasattr(ssl, 'OP_NO_TICKET'):
        ctx.options |= ssl.OP_NO_TICKET
    if hasattr(ssl, 'OP_NO_RENEGOTIATION'):
        ctx.options |= ssl.OP_NO_RENEGOTIATION
    try:
        ctx.set_alpn_protocols([TLS_ALPN_PROTOCOL])
    except Exception:
        pass
    try:
        ctx.set_ciphersuites('TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256')
    except Exception:
        pass
    try:
        ctx.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20')
    except Exception:
        pass
    if hasattr(ctx, 'num_tickets'):
        try:
            ctx.num_tickets = 0
        except Exception:
            pass
    return ctx


def build_server_ssl_context() -> ssl.SSLContext:
    cert_file, key_file = ensure_server_certificate()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    configure_tls_context(ctx)
    ctx.load_cert_chain(certfile=cert_file, keyfile=key_file)
    return ctx


def build_client_ssl_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    configure_tls_context(ctx)
    return ctx


def save_tls_pin(address: str, fingerprint: str) -> None:
    pins = load_tls_pins()
    pins[address] = fingerprint
    save_tls_pins(pins)


def pin_or_verify_server_certificate(address: str, cert_der: bytes) -> tuple[str, str, Optional[str]]:
    fingerprint = tls_fingerprint_from_der(cert_der)
    pins = load_tls_pins()
    known = pins.get(address)
    if not known:
        return fingerprint, 'new', None
    if known != fingerprint:
        return fingerprint, 'mismatch', known
    return fingerprint, 'verified', known


def load_channel_salts() -> dict:
    try:
        with open(CHANNEL_SALT_FILE, 'r', encoding='utf-8') as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except FileNotFoundError:
        return {}
    except Exception:
        return {}


def save_channel_salts(salts: dict) -> None:
    tmp = CHANNEL_SALT_FILE + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as fh:
        json.dump(salts, fh, indent=2, sort_keys=True)
    os.replace(tmp, CHANNEL_SALT_FILE)


def load_channel_auth() -> dict:
    try:
        with open(CHANNEL_AUTH_FILE, 'r', encoding='utf-8') as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except FileNotFoundError:
        return {}
    except Exception:
        return {}


def save_channel_auth(channel_auth: dict) -> None:
    tmp = CHANNEL_AUTH_FILE + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as fh:
        json.dump(channel_auth, fh, indent=2, sort_keys=True)
    os.replace(tmp, CHANNEL_AUTH_FILE)


# ===================== CRYPTO =====================
AES_GCM_NONCE_LEN = 12
AES_GCM_TAG_LEN = 16
WRAPPED_KEY_LEN = 32


def get_random_bytes(length: int) -> bytes:
    return os.urandom(length)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    output = bytearray()
    block = b''
    counter = 1
    while len(output) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        output.extend(block)
        counter += 1
    return bytes(output[:length])


def derive_master_password_key(password: str, server_context: bytes) -> bytes:
    if not server_context:
        raise RuntimeError('Missing server context for password KDF')
    kdf_salt = sha256(APP_SALT + b'|server-context|' + server_context)
    last_error = None
    for cost in (2**15, 2**14, 2**13):
        try:
            return hashlib.scrypt(
                password.encode('utf-8'),
                salt=kdf_salt,
                n=cost,
                r=8,
                p=1,
                dklen=32,
            )
        except ValueError as exc:
            last_error = exc
            continue
    raise RuntimeError(f'scrypt unavailable: {last_error}')


def derive_channel_key(master_key: bytes, channel: str, channel_salt: bytes) -> bytes:
    if not master_key:
        raise RuntimeError('Missing master key')
    if not channel_salt:
        raise RuntimeError('Missing channel salt')
    channel_bytes = sanitize_token(channel, default='general').encode('utf-8')
    prk = hkdf_extract(APP_SALT + b'|channel|' + channel_salt, master_key)
    return hkdf_expand(prk, b'channel:' + channel_bytes, 32)


def derive_channel_auth_verifier(master_key: bytes, channel: str, channel_salt: bytes) -> str:
    if not master_key:
        raise RuntimeError('Missing master key')
    if not channel_salt:
        raise RuntimeError('Missing channel salt')
    channel_bytes = sanitize_token(channel, default='general').encode('utf-8')
    prk = hkdf_extract(APP_SALT + b'|channel-auth|' + channel_salt, master_key)
    verifier = hkdf_expand(prk, b'channel-auth:' + channel_bytes, 32)
    return base64.b64encode(verifier).decode('utf-8')


def _pack_plaintext(plaintext: bytes) -> bytes:
    if len(plaintext) > MAX_TEXT_LEN:
        raise ValueError('Message too long')

    header = len(plaintext).to_bytes(4, 'big')
    base_length = len(header) + len(plaintext)
    target = max(MIN_PADDED_SIZE, ((base_length + PAD_BUCKET - 1) // PAD_BUCKET) * PAD_BUCKET)
    if target < 2048:
        target += secrets.choice((0, PAD_BUCKET))
    padding = get_random_bytes(target - base_length)
    return header + plaintext + padding


def _unpack_plaintext(payload: bytes) -> bytes:
    if len(payload) < 4:
        raise ValueError('Invalid payload')
    msg_length = int.from_bytes(payload[:4], 'big')
    if msg_length < 0 or msg_length > MAX_TEXT_LEN or 4 + msg_length > len(payload):
        raise ValueError('Invalid payload length')
    return payload[4:4 + msg_length]


class NonceCache:
    def __init__(self, limit: int = NONCE_CACHE_LIMIT):
        self.limit = limit
        self._deque: Deque[bytes] = deque()
        self._set: Set[bytes] = set()
        self._lock = threading.Lock()

    def seen_or_add(self, token: bytes) -> bool:
        with self._lock:
            if token in self._set:
                return True
            self._deque.append(token)
            self._set.add(token)
            while len(self._deque) > self.limit:
                old = self._deque.popleft()
                self._set.discard(old)
            return False


class CryptoError(Exception):
    pass


def _derive_message_wrap_key(master_key: bytes, wrap_nonce: bytes, aad: bytes) -> bytes:
    prk = hkdf_extract(APP_SALT + b'|msg-wrap', master_key)
    return hkdf_expand(prk, b'wrap|' + wrap_nonce + b'|' + aad, 32)


def _aes256_gcm_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=AES_GCM_TAG_LEN)
    if aad:
        cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return ciphertext, tag


def _aes256_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=AES_GCM_TAG_LEN)
    if aad:
        cipher.update(aad)
    return cipher.decrypt_and_verify(ciphertext, tag)


def encrypt(msg: str, key: bytes, aad: bytes = b'') -> str:
    plaintext = _pack_plaintext(msg.encode('utf-8'))
    message_key = get_random_bytes(WRAPPED_KEY_LEN)
    message_nonce = get_random_bytes(AES_GCM_NONCE_LEN)
    ciphertext, message_tag = _aes256_gcm_encrypt(message_key, message_nonce, plaintext, aad + b'|inner')

    wrap_nonce = get_random_bytes(AES_GCM_NONCE_LEN)
    wrap_key = _derive_message_wrap_key(key, wrap_nonce, aad)
    wrapped_key, wrap_tag = _aes256_gcm_encrypt(wrap_key, wrap_nonce, message_key, aad + b'|wrap')

    body = (
        bytes([MESSAGE_VERSION]) +
        wrap_nonce + wrap_tag + wrapped_key +
        message_nonce + message_tag + ciphertext
    )
    return base64.b64encode(body).decode('utf-8')


def decrypt(data: str, key: bytes, aad: bytes = b'', nonce_cache: Optional[NonceCache] = None) -> str:
    try:
        raw = base64.b64decode(data.encode('utf-8'), validate=True)
    except Exception as exc:
        raise CryptoError('Invalid base64') from exc

    min_len = 1 + AES_GCM_NONCE_LEN + AES_GCM_TAG_LEN + WRAPPED_KEY_LEN + AES_GCM_NONCE_LEN + AES_GCM_TAG_LEN
    if len(raw) < min_len:
        raise CryptoError('Packet too short')

    if raw[0] != MESSAGE_VERSION:
        raise CryptoError('Unsupported message version')

    offset = 1
    wrap_nonce = raw[offset:offset + AES_GCM_NONCE_LEN]
    offset += AES_GCM_NONCE_LEN
    wrap_tag = raw[offset:offset + AES_GCM_TAG_LEN]
    offset += AES_GCM_TAG_LEN
    wrapped_key = raw[offset:offset + WRAPPED_KEY_LEN]
    offset += WRAPPED_KEY_LEN
    message_nonce = raw[offset:offset + AES_GCM_NONCE_LEN]
    offset += AES_GCM_NONCE_LEN
    message_tag = raw[offset:offset + AES_GCM_TAG_LEN]
    offset += AES_GCM_TAG_LEN
    ciphertext = raw[offset:]

    replay_token = sha256(raw[:offset] + message_tag)
    if nonce_cache and nonce_cache.seen_or_add(replay_token):
        raise CryptoError('Replay detected')

    try:
        wrap_key = _derive_message_wrap_key(key, wrap_nonce, aad)
        message_key = _aes256_gcm_decrypt(wrap_key, wrap_nonce, wrapped_key, wrap_tag, aad + b'|wrap')
        if len(message_key) != WRAPPED_KEY_LEN:
            raise CryptoError('Invalid message key length')
        padded_plaintext = _aes256_gcm_decrypt(message_key, message_nonce, ciphertext, message_tag, aad + b'|inner')
        plaintext = _unpack_plaintext(padded_plaintext)
        return plaintext.decode('utf-8')
    except ValueError as exc:
        raise CryptoError('Authentication failed') from exc
    except CryptoError:
        raise
    except Exception as exc:
        raise CryptoError('Decryption failed') from exc


# ===================== DIFFIE-HELLMAN =====================
def int_to_bytes(value: int) -> bytes:
    if value == 0:
        return b'\x00'
    return value.to_bytes((value.bit_length() + 7) // 8, 'big')


def generate_dh():
    priv = secrets.randbelow(RFC3526_GROUP14_PRIME - 3) + 2
    pub = pow(RFC3526_GROUP14_GENERATOR, priv, RFC3526_GROUP14_PRIME)
    return priv, pub


def is_valid_dh_public(value: int) -> bool:
    return 2 <= value <= RFC3526_GROUP14_PRIME - 2


def compute_shared(their_pub: int, my_priv: int) -> bytes:
    if not is_valid_dh_public(their_pub):
        raise ValueError('Invalid DH public value')
    shared = pow(their_pub, my_priv, RFC3526_GROUP14_PRIME)
    return sha256(int_to_bytes(shared))


def make_handshake_transcript(
    initiator: str,
    responder: str,
    channel: str,
    init_pub: int,
    resp_pub: int,
    init_nonce: str,
    resp_nonce: str,
) -> bytes:
    return (
        f'{sanitize_token(initiator)}|{sanitize_token(responder)}|'
        f'{sanitize_token(channel, default="general")}|{init_pub}|{resp_pub}|{init_nonce}|{resp_nonce}'
    ).encode('utf-8')


def make_handshake_auth(channel_key: bytes, label: bytes, transcript: bytes) -> str:
    return base64.b64encode(hmac.new(channel_key, label + b'|' + transcript, hashlib.sha256).digest()).decode('utf-8')


def verify_handshake_auth(channel_key: bytes, label: bytes, transcript: bytes, token: str) -> bool:
    try:
        supplied = base64.b64decode(token.encode('utf-8'), validate=True)
    except Exception:
        return False
    expected = hmac.new(channel_key, label + b'|' + transcript, hashlib.sha256).digest()
    return hmac.compare_digest(expected, supplied)


def derive_dm_session_key(shared_secret: bytes, transcript: bytes) -> bytes:
    prk = hkdf_extract(APP_SALT + b'|dm', shared_secret)
    return hkdf_expand(prk, b'dm-session|' + transcript, 32)


def init_dm_chain_keys(session_key: bytes, initiator: str, responder: str, local_user: str) -> tuple[bytes, bytes]:
    prk = hkdf_extract(APP_SALT + b'|dm-chains', session_key)
    forward = hkdf_expand(prk, f'{sanitize_token(initiator)}->{sanitize_token(responder)}'.encode('utf-8'), 32)
    backward = hkdf_expand(prk, f'{sanitize_token(responder)}->{sanitize_token(initiator)}'.encode('utf-8'), 32)
    if sanitize_token(local_user) == sanitize_token(initiator):
        return forward, backward
    return backward, forward


def ratchet_chain_key(chain_key: bytes) -> tuple[bytes, bytes]:
    prk = hkdf_extract(APP_SALT + b'|dm-ratchet', chain_key)
    msg_key = hkdf_expand(prk, b'msg', 32)
    next_key = hkdf_expand(prk, b'next', 32)
    return msg_key, next_key


def fingerprint_key(key: bytes) -> str:
    raw = hashlib.sha256(b'fingerprint|' + key).hexdigest().upper()
    return '-'.join(raw[i:i + 4] for i in range(0, 16, 4))


def session_id_from_key(key: bytes, label: bytes = b'session') -> str:
    return hashlib.sha256(label + b'|' + key).hexdigest()[:16]


def pack_secure_inner(sender: str, message: str, seq: int, session_id: str) -> str:
    if seq < 1:
        raise ValueError('Invalid message sequence')
    safe_sender = sanitize_token(sender, default='user', max_len=48)
    safe_session = sanitize_token(session_id, default='sess', max_len=24)
    safe_message = message.replace('\r', ' ').replace('\x00', '?')
    return f'{INNER_MESSAGE_VERSION}|{safe_session}|{seq}|{safe_sender}|{safe_message}'


def unpack_secure_inner(payload: str) -> tuple[str, int, str, str]:
    parts = payload.split('|', 4)
    if len(parts) != 5:
        raise ValueError('Invalid secure envelope')
    version_s, session_id, seq_s, sender, message = parts
    try:
        version = int(version_s)
        seq = int(seq_s)
    except ValueError as exc:
        raise ValueError('Invalid secure envelope') from exc
    if version != INNER_MESSAGE_VERSION:
        raise ValueError('Unsupported secure envelope')
    if seq < 1:
        raise ValueError('Invalid message sequence')
    safe_session = sanitize_token(session_id, default='sess', max_len=24)
    safe_sender = sanitize_token(sender, default='user', max_len=48)
    return safe_session, seq, safe_sender, message


def accept_monotonic_sequence(cache: dict, peer: str, seq: int) -> None:
    if seq < 1:
        raise ValueError('Invalid message sequence')
    last = int(cache.get(peer, 0))
    if seq <= last:
        raise ValueError('Stale or replayed message sequence')
    cache[peer] = seq


# ===================== SHARED HELPERS =====================
def now() -> str:
    return datetime.now().strftime('%H:%M:%S')


def sanitize_token(value: str, default: str = 'general', max_len: int = 32) -> str:
    cleaned = ''.join(ch for ch in (value or '').strip() if ch in TOKEN_ALLOWED)
    return cleaned[:max_len] or default


def sanitize_display_text(text: str, limit: int = 220) -> str:
    cleaned = ANSI_RE.sub('', text)
    cleaned = ''.join(ch if ch.isprintable() or ch in DISPLAY_ALLOWED_CONTROL else '?' for ch in cleaned)
    cleaned = cleaned.replace('\r', ' ')
    cleaned = cleaned.replace('\n', ' ↩ ')
    if len(cleaned) > limit:
        return cleaned[:limit - 1] + '…'
    return cleaned


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub('', text)


def visible_len(text: str) -> int:
    return len(strip_ansi(text))


def truncate_ansi(text: str, width: int) -> str:
    if width <= 0:
        return ''
    output = []
    visible = 0
    i = 0
    while i < len(text) and visible < width:
        if text[i] == '\x1b':
            match = ANSI_RE.match(text, i)
            if match:
                output.append(match.group(0))
                i = match.end()
                continue
        output.append(text[i])
        visible += 1
        i += 1
    result = ''.join(output)
    if COLOR_ENABLED and result.endswith(Colors.RESET):
        return result
    if COLOR_ENABLED and '\x1b[' in result:
        return result + Colors.RESET
    return result


def pad_ansi(text: str, width: int) -> str:
    clipped = truncate_ansi(text, width)
    return clipped + ' ' * max(0, width - visible_len(clipped))


def alias_tag(username: str) -> str:
    safe_name = sanitize_token(username, default='user', max_len=48)
    if not safe_name:
        return 'anon-00000000'
    if not channel_key:
        raw = hashlib.sha256(b'alias|' + safe_name.encode('utf-8')).hexdigest().upper()
    else:
        raw = hmac.new(channel_key, b'alias|' + safe_name.encode('utf-8'), hashlib.sha256).hexdigest().upper()
    return f'anon-{raw[:ALIAS_TAG_LEN]}'


def display_name(username: str) -> str:
    return alias_tag(username)


def status_line(level: str, text: str) -> str:
    level = level.upper()
    prefix = c(f'[{level}]', STATUS_COLOR.get(level, Colors.WHITE))
    return f'{prefix} {text}'


def get_user_color(username: str) -> str:
    safe_name = sanitize_token(username, default='user', max_len=48)
    digest = hashlib.sha256(safe_name.encode('utf-8')).digest()
    return USER_COLOR_POOL[digest[0] % len(USER_COLOR_POOL)]


def color_user(username: str) -> str:
    safe_name = sanitize_token(username, default='user', max_len=48)
    return c(display_name(safe_name), get_user_color(safe_name))


def format_user_cell(username: str, width: int) -> str:
    safe_name = sanitize_token(username, default='', max_len=48)
    if not safe_name:
        return ''.ljust(width)
    return pad_ansi(color_user(safe_name), width)


def resolve_user_reference(reference: str) -> str:
    target = sanitize_token(reference, default='')
    if not target:
        return ''
    for name in users:
        if target == name:
            return name
        if target.lower() == alias_tag(name).lower():
            return name
    return target


def load_json_file(path: str, default):
    try:
        with open(path, 'r', encoding='utf-8') as fh:
            data = json.load(fh)
        return data
    except FileNotFoundError:
        return default
    except Exception:
        return default


def atomic_write_json(path: str, data) -> None:
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
    os.replace(tmp, path)


def _default_local_settings() -> dict:
    return {
        'version': 1,
        'remember_connection': True,
        'last_ip': '127.0.0.1',
        'last_username': sanitize_token(getpass.getuser(), default='user', max_len=48),
        'stream_guard': True,
        'strip_image_metadata': True,
    }


def _local_settings_key() -> bytes:
    identity = f'{getpass.getuser()}|{socket.gethostname()}|{BASE_DIR}'.encode('utf-8', errors='replace')
    return sha256(APP_SALT + b'|local-settings|' + identity)


def encrypt_local_settings_payload(settings: dict) -> dict:
    plaintext = json.dumps(settings, separators=(',', ':'), sort_keys=True).encode('utf-8')
    nonce = get_random_bytes(AES_GCM_NONCE_LEN)
    ciphertext, tag = _aes256_gcm_encrypt(_local_settings_key(), nonce, plaintext, b'black-cloud-settings-v1')
    return {
        'v': 1,
        'alg': 'AES-256-GCM',
        'nonce': b64e(nonce),
        'tag': b64e(tag),
        'ct': b64e(ciphertext),
    }


def decrypt_local_settings_payload(envelope: dict) -> dict:
    if int(envelope.get('v', 0)) != 1:
        raise ValueError('Unsupported local settings version')
    plaintext = _aes256_gcm_decrypt(
        _local_settings_key(),
        b64d(envelope.get('nonce', '')),
        b64d(envelope.get('ct', '')),
        b64d(envelope.get('tag', '')),
        b'black-cloud-settings-v1',
    )
    data = json.loads(plaintext.decode('utf-8'))
    return data if isinstance(data, dict) else {}


def load_local_settings() -> dict:
    settings = _default_local_settings()
    try:
        with open(LOCAL_SETTINGS_FILE, 'r', encoding='utf-8') as fh:
            envelope = json.load(fh)
        if isinstance(envelope, dict) and 'ct' in envelope:
            loaded = decrypt_local_settings_payload(envelope)
        elif isinstance(envelope, dict):
            loaded = envelope
        else:
            loaded = {}
        for key in settings:
            if key in loaded:
                settings[key] = loaded[key]
    except FileNotFoundError:
        pass
    except Exception:
        pass
    settings['last_ip'] = str(settings.get('last_ip') or '127.0.0.1')[:128]
    settings['last_username'] = sanitize_token(str(settings.get('last_username') or getpass.getuser()), default='user', max_len=48)
    settings['remember_connection'] = bool(settings.get('remember_connection', True))
    settings['stream_guard'] = bool(settings.get('stream_guard', True))
    settings['strip_image_metadata'] = bool(settings.get('strip_image_metadata', True))
    return settings


def save_local_settings(settings: dict) -> None:
    merged = _default_local_settings()
    merged.update(settings or {})
    merged['last_username'] = sanitize_token(str(merged.get('last_username') or getpass.getuser()), default='user', max_len=48)
    tmp = LOCAL_SETTINGS_FILE + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as fh:
        json.dump(encrypt_local_settings_payload(merged), fh, indent=2, sort_keys=True)
    os.replace(tmp, LOCAL_SETTINGS_FILE)
    try:
        os.chmod(LOCAL_SETTINGS_FILE, 0o600)
    except OSError:
        pass


def apply_runtime_settings(settings: dict) -> None:
    global STREAM_GUARD_ENABLED, STRIP_IMAGE_METADATA_ENABLED, REMEMBER_CONNECTION_ENABLED
    STREAM_GUARD_ENABLED = bool(settings.get('stream_guard', True))
    STRIP_IMAGE_METADATA_ENABLED = bool(settings.get('strip_image_metadata', True))
    REMEMBER_CONNECTION_ENABLED = bool(settings.get('remember_connection', True))


def ensure_pillow():
    dep_dir = _local_dependency_dir()
    if dep_dir not in sys.path:
        sys.path.insert(0, dep_dir)
    try:
        from PIL import Image, ImageOps
        return Image, ImageOps
    except ModuleNotFoundError:
        os.makedirs(dep_dir, exist_ok=True)
        print('[*] Missing dependency: Pillow')
        print('[*] Installing Pillow locally...')
        base_cmd = [
            sys.executable, '-m', 'pip', 'install', '--upgrade', '--no-input',
            '--target', dep_dir, 'Pillow>=10.4.0',
        ]
        attempted = [base_cmd]
        attempted.append(base_cmd[:-2] + ['--break-system-packages'] + base_cmd[-2:])
        last_error = None
        for cmd in attempted:
            try:
                subprocess.check_call(cmd)
                import importlib
                importlib.invalidate_caches()
                if dep_dir not in sys.path:
                    sys.path.insert(0, dep_dir)
                from PIL import Image, ImageOps
                return Image, ImageOps
            except Exception as exc:
                last_error = exc
        raise RuntimeError(
            'Failed to install Pillow locally. Install it manually with '
            f'"{sys.executable} -m pip install --target {dep_dir} Pillow"'
        ) from last_error


def sanitize_filename(value: str, default: str = 'image') -> str:
    name = os.path.basename(value or '').strip().replace('\x00', '')
    name = re.sub(r'[^A-Za-z0-9_. -]+', '_', name).strip(' .')
    return name[:96] or default


def _image_mime_for_format(fmt: str) -> tuple[str, str]:
    fmt = (fmt or '').upper()
    if fmt in {'JPG', 'JPEG'}:
        return 'image/jpeg', '.jpg'
    if fmt == 'PNG':
        return 'image/png', '.png'
    if fmt == 'WEBP':
        return 'image/webp', '.webp'
    if fmt == 'BMP':
        return 'image/png', '.png'
    return 'image/png', '.png'


def strip_image_metadata_to_bytes(path: str) -> tuple[bytes, str, str]:
    Image, ImageOps = ensure_pillow()
    with Image.open(path) as image:
        image.load()
        image = ImageOps.exif_transpose(image)
        fmt = (image.format or os.path.splitext(path)[1].lstrip('.')).upper()
        mime, ext = _image_mime_for_format(fmt)
        if fmt in {'JPG', 'JPEG'}:
            if image.mode not in ('RGB', 'L'):
                image = image.convert('RGB')
            out_fmt = 'JPEG'
        elif fmt == 'WEBP':
            if image.mode not in ('RGB', 'RGBA'):
                image = image.convert('RGBA' if 'A' in image.getbands() else 'RGB')
            out_fmt = 'WEBP'
        else:
            if image.mode not in ('RGB', 'RGBA', 'L'):
                image = image.convert('RGBA' if 'A' in image.getbands() else 'RGB')
            out_fmt = 'PNG'
            mime, ext = 'image/png', '.png'
        import io
        buffer = io.BytesIO()
        if out_fmt == 'JPEG':
            image.save(buffer, out_fmt, quality=92, optimize=True)
        elif out_fmt == 'WEBP':
            image.save(buffer, out_fmt, quality=92, method=6)
        else:
            image.save(buffer, out_fmt, optimize=True, compress_level=9)
        clean_bytes = bytearray(buffer.getvalue())
        try:
            buffer.seek(0)
            buffer.truncate(0)
            buffer.close()
        except Exception:
            pass
    base = os.path.splitext(sanitize_filename(path, default='image'))[0]
    return clean_bytes, mime, sanitize_filename(base + ext, default='image' + ext)


def build_image_packet(path: str) -> str:
    raw_path = os.path.abspath(path)
    if not os.path.isfile(raw_path):
        raise ValueError('Image file not found')
    if STRIP_IMAGE_METADATA_ENABLED:
        clean_bytes, mime, clean_name = strip_image_metadata_to_bytes(raw_path)
    else:
        with open(raw_path, 'rb') as fh:
            clean_bytes = bytearray(fh.read())
        Image, _ImageOps = ensure_pillow()
        with Image.open(raw_path) as image:
            mime, ext = _image_mime_for_format(image.format or os.path.splitext(raw_path)[1].lstrip('.'))
        base = os.path.splitext(sanitize_filename(raw_path, default='image'))[0]
        clean_name = sanitize_filename(base + ext, default='image' + ext)
    try:
        if len(clean_bytes) > MAX_IMAGE_BYTES:
            raise ValueError(f'Image is too large after cleanup ({len(clean_bytes)} bytes). Limit is {MAX_IMAGE_BYTES} bytes.')
        packet = {
            'v': 1,
            'type': 'image',
            'filename': clean_name,
            'mime': mime,
            'size': len(clean_bytes),
            'sha256': hashlib.sha256(clean_bytes).hexdigest(),
            'meta_stripped': bool(STRIP_IMAGE_METADATA_ENABLED),
            'data': b64e(clean_bytes),
        }
        payload = b64e(json.dumps(packet, separators=(',', ':'), sort_keys=True).encode('utf-8'))
        return IMAGE_PACKET_PREFIX + payload
    finally:
        secure_wipe_buffer(clean_bytes)
        try:
            del clean_bytes
        except Exception:
            pass
        gc.collect()


def parse_image_packet(message: str) -> Optional[dict]:
    if not isinstance(message, str) or not message.startswith(IMAGE_PACKET_PREFIX):
        return None
    try:
        packet = json.loads(b64d(message[len(IMAGE_PACKET_PREFIX):]).decode('utf-8'))
        if int(packet.get('v', 0)) != 1 or packet.get('type') != 'image':
            return None
        raw = bytearray(b64d(packet.get('data', '')))
        if len(raw) > MAX_IMAGE_BYTES:
            raise ValueError('image payload too large')
        digest = hashlib.sha256(raw).hexdigest()
        if digest != packet.get('sha256'):
            raise ValueError('image checksum mismatch')
        packet['raw'] = raw
        packet['filename'] = sanitize_filename(packet.get('filename', 'image'), default='image')
        packet['size'] = len(raw)
        packet['mime'] = str(packet.get('mime') or 'application/octet-stream')[:64]
        return packet
    except Exception as exc:
        return {'error': str(exc), 'filename': 'blocked-image', 'size': 0, 'mime': 'application/octet-stream'}



def make_image_chunk_packets(image_packet: str) -> list[str]:
    """Split one image packet into conservative encrypted-send sized plaintext chunks."""
    if not isinstance(image_packet, str) or not image_packet.startswith(IMAGE_PACKET_PREFIX):
        return [image_packet]
    transfer_id = secrets.token_hex(8)
    packet_hash = hashlib.sha256(image_packet.encode('utf-8')).hexdigest()
    chunk_size = max(1024, min(int(IMAGE_CHUNK_PAYLOAD_SIZE), 4096))
    chunks = [image_packet[i:i + chunk_size] for i in range(0, len(image_packet), chunk_size)]
    if not chunks:
        chunks = ['']
    if len(chunks) > MAX_IMAGE_CHUNKS:
        raise ValueError(f'Image packet needs {len(chunks)} chunks; limit is {MAX_IMAGE_CHUNKS}. Use a smaller image.')
    filename = 'image'
    packet = parse_image_packet(image_packet)
    if packet and not packet.get('error'):
        filename = sanitize_filename(packet.get('filename', 'image'), default='image')
    name_b64 = b64e(filename.encode('utf-8', errors='replace'))
    total = len(chunks)
    return [
        f'{IMAGE_CHUNK_PREFIX}{transfer_id}|{idx}|{total}|{packet_hash}|{name_b64}|{chunk}'
        for idx, chunk in enumerate(chunks)
    ]


def outbound_message_parts(message: str) -> list[str]:
    if isinstance(message, str) and message.startswith(IMAGE_PACKET_PREFIX):
        return make_image_chunk_packets(message)
    return [message]


def parse_image_chunk_packet(message: str) -> Optional[dict]:
    if not isinstance(message, str) or not message.startswith(IMAGE_CHUNK_PREFIX):
        return None
    try:
        _prefix, transfer_id, idx_s, total_s, packet_hash, name_b64, chunk = message.split('|', 6)
        transfer_id = sanitize_token(transfer_id, default='', max_len=32)
        if not transfer_id:
            raise ValueError('invalid image transfer id')
        idx = int(idx_s)
        total = int(total_s)
        if total < 1 or total > MAX_IMAGE_CHUNKS:
            raise ValueError('invalid image chunk count')
        if idx < 0 or idx >= total:
            raise ValueError('invalid image chunk index')
        if len(chunk) > IMAGE_CHUNK_PAYLOAD_SIZE + 1024:
            raise ValueError('image chunk too large')
        if not re.fullmatch(r'[0-9a-fA-F]{64}', packet_hash or ''):
            raise ValueError('invalid image packet hash')
        try:
            filename = b64d(name_b64).decode('utf-8', errors='replace')
        except Exception:
            filename = 'image'
        return {
            'id': transfer_id,
            'idx': idx,
            'total': total,
            'hash': packet_hash.lower(),
            'filename': sanitize_filename(filename, default='image'),
            'chunk': chunk,
        }
    except Exception as exc:
        return {'error': str(exc)}



def secure_wipe_buffer(buffer, passes: int = SECURE_IMAGE_WIPE_PASSES) -> None:
    """Best-effort overwrite for mutable image buffers owned by this process."""
    if buffer is None:
        return
    try:
        mv = memoryview(buffer)
    except TypeError:
        return
    try:
        if mv.readonly or mv.nbytes <= 0:
            return
        length = mv.nbytes
        zero = b'\x00' * length
        for _ in range(max(1, int(passes))):
            mv[:] = zero
    except Exception:
        try:
            for idx in range(len(buffer)):
                buffer[idx] = 0
        except Exception:
            pass
    finally:
        try:
            mv.release()
        except Exception:
            pass


def _wipe_image_chunk_info(info: dict) -> None:
    try:
        chunks = info.get('chunks') if isinstance(info, dict) else None
        if isinstance(chunks, dict):
            for value in list(chunks.values()):
                secure_wipe_buffer(value)
            chunks.clear()
    except Exception:
        pass


def secure_pop_image_chunk_buffer(key: str) -> None:
    info = image_chunk_buffers.pop(key, None)
    if info:
        _wipe_image_chunk_info(info)


def secure_wipe_image_record(record: dict) -> None:
    if not isinstance(record, dict):
        return
    raw = record.get('raw')
    secure_wipe_buffer(raw)
    record.clear()


def wipe_image_token(token: str) -> bool:
    safe_token = sanitize_token(token, default='', max_len=32)
    if not safe_token:
        return False
    with image_memory_lock:
        removed = image_memory_store.pop(safe_token, None)
        try:
            while safe_token in image_memory_order:
                image_memory_order.remove(safe_token)
        except ValueError:
            pass
    if removed:
        secure_wipe_image_record(removed)
        gc.collect()
        return True
    return False


def wipe_all_image_memory() -> None:
    with image_memory_lock:
        records = list(image_memory_store.values())
        image_memory_store.clear()
        image_memory_order.clear()
    for record in records:
        secure_wipe_image_record(record)
    for key in list(image_chunk_buffers.keys()):
        secure_pop_image_chunk_buffer(key)
    try:
        gc.collect()
    except Exception:
        pass


def cleanup_image_chunk_buffers() -> None:
    now_ts = time.time()
    for key, info in list(image_chunk_buffers.items()):
        if now_ts - float(info.get('created_at', now_ts)) > IMAGE_CHUNK_TTL_SECONDS:
            secure_pop_image_chunk_buffer(key)


def store_image_packet_in_memory(sender: str, packet: dict) -> str:
    if packet.get('error'):
        raise ValueError(packet['error'])
    raw = packet.get('raw', b'')
    if not isinstance(raw, (bytes, bytearray)) or not raw:
        raise ValueError('empty image payload')
    token = secrets.token_hex(12)
    safe_sender = sanitize_token(sender, default='user', max_len=48)
    record = {
        'sender': safe_sender,
        'filename': sanitize_filename(packet.get('filename', 'image'), default='image'),
        'mime': str(packet.get('mime') or 'application/octet-stream')[:64],
        'size': len(raw),
        'sha256': hashlib.sha256(raw).hexdigest(),
        'meta_stripped': bool(packet.get('meta_stripped', False)),
        'created_at': time.time(),
        'raw': bytearray(raw),
    }
    try:
        if raw is not record['raw']:
            secure_wipe_buffer(raw)
    except Exception:
        pass
    with image_memory_lock:
        image_memory_store[token] = record
        image_memory_order.append(token)
        while len(image_memory_order) > IMAGE_MEMORY_LIMIT:
            old_token = image_memory_order.popleft()
            old_record = image_memory_store.pop(old_token, None)
            secure_wipe_image_record(old_record)
    return token


def get_memory_image_record(token: str) -> Optional[dict]:
    safe_token = sanitize_token(token, default='', max_len=32)
    if not safe_token:
        return None
    with image_memory_lock:
        return image_memory_store.get(safe_token)


def image_preview_text(sender: str, packet: dict, label: str = 'encrypted image') -> str:
    token = store_image_packet_in_memory(sender, packet)
    filename = sanitize_display_text(packet.get('filename', 'image'), 80)
    return (
        f'[{label}] {filename} ready to view [image:{token}] '
        f'({packet.get("size", 0)} bytes; metadata stripped: {bool(packet.get("meta_stripped", False))}; not saved locally)'
    )


def received_image_chunk_preview(sender: str, message: str) -> Optional[str]:
    chunk = parse_image_chunk_packet(message)
    if chunk is None:
        return None
    if chunk.get('error'):
        return f'[BLOCKED IMAGE CHUNK: {chunk["error"]}]'

    cleanup_image_chunk_buffers()
    safe_sender = sanitize_token(sender, default='user', max_len=48)
    key = f'{safe_sender}|{chunk["id"]}'
    info = image_chunk_buffers.get(key)
    if not info:
        info = {
            'created_at': time.time(),
            'total': chunk['total'],
            'hash': chunk['hash'],
            'filename': chunk['filename'],
            'chunks': {},
        }
        image_chunk_buffers[key] = info

    if int(info.get('total', 0)) != chunk['total'] or info.get('hash') != chunk['hash']:
        secure_pop_image_chunk_buffer(key)
        return '[BLOCKED IMAGE CHUNK: transfer metadata changed]'

    old_chunk = info['chunks'].get(chunk['idx'])
    secure_wipe_buffer(old_chunk)
    info['chunks'][chunk['idx']] = bytearray(str(chunk['chunk']).encode('utf-8'))
    received = len(info['chunks'])
    total = chunk['total']
    filename = sanitize_display_text(str(info.get('filename') or 'image'), 80)

    if received < total:
        return f'[receiving encrypted image] {filename} ({received}/{total} chunks)'

    packet = None
    full_packet_bytes = bytearray()
    try:
        for idx in range(total):
            full_packet_bytes.extend(info['chunks'][idx])
        full_packet = full_packet_bytes.decode('utf-8', errors='strict')
        if hashlib.sha256(full_packet.encode('utf-8')).hexdigest().lower() != info.get('hash'):
            return '[BLOCKED IMAGE: reassembled image checksum mismatch]'
        packet = parse_image_packet(full_packet)
    finally:
        secure_wipe_buffer(full_packet_bytes)
        secure_pop_image_chunk_buffer(key)
    if not packet or packet.get('error'):
        return f'[BLOCKED IMAGE: {packet.get("error", "invalid image packet") if packet else "invalid image packet"}]'
    try:
        return image_preview_text(sender, packet, 'encrypted image')
    except Exception as exc:
        return f'[BLOCKED IMAGE: {exc}]'


def send_encrypted_channel_message(sock: socket.socket, message: str) -> bool:
    if not channel_key:
        raise ValueError(f'Channel key for #{current_channel} is not ready yet')
    if not current_channel_authenticated:
        raise ValueError(f'Channel #{current_channel} is not authenticated yet')
    aad = f'MSG|{current_channel}'.encode('utf-8')
    is_image = isinstance(message, str) and message.startswith(IMAGE_PACKET_PREFIX)
    parts = outbound_message_parts(message)
    for idx, part in enumerate(parts):
        seq = next_channel_outbound_seq()
        inner = pack_secure_inner(current_username, part, seq, channel_send_session_id)
        encrypted_msg = encrypt(inner, channel_key, aad=aad)
        wire = f'BLOB|{encrypted_msg}' if is_image else encrypted_msg
        if len((wire + '\n').encode('utf-8', errors='ignore')) > MAX_LINE_LEN:
            raise ValueError('Encrypted image chunk is still too large; use a smaller image or lower IMAGE_CHUNK_PAYLOAD_SIZE')
        if not send_line(sock, wire):
            return False
        if is_image:
            time.sleep(IMAGE_CHUNK_SEND_PAUSE_SECONDS)
    return True


def send_encrypted_dm_message(sock: socket.socket, target: str, message: str) -> bool:
    bundle = peer_bundles.get(target)
    if not bundle:
        raise KeyError(target)
    is_image = isinstance(message, str) and message.startswith(IMAGE_PACKET_PREFIX)
    dm_prefix = 'DMIMG' if is_image else 'DM'
    for idx, part in enumerate(outbound_message_parts(message)):
        seq = next_dm_outbound_seq(target)
        encrypted_msg = e2e_encrypt_dm_message(bundle, current_username, part, seq)
        wire = f'{dm_prefix}|{target}|{encrypted_msg}'
        if len((wire + '\n').encode('utf-8', errors='ignore')) > MAX_LINE_LEN:
            raise ValueError('Encrypted DM image chunk is still too large; use a smaller image or lower IMAGE_CHUNK_PAYLOAD_SIZE')
        if not send_line(sock, wire):
            return False
        if is_image:
            time.sleep(IMAGE_CHUNK_SEND_PAUSE_SECONDS)
    return True


def message_preview(message: str) -> str:
    packet = parse_image_packet(message)
    if packet:
        if packet.get('error'):
            return f'[blocked image: {packet["error"]}]'
        try:
            return image_preview_text(current_username or 'local', packet, 'encrypted image')
        except Exception as exc:
            return f'[blocked image: {exc}]'
    chunk = parse_image_chunk_packet(message)
    if chunk:
        if chunk.get('error'):
            return f'[blocked image chunk: {chunk["error"]}]'
        return f'[encrypted image chunk {chunk.get("idx", 0) + 1}/{chunk.get("total", 0)}: {chunk.get("filename", "image")}]'
    return sanitize_display_text(message)


def received_message_preview(sender: str, message: str) -> str:
    chunk_preview = received_image_chunk_preview(sender, message)
    if chunk_preview is not None:
        return chunk_preview
    packet = parse_image_packet(message)
    if packet:
        if packet.get('error'):
            return f'[BLOCKED IMAGE: {packet["error"]}]'
        try:
            return image_preview_text(sender, packet, 'encrypted image')
        except Exception as exc:
            return f'[BLOCKED IMAGE: {exc}]'
    return sanitize_display_text(message)

def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode('utf-8')


def b64d(data: str) -> bytes:
    return base64.b64decode(data.encode('utf-8'), validate=True)


def bundle_message_bytes(username: str, enc_pub_b64: str, sign_pub_b64: str) -> bytes:
    safe_user = sanitize_token(username, default='user', max_len=48)
    return b'bundle|%b|%b|%b' % (safe_user.encode('utf-8'), enc_pub_b64.encode('ascii'), sign_pub_b64.encode('ascii'))


def dm_signature_input(sender: str, recipient: str, enc_pub_b64: str, sign_pub_b64: str, ciphertext: bytes) -> bytes:
    safe_sender = sanitize_token(sender, default='user', max_len=48)
    safe_recipient = sanitize_token(recipient, default='user', max_len=48)
    return b'dm-e2e-v1|' + safe_sender.encode('utf-8') + b'|' + safe_recipient.encode('utf-8') + b'|' + enc_pub_b64.encode('ascii') + b'|' + sign_pub_b64.encode('ascii') + b'|' + ciphertext


def ensure_local_identity_material() -> tuple[NaclPrivateKey, SigningKey]:
    data = load_json_file(IDENTITY_FILE, {})
    try:
        enc_sk_b64 = data.get('enc_sk')
        sign_sk_b64 = data.get('sign_sk')
        if enc_sk_b64 and sign_sk_b64:
            return NaclPrivateKey(b64d(enc_sk_b64)), SigningKey(b64d(sign_sk_b64))
    except Exception:
        pass
    enc_sk = NaclPrivateKey.generate()
    sign_sk = SigningKey.generate()
    atomic_write_json(IDENTITY_FILE, {'enc_sk': b64e(bytes(enc_sk)), 'sign_sk': b64e(bytes(sign_sk))})
    try:
        os.chmod(IDENTITY_FILE, 0o600)
    except OSError:
        pass
    return enc_sk, sign_sk


def load_peer_pins() -> dict:
    data = load_json_file(PEER_PINS_FILE, {})
    return data if isinstance(data, dict) else {}


def save_peer_pins(pins: dict) -> None:
    atomic_write_json(PEER_PINS_FILE, pins)


def build_identity_bundle(username: str, enc_private_key: NaclPrivateKey, signing_key: SigningKey) -> dict:
    safe_user = sanitize_token(username, default='user', max_len=48)
    enc_pub_b64 = b64e(bytes(enc_private_key.public_key))
    sign_pub_b64 = b64e(bytes(signing_key.verify_key))
    bundle_sig_b64 = b64e(signing_key.sign(bundle_message_bytes(safe_user, enc_pub_b64, sign_pub_b64)).signature)
    return {'user': safe_user, 'enc_pub': enc_pub_b64, 'sign_pub': sign_pub_b64, 'bundle_sig': bundle_sig_b64}


def verify_identity_bundle(bundle: dict) -> dict:
    user = sanitize_token(bundle.get('user', ''), default='', max_len=48)
    enc_pub_b64 = bundle.get('enc_pub', '')
    sign_pub_b64 = bundle.get('sign_pub', '')
    bundle_sig_b64 = bundle.get('bundle_sig', '')
    if not user or not enc_pub_b64 or not sign_pub_b64 or not bundle_sig_b64:
        raise ValueError('Incomplete identity bundle')
    verify_key = VerifyKey(b64d(sign_pub_b64))
    verify_key.verify(bundle_message_bytes(user, enc_pub_b64, sign_pub_b64), b64d(bundle_sig_b64))
    return {'user': user, 'enc_pub': enc_pub_b64, 'sign_pub': sign_pub_b64, 'bundle_sig': bundle_sig_b64}


def peer_bundle_fingerprint(bundle: dict) -> str:
    safe = verify_identity_bundle(bundle)
    fp = hashlib.sha256(b'peer-bundle|' + b64d(safe['sign_pub']) + b64d(safe['enc_pub'])).hexdigest().upper()
    return '-'.join(fp[i:i + 4] for i in range(0, 16, 4))


def cache_and_pin_peer_bundle(bundle: dict) -> dict:
    safe = verify_identity_bundle(bundle)
    existing = peer_pins.get(safe['user'])
    if existing:
        if existing.get('sign_pub') != safe['sign_pub'] or existing.get('enc_pub') != safe['enc_pub']:
            raise ValueError(f'Pinned identity changed for {safe["user"]}; delete {os.path.basename(PEER_PINS_FILE)} to trust a new identity')
    else:
        peer_pins[safe['user']] = {'sign_pub': safe['sign_pub'], 'enc_pub': safe['enc_pub'], 'first_seen': int(time.time())}
        save_peer_pins(peer_pins)
    peer_bundles[safe['user']] = safe
    return safe


def request_peer_bundle(sock: socket.socket, target: str) -> bool:
    safe_target = sanitize_token(target, default='', max_len=48)
    if not safe_target:
        return False
    if safe_target in peer_info_pending:
        return True
    ok = send_line(sock, f'KEYGET|{safe_target}')
    if ok:
        peer_info_pending.add(safe_target)
    return ok


def retry_peer_bundle_lookup(sock: socket.socket, target: str, attempt: int = 1) -> None:
    safe_target = sanitize_token(target, default='', max_len=48)
    if not safe_target:
        return
    if safe_target in peer_bundles:
        peer_info_retrying.discard(safe_target)
        return
    if attempt > E2E_IDENTITY_MAX_RETRIES:
        peer_info_retrying.discard(safe_target)
        add_dm_message(status_line('WARN', f'{color_user(safe_target)} does not have a usable E2E identity online. They need this same E2E build and must be connected.'))
        render()
        return
    time.sleep(E2E_IDENTITY_RETRY_DELAY)
    if not receive_running or safe_target in peer_bundles:
        peer_info_retrying.discard(safe_target)
        return
    peer_info_pending.discard(safe_target)
    if request_peer_bundle(sock, safe_target):
        add_dm_message(status_line('INFO', f'Retrying E2E identity lookup for {color_user(safe_target)} ({attempt}/{E2E_IDENTITY_MAX_RETRIES})'))
        render()
        return retry_peer_bundle_lookup(sock, safe_target, attempt + 1)
    peer_info_retrying.discard(safe_target)
    add_dm_message(status_line('ERR', f'Could not retry E2E identity lookup for {color_user(safe_target)}'))
    render()


def e2e_encrypt_dm_message(peer_bundle: dict, sender: str, message: str, seq: int) -> str:
    peer = verify_identity_bundle(peer_bundle)
    local_bundle = build_identity_bundle(sender, local_enc_private_key, local_signing_key)
    inner = json.dumps({'v': 1, 'seq': seq, 'sender': sanitize_token(sender, default='user', max_len=48), 'msg': message.replace('\r', ' ').replace('\x00', '?')}, separators=(',', ':'), sort_keys=True).encode('utf-8')
    sealed = SealedBox(NaclPublicKey(b64d(peer['enc_pub']))).encrypt(inner)
    msg_sig = b64e(local_signing_key.sign(dm_signature_input(sender, peer['user'], local_bundle['enc_pub'], local_bundle['sign_pub'], sealed)).signature)
    envelope = {'v': 1, 'sender': sanitize_token(sender, default='user', max_len=48), 'enc_pub': local_bundle['enc_pub'], 'sign_pub': local_bundle['sign_pub'], 'bundle_sig': local_bundle['bundle_sig'], 'ct': b64e(sealed), 'sig': msg_sig}
    return b64e(json.dumps(envelope, separators=(',', ':'), sort_keys=True).encode('utf-8'))


def e2e_decrypt_dm_message(payload: str, outer_sender: str, recipient: str) -> tuple[str, str, int]:
    try:
        envelope = json.loads(b64d(payload).decode('utf-8'))
    except Exception as exc:
        raise ValueError('Invalid E2E envelope') from exc
    sender = sanitize_token(envelope.get('sender', ''), default='', max_len=48)
    if not sender or sender != sanitize_token(outer_sender, default='', max_len=48):
        raise ValueError('Sender mismatch')
    bundle = {'user': sender, 'enc_pub': envelope.get('enc_pub', ''), 'sign_pub': envelope.get('sign_pub', ''), 'bundle_sig': envelope.get('bundle_sig', '')}
    safe_bundle = cache_and_pin_peer_bundle(bundle)
    ciphertext = b64d(envelope.get('ct', ''))
    VerifyKey(b64d(safe_bundle['sign_pub'])).verify(dm_signature_input(sender, recipient, safe_bundle['enc_pub'], safe_bundle['sign_pub'], ciphertext), b64d(envelope.get('sig', '')))
    plaintext = SealedBox(local_enc_private_key).decrypt(ciphertext)
    inner = json.loads(plaintext.decode('utf-8'))
    if int(inner.get('v', 0)) != 1:
        raise ValueError('Unsupported E2E DM version')
    if sanitize_token(inner.get('sender', ''), default='', max_len=48) != sender:
        raise ValueError('Inner sender mismatch')
    seq = int(inner.get('seq', 0))
    if seq < 1:
        raise ValueError('Invalid E2E DM sequence')
    return sender, inner.get('msg', ''), seq


def flush_dm_queue(client: socket.socket, target: str) -> None:
    bundle = peer_bundles.get(target)
    if not bundle:
        return
    queue = dm_queue.get(target)
    if not queue:
        return
    while queue:
        plain = queue.popleft()
        try:
            if not send_encrypted_dm_message(client, target, plain):
                add_dm_message(status_line('ERR', f'Failed to send queued DM to {color_user(target)}'))
                queue.appendleft(plain)
                break
            add_dm_message(format_entry(c(f'[{now()}]', Colors.BRIGHT_BLACK), get_user_color(current_username), f'{color_user(current_username)} → {color_user(target)}: {message_preview(plain)}'))
        except Exception as exc:
            add_dm_message(status_line('ERR', f'Failed to protect queued DM to {color_user(target)}: {exc}'))
            break
    if not queue:
        dm_queue.pop(target, None)


def send_line(sock: socket.socket, message: str) -> bool:
    try:
        encoded = (message + '\n').encode('utf-8')
        if len(encoded) > MAX_LINE_LEN:
            return False
        # TLS sockets are not safe for concurrent writes from multiple threads.
        # The GUI can send typing packets while an image upload worker is
        # chunking, so guard every sendall to prevent stream corruption.
        lock = globals().get('socket_send_lock')
        if lock is None:
            sock.sendall(encoded)
        else:
            with lock:
                sock.sendall(encoded)
        return True
    except OSError:
        return False


def recv_line(sock: socket.socket) -> str:
    buffer = b''
    while b'\n' not in buffer:
        chunk = sock.recv(4096)
        if not chunk:
            return ''
        buffer += chunk
        if len(buffer) > MAX_LINE_LEN:
            raise RuntimeError('Received oversized line during handshake')
    line, _sep, _rest = buffer.partition(b'\n')
    return line.decode('utf-8', errors='replace')


def safe_notify_username(username: str) -> str:
    return sanitize_token(username, default='Unknown', max_len=48)


def _stdin_recently_active() -> bool:
    return (time.time() - last_input_activity_ts) <= FOCUS_ACTIVITY_GRACE


def is_client_foreground() -> bool:
    if _stdin_recently_active():
        return True

    if os.name == 'nt':
        try:
            import ctypes
            user32 = ctypes.windll.user32
            kernel32 = ctypes.windll.kernel32
            return user32.GetForegroundWindow() == kernel32.GetConsoleWindow()
        except Exception:
            return _stdin_recently_active()

    window_id = os.environ.get('WINDOWID')
    if window_id and shutil.which('xdotool'):
        try:
            focused = subprocess.check_output(
                ['xdotool', 'getwindowfocus'],
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=0.25,
            ).strip()
            return focused == window_id
        except Exception:
            return _stdin_recently_active()

    return _stdin_recently_active()


def play_notification_sound() -> None:
    if is_client_foreground():
        return

    if os.name == 'nt':
        try:
            import winsound
            winsound.Beep(880, 65)
            winsound.Beep(660, 55)
            return
        except Exception:
            pass

    try:
        print('\a', end='', flush=True)
        time.sleep(0.045)
        print('\a', end='', flush=True)
    except Exception:
        pass


def desktop_notify(username: str) -> None:
    safe_name = safe_notify_username(username)
    play_notification_sound()
    try:
        if sys.platform.startswith('linux') and shutil.which('notify-send'):
            subprocess.Popen(
                ['notify-send', APP_TITLE, safe_name],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return
        if sys.platform == 'darwin' and shutil.which('osascript'):
            escaped = safe_name.replace('"', '\\"')
            subprocess.Popen(
                ['osascript', '-e', f'display notification "{escaped}" with title "{APP_TITLE}"'],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return
    except Exception:
        pass
    print(status_line('INFO', f'Notification: {safe_name}'))



class TimedMessageWindow:
    def __init__(self, limit: int = MESSAGE_BATCH_LIMIT, hold_seconds: float = MESSAGE_BATCH_SECONDS):
        self.limit = limit
        self.hold_seconds = hold_seconds
        self.visible: Deque[str] = deque()
        self.queued: Deque[str] = deque()
        self.deadline: Optional[float] = None
        self._lock = threading.Lock()

    def add(self, text: str) -> None:
        with self._lock:
            now_ts = time.time()
            if self.deadline is None:
                self.deadline = now_ts + self.hold_seconds
            if len(self.visible) < self.limit:
                self.visible.append(text)
            else:
                if len(self.queued) >= MAX_MESSAGE_QUEUE:
                    self.queued.popleft()
                self.queued.append(text)

    def snapshot(self) -> list[str]:
        with self._lock:
            return list(self.visible)

    def clear_all(self) -> None:
        with self._lock:
            self.visible.clear()
            self.queued.clear()
            self.deadline = None

    def tick(self) -> bool:
        with self._lock:
            if self.deadline is None or time.time() < self.deadline:
                return False
            self.visible.clear()
            while self.queued and len(self.visible) < self.limit:
                self.visible.append(self.queued.popleft())
            self.deadline = time.time() + self.hold_seconds if self.visible else None
            return True


# ===================== SERVER =====================
clients: Dict[socket.socket, str] = {}
user_channels = defaultdict(lambda: 'general')
channel_users = defaultdict(set)
typing_users = defaultdict(set)
last_activity = defaultdict(float)
state_lock = threading.Lock()
channel_salt_lock = threading.Lock()
channel_auth_lock = threading.Lock()
server_channel_salts = load_channel_salts()
server_channel_auth = load_channel_auth()
authorized_channels: Dict[socket.socket, str] = {}
client_identity_bundles: Dict[str, dict] = {}
rate_buckets = defaultdict(deque)


def get_client_channel(client: socket.socket) -> str:
    return user_channels.get(client, 'general')


def get_authorized_channel(client: socket.socket) -> str:
    return authorized_channels.get(client, '')


def channel_has_authorized_users(channel: str) -> bool:
    safe_channel = sanitize_token(channel, default='general')
    with state_lock:
        return any(auth_channel == safe_channel for auth_channel in authorized_channels.values())


def verify_or_register_channel_auth(channel: str, verifier: str) -> tuple[bool, str]:
    safe_channel = sanitize_token(channel, default='general')
    if not verifier or len(verifier) > 128:
        return False, 'invalid'
    with channel_auth_lock:
        known = server_channel_auth.get(safe_channel)
        if not known:
            server_channel_auth[safe_channel] = verifier
            save_channel_auth(server_channel_auth)
            return True, 'registered'
        if hmac.compare_digest(known, verifier):
            return True, 'verified'

        # Recovery path: older builds tied channel auth to the TLS/server fingerprint.
        # If the server cert changed, the saved verifier becomes stale even when the
        # user types the right channel password. When nobody is currently authorized
        # in this channel, allow the first successful-looking client to rotate the
        # saved verifier instead of trapping everyone in an auth-fail loop.
        if not channel_has_authorized_users(safe_channel):
            server_channel_auth[safe_channel] = verifier
            save_channel_auth(server_channel_auth)
            return True, 'recovered'

        return False, 'mismatch'


def reset_channel_auth_verifier(channel: str, verifier: str) -> bool:
    safe_channel = sanitize_token(channel, default='general')
    if not verifier or len(verifier) > 128:
        return False
    with channel_auth_lock:
        server_channel_auth[safe_channel] = verifier
        save_channel_auth(server_channel_auth)
    return True


def activate_client_channel(client: socket.socket, channel: str) -> None:
    safe_channel = sanitize_token(channel, default='general')
    with state_lock:
        name = clients.get(client)
        if not name:
            return
        old_auth = authorized_channels.get(client)
        if old_auth and old_auth != safe_channel:
            channel_users[old_auth].discard(name)
            typing_users[old_auth].discard(name)
        authorized_channels[client] = safe_channel
        channel_users[safe_channel].add(name)
        typing_users[safe_channel].discard(name)
    if old_auth and old_auth != safe_channel:
        broadcast_users(old_auth)
        broadcast_typing(old_auth)
    broadcast_users(safe_channel)
    broadcast_typing(safe_channel)


def get_or_create_channel_salt(channel: str) -> bytes:
    safe_channel = sanitize_token(channel, default='general')
    with channel_salt_lock:
        encoded = server_channel_salts.get(safe_channel)
        if not encoded:
            encoded = base64.b64encode(get_random_bytes(16)).decode('utf-8')
            server_channel_salts[safe_channel] = encoded
            save_channel_salts(server_channel_salts)
        try:
            return base64.b64decode(encoded.encode('utf-8'), validate=True)
        except Exception:
            encoded = base64.b64encode(get_random_bytes(16)).decode('utf-8')
            server_channel_salts[safe_channel] = encoded
            save_channel_salts(server_channel_salts)
            return base64.b64decode(encoded.encode('utf-8'))


def send_channel_salt(client: socket.socket, channel: str) -> bool:
    safe_channel = sanitize_token(channel, default='general')
    salt = get_or_create_channel_salt(safe_channel)
    return send_line(client, f'CHSAL|{safe_channel}|{base64.b64encode(salt).decode("utf-8")}')


def broadcast_users(channel: str) -> None:
    with state_lock:
        members = sorted(channel_users[channel])
        targets = [c for c in clients if user_channels.get(c) == channel]
    payload = ','.join(members)
    for client in targets:
        send_line(client, f'USERS|{channel}|{payload}')


def broadcast_typing(channel: str) -> None:
    with state_lock:
        typers = sorted(typing_users[channel])
        targets = [c for c in clients if user_channels.get(c) == channel]
    payload = ','.join(typers)
    for client in targets:
        send_line(client, f'TYPING|{payload}')


def route_to(target: str, message: str) -> bool:
    with state_lock:
        target_client = next((c for c, name in clients.items() if name == target), None)
    if not target_client:
        return False
    return send_line(target_client, message)


def channel_send(channel: str, message: str, exclude_client: Optional[socket.socket] = None) -> None:
    with state_lock:
        targets = [c for c in clients if user_channels.get(c) == channel and c is not exclude_client]
    dead = []
    for target_client in targets:
        if not send_line(target_client, message):
            dead.append(target_client)
    for target_client in dead:
        disconnect_client(target_client)


def move_user_to_channel(client: socket.socket, new_channel: str) -> str:
    new_channel = sanitize_token(new_channel, default='general')
    with state_lock:
        name = clients.get(client)
        if not name:
            return 'general'
        old_channel = user_channels.get(client, 'general')
        if old_channel == new_channel:
            return new_channel
        old_auth = authorized_channels.pop(client, '')
        if old_auth:
            channel_users[old_auth].discard(name)
            typing_users[old_auth].discard(name)
        user_channels[client] = new_channel
    if old_auth:
        broadcast_users(old_auth)
        broadcast_typing(old_auth)
    send_channel_salt(client, new_channel)
    return new_channel


def disconnect_client(client: socket.socket) -> None:
    with state_lock:
        name = clients.pop(client, None)
        channel = user_channels.pop(client, 'general')
        auth_channel = authorized_channels.pop(client, '')
        last_activity.pop(client, None)
        rate_buckets.pop(client, None)
        if name:
            client_identity_bundles.pop(name, None)
        if name and auth_channel:
            channel_users[auth_channel].discard(name)
            typing_users[auth_channel].discard(name)
    try:
        client.close()
    except OSError:
        pass
    if name and auth_channel:
        broadcast_users(auth_channel)
        broadcast_typing(auth_channel)


def allow_client_message(client: socket.socket) -> bool:
    now_ts = time.time()
    with state_lock:
        bucket = rate_buckets[client]
        while bucket and now_ts - bucket[0] > RATE_LIMIT_WINDOW:
            bucket.popleft()
        if len(bucket) >= RATE_LIMIT_MAX:
            return False
        bucket.append(now_ts)
        return True


def handle_command(client: socket.socket, data: str) -> None:
    if len(data.encode('utf-8', errors='ignore')) > MAX_LINE_LEN:
        send_line(client, 'SYS|Message too large')
        disconnect_client(client)
        return

    with state_lock:
        name = clients.get(client)
        last_activity[client] = time.time()
    if not name:
        return

    if data.startswith('CHRESET|'):
        parts = data.split('|', 2)
        if len(parts) != 3:
            send_line(client, 'SYS|Malformed channel password reset packet')
            return
        _tag, channel, verifier = parts
        current = get_client_channel(client)
        safe_channel = sanitize_token(channel, default='general')
        if safe_channel != current:
            send_line(client, 'SYS|Channel password reset mismatch')
            send_channel_salt(client, current)
            return
        if reset_channel_auth_verifier(current, verifier):
            activate_client_channel(client, current)
            send_line(client, f'SYS|Channel authenticated: {current} (saved password verifier reset)')
        else:
            send_line(client, f'SYS|Channel password reset failed: {current}')
            send_channel_salt(client, current)
        return

    if data.startswith('CHAUTH|'):
        parts = data.split('|', 2)
        if len(parts) != 3:
            send_line(client, 'SYS|Malformed channel auth packet')
            return
        _tag, channel, verifier = parts
        current = get_client_channel(client)
        safe_channel = sanitize_token(channel, default='general')
        if safe_channel != current:
            send_line(client, 'SYS|Channel auth mismatch')
            send_channel_salt(client, current)
            return
        auth_ok, auth_state = verify_or_register_channel_auth(current, verifier)
        if auth_ok:
            activate_client_channel(client, current)
            if auth_state == 'recovered':
                send_line(client, f'SYS|Channel authenticated: {current} (saved password verifier refreshed)')
            elif auth_state == 'registered':
                send_line(client, f'SYS|Channel authenticated: {current} (password registered)')
            else:
                send_line(client, f'SYS|Channel authenticated: {current}')
        else:
            if auth_state == 'mismatch':
                send_line(client, f'SYS|Channel authentication failed: {current} (wrong password or another user is already authenticated)')
            else:
                send_line(client, f'SYS|Channel authentication failed: {current}')
            send_channel_salt(client, current)
        return

    if data.startswith('KEYREG|'):
        parts = data.split('|', 3)
        if len(parts) != 4:
            send_line(client, 'SYS|Malformed identity packet')
            return
        _tag, enc_pub, sign_pub, bundle_sig = parts
        try:
            bundle = verify_identity_bundle({'user': name, 'enc_pub': enc_pub, 'sign_pub': sign_pub, 'bundle_sig': bundle_sig})
        except Exception:
            send_line(client, 'SYS|Invalid identity bundle')
            disconnect_client(client)
            return
        with state_lock:
            client_identity_bundles[name] = bundle
        send_line(client, 'SYS|Identity bundle registered')
        return

    if data.startswith('KEYGET|'):
        parts = data.split('|', 1)
        if len(parts) != 2:
            send_line(client, 'SYS|Malformed key lookup packet')
            return
        target = sanitize_token(parts[1], default='', max_len=48)
        if not target:
            send_line(client, 'SYS|Invalid key lookup target')
            return
        with state_lock:
            bundle = dict(client_identity_bundles.get(target, {})) if target in client_identity_bundles else None
        if not bundle:
            send_line(client, f'KEYMISS|{target}')
        else:
            send_line(client, f'KEYINFO|{target}|{bundle["enc_pub"]}|{bundle["sign_pub"]}|{bundle["bundle_sig"]}')
        return


    if data.startswith('BLOB|') or data.startswith('DMIMG|'):
        if get_authorized_channel(client) != get_client_channel(client):
            send_line(client, 'SYS|Authenticate to the current channel first')
            send_channel_salt(client, get_client_channel(client))
            return
        if data.startswith('BLOB|'):
            payload = data.split('|', 1)[1]
            if not payload:
                send_line(client, 'SYS|Malformed image packet')
                return
            channel = get_client_channel(client)
            # Do not echo encrypted image chunks back to the uploader. Echoing
            # many chunks onto the same socket during upload can make the sender
            # disconnect before the transfer finishes.
            channel_send(channel, f'MSG|{channel}|{payload}', exclude_client=client)
            return
        parts = data.split('|', 2)
        if len(parts) != 3:
            send_line(client, 'SYS|Malformed DM image packet')
            return
        _prefix, target, payload = parts
        if not route_to(target, f'DM|{name}|{payload}'):
            send_line(client, f'SYS|User not found: {target}')
        return

    if data not in ('/typing on', '/typing off') and not allow_client_message(client):
        send_line(client, 'SYS|Rate limit hit; slow down')
        return

    if data.startswith('/join '):
        requested = data.split(' ', 1)[1].strip()
        joined = move_user_to_channel(client, requested)
        send_line(client, f'SYS|Joined channel: {joined}; awaiting channel authentication')
        return

    if get_authorized_channel(client) != get_client_channel(client):
        send_line(client, 'SYS|Authenticate to the current channel first')
        send_channel_salt(client, get_client_channel(client))
        return


    if data.startswith('DH_REQ|') or data.startswith('DH_RES|') or data.startswith('DH_ACK|'):
        parts = data.split('|', 2)
        if len(parts) != 3:
            send_line(client, 'SYS|Malformed secure handshake packet')
            return
        msg_type, target, payload = parts
        if not route_to(target, f'{msg_type}|{name}|{payload}'):
            send_line(client, f'SYS|User not found: {target}')
        return

    if data.startswith('DM|'):
        parts = data.split('|', 2)
        if len(parts) != 3:
            send_line(client, 'SYS|Malformed DM packet')
            return
        _prefix, target, payload = parts
        if not route_to(target, f'DM|{name}|{payload}'):
            send_line(client, f'SYS|User not found: {target}')
        return


    if data == '/typing on':
        channel = get_client_channel(client)
        with state_lock:
            typing_users[channel].add(name)
        broadcast_typing(channel)
        return

    if data == '/typing off':
        channel = get_client_channel(client)
        with state_lock:
            typing_users[channel].discard(name)
        broadcast_typing(channel)
        return

    channel = get_client_channel(client)
    channel_send(channel, f'MSG|{channel}|{data}')


def handle_client(client: socket.socket) -> None:
    with state_lock:
        name = clients.get(client)
        if not name:
            return
        user_channels[client] = 'general'
        authorized_channels.pop(client, None)
        last_activity[client] = time.time()
    send_channel_salt(client, 'general')

    buffer = ''
    try:
        while True:
            chunk = client.recv(4096)
            if not chunk:
                break
            buffer += chunk.decode('utf-8', errors='replace')
            if len(buffer) > MAX_LINE_LEN * 2:
                send_line(client, 'SYS|Connection closed: oversized input buffer')
                break
            while '\n' in buffer:
                line, buffer = buffer.split('\n', 1)
                line = line.rstrip('\r')
                if not line:
                    continue
                handle_command(client, line)
    except OSError:
        pass
    finally:
        disconnect_client(client)


def server() -> None:
    try:
        tls_context = build_server_ssl_context()
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((HOST, PORT))
        server_sock.listen()
        print(status_line('OK', f'Server listening on {HOST}:{PORT} with audited TLS/OpenSSL transport'))
    except Exception as exc:
        print(status_line('ERR', f'Failed to start server: {exc}'))
        return

    while True:
        try:
            raw_client, _addr = server_sock.accept()
            raw_client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            raw_client.settimeout(10.0)
            try:
                client = tls_context.wrap_socket(raw_client, server_side=True)
            except (ssl.SSLError, ConnectionResetError, BrokenPipeError, TimeoutError, OSError):
                try:
                    raw_client.close()
                except OSError:
                    pass
                continue
            try:
                client.settimeout(10.0)
                if not send_line(client, 'NICK'):
                    try:
                        client.close()
                    except OSError:
                        pass
                    continue
                proposed_name = recv_line(client).strip()
                if not proposed_name:
                    try:
                        client.close()
                    except OSError:
                        pass
                    continue
                name = sanitize_token(proposed_name, default='user')
                if not name:
                    send_line(client, 'SYS|Invalid nickname')
                    client.close()
                    continue
                with state_lock:
                    if name in clients.values():
                        send_line(client, 'SYS|Nickname already in use')
                        client.close()
                        continue
                    clients[client] = name
                client.settimeout(None)
                threading.Thread(target=handle_client, args=(client,), daemon=True).start()
            except (ConnectionResetError, BrokenPipeError, TimeoutError, OSError):
                try:
                    client.close()
                except OSError:
                    pass
                continue
        except KeyboardInterrupt:
            print('\n' + status_line('WARN', 'Server shutting down'))
            break
        except OSError as exc:
            if getattr(exc, 'errno', None) in {104, 54, 10054}:
                continue
            print(status_line('ERR', f'Accept loop error: {exc}'))
        except Exception as exc:
            print(status_line('ERR', f'Accept loop error: {exc}'))


# ===================== CLIENT =====================
message_window = TimedMessageWindow()
dm_window = TimedMessageWindow()
users = []
typing = []

current_channel = 'general'
dm_target: Optional[str] = None
current_username = ''
local_enc_private_key = None
local_signing_key = None
peer_pins: Dict[str, dict] = {}
peer_bundles: Dict[str, dict] = {}
peer_info_pending: Set[str] = set()
peer_info_retrying: Set[str] = set()
master_password_key = b''
server_context_key = b''
current_channel_salt = b''
channel_key = b''
channel_auth_failed_salts: Set[str] = set()
channel_auth_reset_attempts: Dict[str, int] = defaultdict(int)
current_channel_authenticated = False
CHANNEL_AUTH_RESET_MAX_ATTEMPTS = 8

pending_dh: Dict[str, dict] = {}
dh_keys: Dict[str, bytes] = {}
dm_send_chain: Dict[str, bytes] = {}
dm_recv_chain: Dict[str, bytes] = {}
dm_queue: Dict[str, Deque[str]] = defaultdict(deque)
channel_nonce_cache = NonceCache()
dm_nonce_cache: Dict[str, NonceCache] = defaultdict(NonceCache)
ui_lock = threading.Lock()
receive_running = True
last_input_activity_ts = 0.0
stream_guard_input_active = False
channel_send_seq = 0
channel_send_session_id = session_id_from_key(get_random_bytes(32), b'channel-session')
channel_recv_seq: Dict[str, int] = defaultdict(int)
dm_session_ids: Dict[str, str] = {}
dm_send_seq: Dict[str, int] = defaultdict(int)
dm_recv_seq: Dict[str, int] = defaultdict(int)
dm_message_count: Dict[str, int] = defaultdict(int)

# One TLS socket must never be written by two threads at the same time.
# Image uploads send many chunks, while GUI timers/typing packets can also
# write to the socket; serialize all socket writes to prevent TLS stream
# corruption and disconnects during picture upload.
socket_send_lock = threading.RLock()
image_chunk_buffers: Dict[str, dict] = {}
image_memory_lock = threading.Lock()
image_memory_store: Dict[str, dict] = {}
image_memory_order: Deque[str] = deque()
try:
    atexit.register(wipe_all_image_memory)
except Exception:
    pass


def clear() -> None:
    os.system('cls' if os.name == 'nt' else 'clear')


def format_entry(prefix: str, color: str, body: str) -> str:
    return f'{c(prefix, color)} {body}'


def mark_local_activity() -> None:
    global last_input_activity_ts
    last_input_activity_ts = time.time()


def begin_stream_guard_input() -> None:
    global stream_guard_input_active
    mark_local_activity()
    stream_guard_input_active = True


def end_stream_guard_input() -> None:
    global stream_guard_input_active
    stream_guard_input_active = False
    mark_local_activity()


def add_message(text: str) -> None:
    message_window.add(text)
    app = globals().get('GUI_APP')
    if app is not None:
        app.append_chat_line(strip_ansi(text))


def add_dm_message(text: str) -> None:
    dm_window.add(text)
    app = globals().get('GUI_APP')
    if app is not None:
        app.append_dm_line(strip_ansi(text))


def render() -> None:
    app = globals().get('GUI_APP')
    if app is not None:
        app.refresh_state()
        return
    if STREAM_GUARD_ENABLED and stream_guard_input_active:
        return
    with ui_lock:
        clear()
        secure_state = 'ON' if channel_key else 'OFF'
        dm_state = dm_target or 'None'
        print(c('=' * 118, Colors.BRIGHT_BLUE))
        print(c(APP_TITLE + '  ::  secure encrypted chat', Colors.BOLD + Colors.BRIGHT_WHITE))
        print(
            f"{c('#' + current_channel, Colors.BRIGHT_CYAN)} | "
            f"DM: {c(display_name(dm_state) if dm_state != 'None' else dm_state, Colors.BRIGHT_MAGENTA)} | "
            f"USER: {color_user(current_username or '?')} | "
            f"SECURE: {c(secure_state, Colors.BRIGHT_YELLOW)}"
        )
        print(c('=' * 118, Colors.BRIGHT_BLUE))
        print(c('USERS'.ljust(28), Colors.BOLD) + c('CHAT'.ljust(56), Colors.BOLD) + c('DM', Colors.BOLD))

        chat_items = message_window.snapshot()
        dm_items = dm_window.snapshot()

        for i in range(DISPLAY_ROWS):
            raw_user = users[i] if i < len(users) else ''
            chat_col = chat_items[i] if i < len(chat_items) else ''
            dm_col = dm_items[i] if i < len(dm_items) else ''
            user_col = format_user_cell(raw_user, 24)
            print(f'{user_col}    {pad_ansi(chat_col, 56)}{pad_ansi(dm_col, 34)}')

        print(c('=' * 118, Colors.BRIGHT_BLUE))
        if typing:
            typing_display = ', '.join(color_user(name) for name in typing)
            print(status_line('INFO', 'typing: ' + typing_display))
        print(c('Commands: /join /dm /back /users /help', Colors.DIM))


def cleanup() -> None:
    handshake_check_at = 0.0
    while receive_running:
        time.sleep(0.2)
        changed = message_window.tick()
        changed = dm_window.tick() or changed
        now_ts = time.time()
        if now_ts >= handshake_check_at:
            cleanup_pending_handshakes()
            handshake_check_at = now_ts + 1.0
        if changed:
            render()


def cleanup_pending_handshakes() -> None:
    expired = []
    now_ts = time.time()
    for peer, info in list(pending_dh.items()):
        started = float(info.get('started_at', 0.0))
        if started and now_ts - started > HANDSHAKE_TIMEOUT:
            expired.append(peer)
    for peer in expired:
        pending_dh.pop(peer, None)
        dm_queue.pop(peer, None)
        add_dm_message(status_line('WARN', f'Secure DM setup with {color_user(peer)} timed out'))


def refresh_channel_key() -> None:
    global channel_key
    if not master_password_key or not current_channel_salt:
        channel_key = b''
        return
    channel_key = derive_channel_key(master_password_key, current_channel, current_channel_salt)


def _channel_salt_tag(channel: str, salt: bytes) -> str:
    safe_channel = sanitize_token(channel, default='general')
    return hashlib.sha256(safe_channel.encode('utf-8') + b'|' + salt).hexdigest()[:24]


def try_reset_channel_auth(client: socket.socket, channel: str, reason: str = '') -> bool:
    safe_channel = sanitize_token(channel, default='general')
    if not master_password_key or not current_channel_salt:
        add_message(status_line('WARN', f'Cannot reset #{safe_channel} auth yet; channel salt/key is not ready'))
        return False
    salt_tag = _channel_salt_tag(safe_channel, current_channel_salt)
    attempts = int(channel_auth_reset_attempts.get(salt_tag, 0))
    if attempts >= CHANNEL_AUTH_RESET_MAX_ATTEMPTS:
        add_message(status_line('WARN', f'Channel authentication is still failing for #{safe_channel}; reconnect or delete cloud_channel_auth.json on the server'))
        return False
    try:
        verifier = derive_channel_auth_verifier(master_password_key, safe_channel, current_channel_salt)
    except Exception as exc:
        add_message(status_line('ERR', f'Channel auth reset setup failed for #{safe_channel}: {exc}'))
        return False
    channel_auth_reset_attempts[salt_tag] = attempts + 1
    detail = f' ({reason})' if reason else ''
    add_message(status_line('SECURE', f'Resetting saved channel password for #{safe_channel}{detail}; attempt {attempts + 1}/{CHANNEL_AUTH_RESET_MAX_ATTEMPTS}'))
    return send_line(client, f'CHRESET|{safe_channel}|{verifier}')


def channel_auth_ready() -> bool:
    return bool(channel_key and current_channel_authenticated)


def ensure_channel_auth_ready(client: socket.socket) -> bool:
    if channel_auth_ready():
        return True
    if current_channel_salt:
        try_reset_channel_auth(client, current_channel, 'send blocked until authenticated')
    add_message(status_line('WARN', f'Channel #{current_channel} is not authenticated yet; wait for "Channel authenticated" then send again'))
    return False


def notify_new_message(sender: str) -> None:
    if sender and sender != current_username:
        desktop_notify(display_name(sender))


def install_dm_session(peer: str, session_key: bytes, initiator: str, responder: str) -> None:
    dh_keys[peer] = session_key
    send_key, recv_key = init_dm_chain_keys(session_key, initiator, responder, current_username)
    dm_send_chain[peer] = send_key
    dm_recv_chain[peer] = recv_key
    dm_session_ids[peer] = session_id_from_key(session_key, b'dm-session')
    dm_nonce_cache.pop(peer, None)
    dm_send_seq[peer] = 0
    dm_recv_seq[peer] = 0
    dm_message_count[peer] = 0


def next_dm_send_key(peer: str) -> bytes:
    chain_key = dm_send_chain.get(peer)
    if not chain_key:
        raise KeyError(peer)
    msg_key, next_key = ratchet_chain_key(chain_key)
    dm_send_chain[peer] = next_key
    return msg_key


def next_dm_recv_key(peer: str) -> bytes:
    chain_key = dm_recv_chain.get(peer)
    if not chain_key:
        raise KeyError(peer)
    msg_key, next_key = ratchet_chain_key(chain_key)
    dm_recv_chain[peer] = next_key
    return msg_key


def next_channel_outbound_seq() -> int:
    global channel_send_seq
    channel_send_seq += 1
    return channel_send_seq


def next_dm_outbound_seq(peer: str) -> int:
    dm_send_seq[peer] += 1
    return dm_send_seq[peer]


def maybe_rekey_dm(client: socket.socket, peer: str) -> None:
    dm_message_count[peer] += 1
    if dm_message_count[peer] < DM_REKEY_MESSAGES:
        return
    dm_message_count[peer] = 0
    if peer in pending_dh:
        return
    add_dm_message(status_line('SECURE', f'Refreshing secure DM with {color_user(peer)}'))
    start_dm_handshake(client, peer, force_restart=True)


def queue_dm_message(target: str, msg: str) -> None:
    queue = dm_queue[target]
    if len(queue) >= MAX_QUEUE_PER_TARGET:
        queue.popleft()
    queue.append(msg)


def start_dm_handshake(client: socket.socket, target: str, force_restart: bool = False) -> None:
    target = sanitize_token(target, default='')
    if not target:
        add_dm_message(status_line('ERR', 'Invalid DM target'))
        return
    if target == current_username:
        add_dm_message(status_line('WARN', 'Cannot DM yourself'))
        return
    if not channel_key:
        add_dm_message(status_line('WARN', 'Channel key not ready yet'))
        return
    if target in dh_keys and not force_restart:
        add_dm_message(status_line('INFO', f'Secure DM with {color_user(target)} already ready'))
        return
    if target in pending_dh and not force_restart:
        add_dm_message(status_line('INFO', f'Secure DM with {color_user(target)} is still being prepared'))
        return

    priv, pub = generate_dh()
    init_nonce = base64.b64encode(get_random_bytes(12)).decode('utf-8')
    pending_dh[target] = {
        'private': priv,
        'initiator_pub': pub,
        'channel': current_channel,
        'init_nonce': init_nonce,
        'started_at': time.time(),
        'state': 'awaiting-resp',
    }
    transcript = make_handshake_transcript(current_username, target, current_channel, pub, 0, init_nonce, '-')
    req_auth = make_handshake_auth(channel_key, b'dh-req', transcript)
    if send_line(client, f'DH_REQ|{target}|{current_channel}|{pub}|{init_nonce}|{req_auth}'):
        add_dm_message(status_line('SECURE', f'Starting secure DM with {color_user(target)}'))
    else:
        pending_dh.pop(target, None)
        add_dm_message(status_line('ERR', f'Failed to start secure DM with {color_user(target)}'))


def receive(client: socket.socket) -> None:
    global users, typing, receive_running, current_channel_salt, channel_send_session_id, current_channel_authenticated
    buffer = ''
    while True:
        try:
            chunk = client.recv(4096)
            if not chunk:
                add_message(status_line('WARN', 'Disconnected from server'))
                break
            buffer += chunk.decode('utf-8', errors='replace')
            if len(buffer) > MAX_LINE_LEN * 2:
                add_message(status_line('ERR', 'Incoming buffer overflow; closing connection'))
                break

            while '\n' in buffer:
                raw_line, buffer = buffer.split('\n', 1)
                line = raw_line.rstrip('\r')
                if not line:
                    continue
                parts = line.split('|')
                tag = parts[0]

                if tag == 'CHSAL' and len(parts) >= 3:
                    channel = sanitize_token(parts[1], default='general')
                    try:
                        salt = base64.b64decode(parts[2].encode('utf-8'), validate=True)
                    except Exception:
                        add_message(status_line('ERR', f'Invalid channel salt for #{channel}'))
                        render()
                        continue
                    if channel == current_channel:
                        current_channel_salt = salt
                        salt_tag = _channel_salt_tag(channel, salt)
                        current_channel_authenticated = False
                        channel_send_session_id = session_id_from_key(get_random_bytes(32), b'channel-session')
                        refresh_channel_key()
                        if salt_tag in channel_auth_failed_salts:
                            try_reset_channel_auth(client, channel, 'stale verifier')
                            render()
                            continue
                        try:
                            verifier = derive_channel_auth_verifier(master_password_key, channel, salt)
                            if send_line(client, f'CHAUTH|{channel}|{verifier}'):
                                add_message(status_line('SECURE', f'Channel key ready for #{channel}; authenticating'))
                            else:
                                add_message(status_line('ERR', f'Failed to send channel authentication for #{channel}'))
                        except Exception as exc:
                            add_message(status_line('ERR', f'Channel auth setup failed for #{channel}: {exc}'))

                elif tag == 'USERS' and len(parts) >= 3:
                    channel = sanitize_token(parts[1], default='general')
                    if channel == current_channel:
                        users = [sanitize_token(name, default='user') for name in parts[2].split(',') if name]

                elif tag == 'KEYINFO' and len(parts) >= 5:
                    target = sanitize_token(parts[1], default='', max_len=48)
                    peer_info_pending.discard(target)
                    try:
                        bundle = cache_and_pin_peer_bundle({'user': target, 'enc_pub': parts[2], 'sign_pub': parts[3], 'bundle_sig': parts[4]})
                        peer_info_retrying.discard(target)
                        add_dm_message(status_line('SECURE', f'E2E identity ready for {color_user(target)} | fp {peer_bundle_fingerprint(bundle)}'))
                        flush_dm_queue(client, target)
                    except Exception as exc:
                        add_dm_message(status_line('ERR', f'Could not trust E2E identity for {color_user(target)}: {exc}'))

                elif tag == 'KEYMISS' and len(parts) >= 2:
                    target = sanitize_token(parts[1], default='', max_len=48)
                    peer_info_pending.discard(target)
                    if target and target not in peer_info_retrying:
                        peer_info_retrying.add(target)
                        add_dm_message(status_line('WARN', f'E2E identity for {color_user(target)} is not available yet; retrying automatically'))
                        threading.Thread(target=retry_peer_bundle_lookup, args=(client, target, 1), daemon=True).start()
                    else:
                        add_dm_message(status_line('WARN', f'E2E identity for {color_user(target)} is still not available'))

                elif tag == 'MSG' and len(parts) >= 3:
                    channel = sanitize_token(parts[1], default='general')
                    aad = f'MSG|{channel}'.encode('utf-8')
                    try:
                        inner = decrypt(parts[2], channel_key, aad=aad, nonce_cache=channel_nonce_cache)
                        session_id, seq, sender, msg = unpack_secure_inner(inner)
                        accept_monotonic_sequence(channel_recv_seq, f'{sender}|{session_id}', seq)
                        safe_msg = received_message_preview(sender, msg)
                    except (CryptoError, ValueError) as exc:
                        sender = 'user'
                        safe_msg = f'[BLOCKED: {exc}]'
                    add_message(format_entry(c(f'[{now()}]', Colors.BRIGHT_BLACK), get_user_color(sender), f'{color_user(sender)}: {safe_msg}'))
                    notify_new_message(sender)

                elif tag == 'DM' and len(parts) >= 3:
                    sender = sanitize_token(parts[1], default='user')
                    encrypted_msg = parts[2]
                    try:
                        inner_sender, msg, seq = e2e_decrypt_dm_message(encrypted_msg, sender, current_username)
                        accept_monotonic_sequence(dm_recv_seq, sender, seq)
                        safe_msg = received_message_preview(sender, msg)
                    except Exception as exc:
                        safe_msg = f'[BLOCKED: {exc}]'
                    add_dm_message(format_entry(c(f'[{now()}]', Colors.BRIGHT_BLACK), get_user_color(sender), f'{color_user(sender)}: {safe_msg}'))
                    notify_new_message(sender)

                elif tag == 'TYPING' and len(parts) >= 2:
                    typing = [name for name in parts[1].split(',') if name and name != current_username]

                elif tag == 'DH_REQ' and len(parts) >= 6:
                    sender = sanitize_token(parts[1], default='')
                    req_channel = sanitize_token(parts[2], default='general')
                    try:
                        initiator_pub = int(parts[3])
                    except ValueError:
                        add_dm_message(status_line('ERR', f'Rejected {color_user(sender)}: invalid handshake data'))
                        render()
                        continue
                    init_nonce = parts[4]
                    req_auth = parts[5]

                    if req_channel != current_channel:
                        add_dm_message(status_line('WARN', f'Rejected {color_user(sender)}: not in same channel'))
                        render()
                        continue

                    req_transcript = make_handshake_transcript(sender, current_username, req_channel, initiator_pub, 0, init_nonce, '-')
                    if not verify_handshake_auth(channel_key, b'dh-req', req_transcript, req_auth):
                        add_dm_message(status_line('ERR', f'Rejected {color_user(sender)}: bad handshake auth'))
                        render()
                        continue

                    try:
                        responder_priv, responder_pub = generate_dh()
                        shared_secret = compute_shared(initiator_pub, responder_priv)
                    except ValueError:
                        add_dm_message(status_line('ERR', f'Rejected {color_user(sender)}: invalid DH value'))
                        render()
                        continue

                    resp_nonce = base64.b64encode(get_random_bytes(12)).decode('utf-8')
                    transcript = make_handshake_transcript(sender, current_username, req_channel, initiator_pub, responder_pub, init_nonce, resp_nonce)
                    session_key = derive_dm_session_key(shared_secret, transcript)
                    pending_dh[sender] = {
                        'private': responder_priv,
                        'initiator_pub': initiator_pub,
                        'responder_pub': responder_pub,
                        'channel': req_channel,
                        'session_key': session_key,
                        'init_nonce': init_nonce,
                        'resp_nonce': resp_nonce,
                        'started_at': time.time(),
                        'state': 'awaiting-ack',
                    }

                    resp_auth = make_handshake_auth(channel_key, b'dh-res', transcript)
                    confirm = base64.b64encode(hmac.new(session_key, b'dh-confirm-res|' + transcript, hashlib.sha256).digest()).decode('utf-8')
                    send_line(client, f'DH_RES|{sender}|{req_channel}|{responder_pub}|{init_nonce}|{resp_nonce}|{resp_auth}|{confirm}')
                    add_dm_message(status_line('SECURE', f'Exchange started with {color_user(sender)} | fp {fingerprint_key(session_key)}'))

                elif tag == 'DH_RES' and len(parts) >= 8:
                    sender = sanitize_token(parts[1], default='')
                    resp_channel = sanitize_token(parts[2], default='general')
                    try:
                        responder_pub = int(parts[3])
                    except ValueError:
                        add_dm_message(status_line('ERR', f'Rejected {color_user(sender)}: invalid response key'))
                        render()
                        continue
                    init_nonce = parts[4]
                    resp_nonce = parts[5]
                    resp_auth = parts[6]
                    confirm = parts[7]
                    pending = pending_dh.get(sender)
                    if not pending:
                        add_dm_message(status_line('WARN', f'Ignoring unexpected secure response from {color_user(sender)}'))
                        render()
                        continue
                    if pending.get('channel') != resp_channel:
                        add_dm_message(status_line('ERR', f'Rejected {color_user(sender)}: channel mismatch'))
                        render()
                        continue
                    if pending.get('init_nonce') != init_nonce:
                        add_dm_message(status_line('ERR', f'Rejected {color_user(sender)}: nonce mismatch'))
                        render()
                        continue

                    initiator_pub = pending['initiator_pub']
                    transcript = make_handshake_transcript(current_username, sender, resp_channel, initiator_pub, responder_pub, init_nonce, resp_nonce)
                    if not verify_handshake_auth(channel_key, b'dh-res', transcript, resp_auth):
                        add_dm_message(status_line('ERR', f'Rejected {color_user(sender)}: bad response auth'))
                        render()
                        continue

                    try:
                        shared_secret = compute_shared(responder_pub, pending['private'])
                    except ValueError:
                        add_dm_message(status_line('ERR', f'Rejected {color_user(sender)}: invalid DH response'))
                        render()
                        continue

                    session_key = derive_dm_session_key(shared_secret, transcript)
                    expected_confirm = hmac.new(session_key, b'dh-confirm-res|' + transcript, hashlib.sha256).digest()
                    try:
                        supplied_confirm = base64.b64decode(confirm.encode('utf-8'), validate=True)
                    except Exception:
                        add_dm_message(status_line('ERR', f'Rejected {color_user(sender)}: invalid confirmation'))
                        render()
                        continue

                    if not hmac.compare_digest(expected_confirm, supplied_confirm):
                        add_dm_message(status_line('ERR', f'Rejected {color_user(sender)}: confirmation failed'))
                        render()
                        continue

                    install_dm_session(sender, session_key, current_username, sender)
                    pending['resp_nonce'] = resp_nonce
                    pending['responder_pub'] = responder_pub
                    ack = base64.b64encode(hmac.new(session_key, b'dh-confirm-ack|' + transcript, hashlib.sha256).digest()).decode('utf-8')
                    send_line(client, f'DH_ACK|{sender}|{resp_channel}|{init_nonce}|{resp_nonce}|{ack}')
                    add_dm_message(status_line('SECURE', f'{color_user(sender)} ready | fp {fingerprint_key(session_key)}'))
                    flush_dm_queue(client, sender)

                elif tag == 'DH_ACK' and len(parts) >= 6:
                    sender = sanitize_token(parts[1], default='')
                    ack_channel = sanitize_token(parts[2], default='general')
                    init_nonce = parts[3]
                    resp_nonce = parts[4]
                    ack = parts[5]
                    pending = pending_dh.get(sender)
                    if not pending:
                        render()
                        continue
                    session_key = pending.get('session_key')
                    responder_pub = pending.get('responder_pub')
                    initiator_pub = pending.get('initiator_pub')
                    if not session_key or responder_pub is None or initiator_pub is None:
                        render()
                        continue
                    if pending.get('init_nonce') != init_nonce or pending.get('resp_nonce') != resp_nonce:
                        add_dm_message(status_line('ERR', f'Rejected {color_user(sender)}: ack nonce mismatch'))
                        render()
                        continue

                    transcript = make_handshake_transcript(sender, current_username, ack_channel, initiator_pub, responder_pub, init_nonce, resp_nonce)
                    expected_ack = hmac.new(session_key, b'dh-confirm-ack|' + transcript, hashlib.sha256).digest()
                    try:
                        supplied_ack = base64.b64decode(ack.encode('utf-8'), validate=True)
                    except Exception:
                        add_dm_message(status_line('ERR', f'Rejected {color_user(sender)}: bad ack'))
                        render()
                        continue

                    if not hmac.compare_digest(expected_ack, supplied_ack):
                        add_dm_message(status_line('ERR', f'Rejected {color_user(sender)}: ack failed'))
                        render()
                        continue

                    install_dm_session(sender, session_key, sender, current_username)
                    pending_dh.pop(sender, None)
                    add_dm_message(status_line('SECURE', f'{color_user(sender)} verified | fp {fingerprint_key(session_key)}'))
                    flush_dm_queue(client, sender)

                elif tag == 'SYS' and len(parts) >= 2:
                    sys_text = sanitize_display_text('|'.join(parts[1:]))
                    if sys_text.startswith('Channel authentication failed:') and current_channel_salt:
                        current_channel_authenticated = False
                        salt_tag = _channel_salt_tag(current_channel, current_channel_salt)
                        channel_auth_failed_salts.add(salt_tag)
                        try_reset_channel_auth(client, current_channel, 'auth failed')
                    elif sys_text.startswith('Channel authenticated:'):
                        current_channel_authenticated = True
                        channel_auth_failed_salts.clear()
                        channel_auth_reset_attempts.clear()
                    add_message(status_line('INFO', sys_text))

                render()
        except OSError as exc:
            add_message(status_line('ERR', f'Network error: {exc}'))
            break
        except Exception as exc:
            add_message(status_line('ERR', f'Unexpected receive error: {exc}'))
            break

    receive_running = False
    app = globals().get('GUI_APP')
    if app is not None and getattr(app, 'sock', None) is client:
        app.sock = None
        app.connected = False
    try:
        client.close()
    except OSError:
        pass
    render()


def client(ip: str) -> None:
    global current_channel, dm_target, current_username, local_enc_private_key, local_signing_key, peer_info_retrying
    global peer_pins, peer_bundles, peer_info_pending, master_password_key, server_context_key, current_channel_salt
    global channel_key, receive_running, channel_send_seq, channel_send_session_id, current_channel_authenticated

    try:
        raw_sock = socket.create_connection((ip, PORT), timeout=10)
        raw_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        tls_context = build_client_ssl_context()
        sock = tls_context.wrap_socket(raw_sock, server_hostname=TLS_COMMON_NAME)
        sock.settimeout(None)
        cert_der = sock.getpeercert(binary_form=True)
        if not cert_der:
            raise RuntimeError('Server did not provide a TLS certificate')
        tls_fp, tls_pin_state, known_tls_fp = pin_or_verify_server_certificate(f'{ip}:{PORT}', cert_der)
        negotiated_alpn = None
        try:
            negotiated_alpn = sock.selected_alpn_protocol()
        except Exception:
            negotiated_alpn = None
        if negotiated_alpn not in (None, TLS_ALPN_PROTOCOL):
            raise RuntimeError(f'Unexpected TLS application protocol: {negotiated_alpn}')
        printable_fp = fingerprint_key(bytes.fromhex(tls_fp))
        if tls_pin_state == 'new':
            print(status_line('WARN', f'First connection to {ip}:{PORT}. Verify server fingerprint before trusting: {printable_fp}'))
            begin_stream_guard_input()
            trust_answer = input('Type TRUST to pin this server: ').strip()
            end_stream_guard_input()
            if trust_answer != 'TRUST':
                raise RuntimeError('Server certificate not trusted')
            save_tls_pin(f'{ip}:{PORT}', tls_fp)
            tls_pin_state = 'pinned'
        elif tls_pin_state == 'mismatch':
            old_printable_fp = fingerprint_key(bytes.fromhex(known_tls_fp)) if known_tls_fp else 'UNKNOWN'
            print(status_line('ERR', 'TLS certificate fingerprint mismatch'))
            print(status_line('WARN', f'Known fp: {old_printable_fp}'))
            print(status_line('WARN', f'New   fp: {printable_fp}'))
            print(status_line('WARN', 'Only replace the pin if you intentionally changed the server certificate.'))
            begin_stream_guard_input()
            trust_answer = input('Type REPLACE to trust the new server certificate: ').strip()
            end_stream_guard_input()
            if trust_answer != 'REPLACE':
                raise RuntimeError('Server certificate mismatch not accepted')
            save_tls_pin(f'{ip}:{PORT}', tls_fp)
            tls_pin_state = 're-pinned'
        print(status_line('SECURE', f'Audited TLS/OpenSSL {tls_pin_state} | fp {printable_fp}'))
        server_context_key = bytes.fromhex(tls_fp)
    except Exception as exc:
        print(status_line('ERR', f'Failed to connect securely: {exc}'))
        return

    try:
        prompt = recv_line(sock)
    except Exception as exc:
        print(status_line('ERR', f'Handshake failed: {exc}'))
        sock.close()
        return

    if prompt != 'NICK':
        print(status_line('ERR', f'Unexpected server handshake: {prompt!r}'))
        sock.close()
        return

    settings = load_local_settings()
    apply_runtime_settings(settings)
    default_name = sanitize_token(str(settings.get('last_username') or getpass.getuser()), default='user', max_len=48)
    begin_stream_guard_input()
    entered_name = input(f'Nickname [{default_name}]: ').strip()
    end_stream_guard_input()
    current_username = sanitize_token(entered_name or default_name, default='user', max_len=48)
    if settings.get('remember_connection', True):
        settings['last_username'] = current_username
        save_local_settings(settings)
    peer_pins = load_peer_pins()
    peer_bundles = {}
    peer_info_pending = set()
    peer_info_retrying = set()
    local_enc_private_key, local_signing_key = ensure_local_identity_material()
    begin_stream_guard_input()
    password = getpass.getpass('Channel password: ')
    end_stream_guard_input()
    if len(password) < MIN_PASSWORD_LEN:
        print(status_line('ERR', f'Password must be at least {MIN_PASSWORD_LEN} characters'))
        sock.close()
        return
    charset_count = sum([
        any(ch.islower() for ch in password),
        any(ch.isupper() for ch in password),
        any(ch.isdigit() for ch in password),
        any(not ch.isalnum() for ch in password),
    ])
    if charset_count < 3:
        print(status_line('ERR', 'Password must use at least 3 of: lowercase, uppercase, digits, symbols'))
        sock.close()
        return
    try:
        master_password_key = derive_master_password_key(password, server_context_key)
    except Exception as exc:
        print(status_line('ERR', f'Could not derive secure key: {exc}'))
        sock.close()
        return
    finally:
        password = ''
    current_channel_salt = b''
    channel_key = b''
    current_channel_authenticated = False
    channel_send_seq = 0
    channel_send_session_id = session_id_from_key(get_random_bytes(32), b'channel-session')

    if not send_line(sock, current_username):
        print(status_line('ERR', 'Failed to send nickname'))
        sock.close()
        return

    try:
        local_bundle = build_identity_bundle(current_username, local_enc_private_key, local_signing_key)
        if not send_line(sock, f"KEYREG|{local_bundle['enc_pub']}|{local_bundle['sign_pub']}|{local_bundle['bundle_sig']}"):
            print(status_line('ERR', 'Failed to register E2E identity'))
            sock.close()
            return
    except Exception as exc:
        print(status_line('ERR', f'Failed to prepare E2E identity: {exc}'))
        sock.close()
        return

    receive_running = True
    threading.Thread(target=receive, args=(sock,), daemon=True).start()
    threading.Thread(target=cleanup, daemon=True).start()

    while receive_running:
        render()
        try:
            begin_stream_guard_input()
            msg = input('> ')
            end_stream_guard_input()
        except (EOFError, KeyboardInterrupt):
            print('\n' + status_line('WARN', 'Disconnecting'))
            try:
                sock.close()
            finally:
                break

        if not msg:
            continue

        if msg == '/help':
            add_message(status_line('INFO', 'Use /join room, /dm user, /back, /users, /img path, /resetchannelpass | DMs use signed E2E sealed boxes'))
            continue

        if msg == '/users':
            add_message(status_line('INFO', 'Users: ' + (', '.join(color_user(name) for name in users) if users else 'none')))
            continue

        if msg == '/resetchannelpass':
            if not try_reset_channel_auth(sock, current_channel, 'manual reset'):
                add_message(status_line('ERR', f'Failed to reset saved channel password for #{current_channel}'))
            continue

        send_line(sock, '/typing on')
        time.sleep(0.08)
        send_line(sock, '/typing off')

        if msg.startswith('/join '):
            current_channel = sanitize_token(msg.split(' ', 1)[1].strip(), default='general')
            current_channel_salt = b''
            channel_key = b''
            current_channel_authenticated = False
            channel_send_session_id = session_id_from_key(get_random_bytes(32), b'channel-session')
            dm_target = None
            message_window.clear_all()
            typing.clear()
            dh_keys.clear()
            dm_send_chain.clear()
            dm_recv_chain.clear()
            dm_session_ids.clear()
            pending_dh.clear()
            dm_queue.clear()
            dm_window.clear_all()
            dm_nonce_cache.clear()
            dm_send_seq.clear()
            dm_recv_seq.clear()
            dm_message_count.clear()
            channel_send_seq = 0
            channel_recv_seq.clear()
            channel_auth_failed_salts.clear()
            channel_auth_reset_attempts.clear()
            channel_nonce_cache._deque.clear()
            channel_nonce_cache._set.clear()
            if not send_line(sock, f'/join {current_channel}'):
                add_message(status_line('ERR', 'Failed to join channel'))
            continue

        if msg.startswith('/dm '):
            target = resolve_user_reference(msg.split(' ', 1)[1].strip())
            if not target:
                add_dm_message(status_line('ERR', 'Invalid DM target'))
                continue
            if target == current_username:
                add_dm_message(status_line('WARN', 'Cannot DM yourself'))
                continue
            dm_target = target
            if target not in peer_bundles:
                if request_peer_bundle(sock, target):
                    add_dm_message(status_line('SECURE', f'Requesting E2E identity for {color_user(target)}'))
                else:
                    add_dm_message(status_line('ERR', f'Failed to request E2E identity for {color_user(target)}'))
            else:
                add_dm_message(status_line('SECURE', f'E2E DM ready for {color_user(target)} | fp {peer_bundle_fingerprint(peer_bundles[target])}'))
            continue

        if msg == '/back':
            dm_target = None
            add_dm_message(status_line('INFO', 'Back to channel chat'))
            continue

        if msg.startswith('/img '):
            image_path = msg.split(' ', 1)[1].strip().strip('"')
            try:
                msg = build_image_packet(image_path)
            except Exception as exc:
                add_message(status_line('ERR', f'Image upload failed: {exc}'))
                continue

        try:
            if dm_target:
                bundle = peer_bundles.get(dm_target)
                if not bundle:
                    queue_dm_message(dm_target, msg)
                    if request_peer_bundle(sock, dm_target):
                        add_dm_message(status_line('WARN', f'E2E identity not ready for {color_user(dm_target)}; message queued until their identity is online'))
                    else:
                        add_dm_message(status_line('ERR', f'Failed to request E2E identity for {color_user(dm_target)}'))
                    continue
                if not send_encrypted_dm_message(sock, dm_target, msg):
                    add_dm_message(status_line('ERR', f'Failed to send DM to {color_user(dm_target)}'))
                else:
                    add_dm_message(format_entry(c(f'[{now()}]', Colors.BRIGHT_BLACK), get_user_color(current_username), f'{color_user(current_username)} → {color_user(dm_target)}: {message_preview(msg)}'))
            else:
                if not ensure_channel_auth_ready(sock):
                    continue
                if not send_encrypted_channel_message(sock, msg):
                    add_message(status_line('ERR', 'Failed to send channel message'))
                elif msg.startswith(IMAGE_PACKET_PREFIX):
                    add_message(format_entry(c(f'[{now()}]', Colors.BRIGHT_BLACK), get_user_color(current_username), f'{color_user(current_username)}: {message_preview(msg)}'))
        except ValueError as exc:
            add_message(status_line('ERR', str(exc)))
        except Exception as exc:
            add_message(status_line('ERR', f'Unexpected send error: {exc}'))




# ===================== PYQT6 DISCORD-STYLE GUI CLIENT / LAUNCHER =====================
GUI_APP = None


def ensure_pyqt6():
    # Load PyQt6, installing it into the local dependency folder if missing.
    dep_dir = _local_dependency_dir()
    if dep_dir not in sys.path:
        sys.path.insert(0, dep_dir)
    try:
        from PyQt6 import QtCore, QtGui, QtWidgets
        return QtCore, QtGui, QtWidgets
    except ModuleNotFoundError:
        os.makedirs(dep_dir, exist_ok=True)
        print('[*] Missing dependency: PyQt6')
        print('[*] Installing PyQt6 locally...')
        base_cmd = [
            sys.executable, '-m', 'pip', 'install', '--upgrade', '--no-input',
            '--target', dep_dir, 'PyQt6>=6.7.0',
        ]
        attempted = [base_cmd]
        attempted.append(base_cmd[:-2] + ['--break-system-packages'] + base_cmd[-2:])
        last_error = None
        for cmd in attempted:
            try:
                subprocess.check_call(cmd)
                import importlib
                importlib.invalidate_caches()
                if dep_dir not in sys.path:
                    sys.path.insert(0, dep_dir)
                from PyQt6 import QtCore, QtGui, QtWidgets
                return QtCore, QtGui, QtWidgets
            except Exception as exc:
                last_error = exc
        raise RuntimeError(
            'Failed to install PyQt6 locally. Install it manually with '
            f'"{sys.executable} -m pip install --target {dep_dir} PyQt6"'
        ) from last_error


def _reset_client_runtime_state() -> None:
    global users, typing, current_channel, dm_target, peer_bundles, peer_info_pending, peer_info_retrying
    global current_channel_salt, channel_key, channel_send_seq, channel_send_session_id, receive_running, current_channel_authenticated

    users = []
    typing = []
    current_channel = 'general'
    dm_target = None
    peer_bundles = {}
    peer_info_pending = set()
    peer_info_retrying = set()
    current_channel_salt = b''
    channel_key = b''
    channel_send_seq = 0
    channel_send_session_id = session_id_from_key(get_random_bytes(32), b'channel-session')
    message_window.clear_all()
    dm_window.clear_all()
    dh_keys.clear()
    dm_send_chain.clear()
    dm_recv_chain.clear()
    dm_session_ids.clear()
    pending_dh.clear()
    dm_queue.clear()
    dm_nonce_cache.clear()
    dm_send_seq.clear()
    dm_recv_seq.clear()
    dm_message_count.clear()
    channel_recv_seq.clear()
    channel_auth_failed_salts.clear()
    channel_auth_reset_attempts.clear()
    current_channel_authenticated = False
    channel_nonce_cache._deque.clear()
    channel_nonce_cache._set.clear()
    receive_running = False


def _make_black_cloud_gui_class(QtCore, QtGui, QtWidgets):
    class ImageViewerDialog(QtWidgets.QDialog):
        def __init__(self, parent, token: str):
            super().__init__(parent)
            self.token = sanitize_token(token, default='', max_len=32)
            record = get_memory_image_record(self.token)
            filename = str(record.get('filename') or 'image') if record else 'image'

            self.setWindowTitle(APP_TITLE + ' — Image Viewer')
            self.setModal(False)
            self.resize(920, 720)
            self.setStyleSheet(parent._stylesheet() if parent is not None else '')

            root = QtWidgets.QVBoxLayout(self)
            root.setContentsMargins(14, 14, 14, 14)
            root.setSpacing(10)

            title = QtWidgets.QLabel(filename)
            title.setObjectName('headerTitle')
            title.setWordWrap(True)
            root.addWidget(title)

            self.image_label = QtWidgets.QLabel()
            self.image_label.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
            self.image_label.setStyleSheet('background:#1e1f22; border-radius:10px; padding:10px;')

            self._viewer_pixmap = QtGui.QPixmap()
            if record:
                image_bytes = bytearray(record.get('raw', b''))
                try:
                    self._viewer_pixmap.loadFromData(bytes(image_bytes))
                finally:
                    secure_wipe_buffer(image_bytes)
                    del image_bytes
            if self._viewer_pixmap.isNull():
                self.image_label.setText('Could not open image from memory')
            else:
                screen = QtWidgets.QApplication.primaryScreen()
                screen_size = screen.availableGeometry().size() if screen else QtCore.QSize(1000, 760)
                max_w = max(520, min(1280, screen_size.width() - 160))
                max_h = max(420, min(900, screen_size.height() - 220))
                shown = self._viewer_pixmap.scaled(max_w, max_h, QtCore.Qt.AspectRatioMode.KeepAspectRatio, QtCore.Qt.TransformationMode.SmoothTransformation)
                self.image_label.setPixmap(shown)
                self.image_label.setMinimumSize(shown.size())

            scroll = QtWidgets.QScrollArea()
            scroll.setWidgetResizable(True)
            scroll.setFrameShape(QtWidgets.QFrame.Shape.NoFrame)
            scroll.setWidget(self.image_label)
            root.addWidget(scroll, 1)

            info_text = 'Stored in memory only — not saved locally. It disappears when this app closes/restarts.'
            if record:
                info_text += f"\n{record.get('size', 0)} bytes • {record.get('mime', 'image')} • SHA256 {record.get('sha256', '')[:12]}"
            info_label = QtWidgets.QLabel(info_text)
            info_label.setObjectName('mutedLabel')
            info_label.setTextInteractionFlags(QtCore.Qt.TextInteractionFlag.TextSelectableByMouse)
            info_label.setWordWrap(True)
            root.addWidget(info_label)

            buttons = QtWidgets.QHBoxLayout()
            wipe_button = QtWidgets.QPushButton('Wipe image from memory')
            wipe_button.clicked.connect(self.secure_wipe_current_image)
            buttons.addWidget(wipe_button)
            close_button = QtWidgets.QPushButton('Close')
            close_button.clicked.connect(self.close)
            buttons.addWidget(close_button)
            root.addLayout(buttons)

        def secure_wipe_current_image(self) -> None:
            self.image_label.clear()
            self.image_label.setText('Image wiped from memory.')
            try:
                self._viewer_pixmap = QtGui.QPixmap()
                QtGui.QPixmapCache.clear()
            except Exception:
                pass
            wipe_image_token(self.token)

        def closeEvent(self, event) -> None:
            try:
                self.image_label.clear()
                self._viewer_pixmap = QtGui.QPixmap()
                QtGui.QPixmapCache.clear()
                gc.collect()
            except Exception:
                pass
            super().closeEvent(event)

    class SettingsDialog(QtWidgets.QDialog):
        def __init__(self, parent, settings: dict, current_ip: str, current_username: str):
            super().__init__(parent)
            self.setWindowTitle(APP_TITLE + ' — Settings')
            self.setModal(True)
            self.setMinimumWidth(440)
            self._settings = dict(settings or {})
            self.setStyleSheet(parent._stylesheet() if parent is not None else '')

            root = QtWidgets.QVBoxLayout(self)
            root.setContentsMargins(20, 18, 20, 18)
            root.setSpacing(14)

            title = QtWidgets.QLabel('Settings')
            title.setObjectName('headerTitle')
            title.setFont(QtGui.QFont('Segoe UI', 15, QtGui.QFont.Weight.Bold))
            root.addWidget(title)

            note = QtWidgets.QLabel('Saved locally in encrypted settings. Connection fields stay on the main screen.')
            note.setObjectName('mutedLabel')
            note.setWordWrap(True)
            root.addWidget(note)

            box = QtWidgets.QFrame()
            box.setObjectName('settingsCard')
            box_layout = QtWidgets.QVBoxLayout(box)
            box_layout.setContentsMargins(14, 14, 14, 14)
            box_layout.setSpacing(12)

            self.remember_check = QtWidgets.QCheckBox('Remember IP/user')
            self.remember_check.setChecked(bool(self._settings.get('remember_connection', True)))
            box_layout.addWidget(self.remember_check)

            self.stream_guard_check = QtWidgets.QCheckBox('Stream guard')
            self.stream_guard_check.setChecked(bool(self._settings.get('stream_guard', True)))
            box_layout.addWidget(self.stream_guard_check)

            self.strip_meta_check = QtWidgets.QCheckBox('Strip image metadata before sending pictures')
            self.strip_meta_check.setChecked(bool(self._settings.get('strip_image_metadata', True)))
            box_layout.addWidget(self.strip_meta_check)

            root.addWidget(box)

            remembered = QtWidgets.QFrame()
            remembered.setObjectName('settingsCard')
            remembered_layout = QtWidgets.QFormLayout(remembered)
            remembered_layout.setContentsMargins(14, 14, 14, 14)
            remembered_layout.setSpacing(10)
            remembered_layout.setLabelAlignment(QtCore.Qt.AlignmentFlag.AlignLeft)

            self.saved_ip_edit = QtWidgets.QLineEdit(str(self._settings.get('last_ip') or current_ip or '127.0.0.1'))
            self.saved_ip_edit.setPlaceholderText('Saved server IP')
            self.saved_user_edit = QtWidgets.QLineEdit(sanitize_token(str(self._settings.get('last_username') or current_username or getpass.getuser()), default='user', max_len=48))
            self.saved_user_edit.setPlaceholderText('Saved username')
            remembered_layout.addRow('Saved IP', self.saved_ip_edit)
            remembered_layout.addRow('Saved user', self.saved_user_edit)
            root.addWidget(remembered)

            buttons = QtWidgets.QDialogButtonBox(
                QtWidgets.QDialogButtonBox.StandardButton.Save | QtWidgets.QDialogButtonBox.StandardButton.Cancel
            )
            buttons.accepted.connect(self.accept)
            buttons.rejected.connect(self.reject)
            root.addWidget(buttons)

        def values(self) -> dict:
            remember = bool(self.remember_check.isChecked())
            return {
                'remember_connection': remember,
                'last_ip': self.saved_ip_edit.text().strip() if remember else '',
                'last_username': sanitize_token(self.saved_user_edit.text().strip(), default='user', max_len=48) if remember else '',
                'stream_guard': bool(self.stream_guard_check.isChecked()),
                'strip_image_metadata': bool(self.strip_meta_check.isChecked()),
            }

    class BlackCloudGUI(QtWidgets.QMainWindow):
        chat_line_signal = QtCore.pyqtSignal(str)
        dm_line_signal = QtCore.pyqtSignal(str)
        refresh_signal = QtCore.pyqtSignal()
        error_signal = QtCore.pyqtSignal(str, str)
        question_signal = QtCore.pyqtSignal(str, str, object)
        clear_logs_signal = QtCore.pyqtSignal()
        set_connect_enabled_signal = QtCore.pyqtSignal(bool)
        set_channel_text_signal = QtCore.pyqtSignal(str)
        set_dm_text_signal = QtCore.pyqtSignal(str)

        def __init__(self):
            super().__init__()
            self.sock: Optional[socket.socket] = None
            self.connected = False
            self.server_thread: Optional[threading.Thread] = None
            self.settings = load_local_settings()
            apply_runtime_settings(self.settings)
            self._settings_loading = True
            self._title_font = QtGui.QFont('Segoe UI', 14, QtGui.QFont.Weight.Bold)
            self._body_font = QtGui.QFont('Segoe UI', 10)

            self.chat_line_signal.connect(self._append_chat_line_ui)
            self.dm_line_signal.connect(self._append_dm_line_ui)
            self.refresh_signal.connect(self._refresh_state_ui)
            self.error_signal.connect(self._show_error_ui)
            self.question_signal.connect(self._ask_yes_no_ui)
            self.clear_logs_signal.connect(self._clear_text_widgets_ui)

            self._build_ui()
            self.set_connect_enabled_signal.connect(self.connect_button.setEnabled)
            self.set_channel_text_signal.connect(self.channel_edit.setText)
            self.set_dm_text_signal.connect(self.dm_edit.setText)
            self._settings_loading = False
            self.refresh_state()

        def _build_ui(self) -> None:
            self.setWindowTitle(APP_TITLE + ' — PyQt6')
            self.resize(1320, 820)
            self.setMinimumSize(1040, 640)
            self.setObjectName('mainWindow')
            self.setStyleSheet(self._stylesheet())

            central = QtWidgets.QWidget()
            self.setCentralWidget(central)
            root = QtWidgets.QHBoxLayout(central)
            root.setContentsMargins(0, 0, 0, 0)
            root.setSpacing(0)

            rail = QtWidgets.QFrame()
            rail.setObjectName('serverRail')
            rail.setFixedWidth(74)
            rail_layout = QtWidgets.QVBoxLayout(rail)
            rail_layout.setContentsMargins(10, 14, 10, 14)
            rail_layout.setSpacing(12)

            logo = QtWidgets.QLabel('☁')
            logo.setObjectName('serverIconActive')
            logo.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
            rail_layout.addWidget(logo)

            for label in ('#', '@'):
                icon = QtWidgets.QLabel(label)
                icon.setObjectName('serverIcon')
                icon.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
                rail_layout.addWidget(icon)

            self.settings_button = QtWidgets.QPushButton('⚙')
            self.settings_button.setObjectName('serverIconButton')
            self.settings_button.setToolTip('Settings')
            self.settings_button.clicked.connect(self.open_settings)
            rail_layout.addWidget(self.settings_button)
            rail_layout.addStretch(1)
            self.secure_dot = QtWidgets.QLabel('●')
            self.secure_dot.setObjectName('offlineDot')
            self.secure_dot.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
            rail_layout.addWidget(self.secure_dot)
            root.addWidget(rail)

            sidebar = QtWidgets.QFrame()
            sidebar.setObjectName('sidebar')
            sidebar.setFixedWidth(292)
            side_layout = QtWidgets.QVBoxLayout(sidebar)
            side_layout.setContentsMargins(16, 16, 16, 14)
            side_layout.setSpacing(10)

            title = QtWidgets.QLabel('BLACK CLOUD')
            title.setObjectName('appTitle')
            title.setFont(self._title_font)
            side_layout.addWidget(title)

            subtitle = QtWidgets.QLabel('secure encrypted chat')
            subtitle.setObjectName('mutedLabel')
            side_layout.addWidget(subtitle)

            self.status_pill = QtWidgets.QLabel('Not connected')
            self.status_pill.setObjectName('statusPill')
            self.status_pill.setWordWrap(True)
            side_layout.addWidget(self.status_pill)

            side_layout.addWidget(self._section_label('Connection'))
            self.ip_edit = QtWidgets.QLineEdit(str(self.settings.get('last_ip') or '127.0.0.1'))
            self.ip_edit.setPlaceholderText('Server IP')
            side_layout.addWidget(self.ip_edit)

            self.nick_edit = QtWidgets.QLineEdit(sanitize_token(str(self.settings.get('last_username') or getpass.getuser()), default='user', max_len=48))
            self.nick_edit.setPlaceholderText('Nickname')
            side_layout.addWidget(self.nick_edit)

            self.password_edit = QtWidgets.QLineEdit()
            self.password_edit.setPlaceholderText('Channel password')
            self.password_edit.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)
            side_layout.addWidget(self.password_edit)

            button_row = QtWidgets.QHBoxLayout()
            self.server_button = QtWidgets.QPushButton('Start Server')
            self.server_button.clicked.connect(self.start_server)
            self.connect_button = QtWidgets.QPushButton('Connect')
            self.connect_button.setObjectName('primaryButton')
            self.connect_button.clicked.connect(self.connect)
            button_row.addWidget(self.server_button)
            button_row.addWidget(self.connect_button)
            side_layout.addLayout(button_row)

            self.disconnect_button = QtWidgets.QPushButton('Disconnect')
            self.disconnect_button.clicked.connect(self.disconnect)
            side_layout.addWidget(self.disconnect_button)

            side_layout.addWidget(self._section_label('Text Channels'))
            channel_row = QtWidgets.QHBoxLayout()
            self.channel_edit = QtWidgets.QLineEdit('general')
            self.channel_edit.setPlaceholderText('channel')
            self.join_button = QtWidgets.QPushButton('Join')
            self.join_button.clicked.connect(self.join_channel)
            channel_row.addWidget(self.channel_edit, 1)
            channel_row.addWidget(self.join_button)
            side_layout.addLayout(channel_row)

            self.channel_card = QtWidgets.QLabel('# general')
            self.channel_card.setObjectName('channelCardActive')
            side_layout.addWidget(self.channel_card)

            side_layout.addWidget(self._section_label('Direct Messages'))
            dm_row = QtWidgets.QHBoxLayout()
            self.dm_edit = QtWidgets.QLineEdit()
            self.dm_edit.setPlaceholderText('user / anon tag')
            self.dm_button = QtWidgets.QPushButton('DM')
            self.dm_button.clicked.connect(self.start_dm_from_entry)
            dm_row.addWidget(self.dm_edit, 1)
            dm_row.addWidget(self.dm_button)
            side_layout.addLayout(dm_row)
            self.back_button = QtWidgets.QPushButton('Back to #chat')
            self.back_button.clicked.connect(self.back_to_chat)
            side_layout.addWidget(self.back_button)
            side_layout.addStretch(1)

            help_label = QtWidgets.QLabel('Commands still work: /join, /dm, /back, /users, /img, /help')
            help_label.setObjectName('helpText')
            help_label.setWordWrap(True)
            side_layout.addWidget(help_label)
            root.addWidget(sidebar)

            main = QtWidgets.QFrame()
            main.setObjectName('mainPanel')
            main_layout = QtWidgets.QVBoxLayout(main)
            main_layout.setContentsMargins(0, 0, 0, 0)
            main_layout.setSpacing(0)

            header = QtWidgets.QFrame()
            header.setObjectName('chatHeader')
            header_layout = QtWidgets.QHBoxLayout(header)
            header_layout.setContentsMargins(20, 12, 20, 12)
            self.header_title = QtWidgets.QLabel('# general')
            self.header_title.setObjectName('headerTitle')
            self.header_title.setFont(self._title_font)
            header_layout.addWidget(self.header_title)
            self.header_subtitle = QtWidgets.QLabel('Encrypted channel messages')
            self.header_subtitle.setObjectName('mutedLabel')
            header_layout.addWidget(self.header_subtitle)
            header_layout.addStretch(1)
            self.typing_label = QtWidgets.QLabel('')
            self.typing_label.setObjectName('typingLabel')
            header_layout.addWidget(self.typing_label)
            main_layout.addWidget(header)

            self.chat_log = QtWidgets.QTextBrowser()
            self.chat_log.setObjectName('chatLog')
            self.chat_log.setReadOnly(True)
            self.chat_log.setOpenExternalLinks(False)
            self.chat_log.anchorClicked.connect(self._handle_log_link)
            self.chat_log.setFont(self._body_font)
            main_layout.addWidget(self.chat_log, 1)

            composer = QtWidgets.QFrame()
            composer.setObjectName('composer')
            composer_layout = QtWidgets.QHBoxLayout(composer)
            composer_layout.setContentsMargins(18, 14, 18, 14)
            self.message_edit = QtWidgets.QLineEdit()
            self.message_edit.setObjectName('messageInput')
            self.message_edit.setPlaceholderText('Message #general')
            self.message_edit.returnPressed.connect(self.send_current_message)
            self.upload_button = QtWidgets.QPushButton('Upload Picture')
            self.upload_button.clicked.connect(self.upload_picture)
            self.wipe_images_button = QtWidgets.QPushButton('Wipe Images')
            self.wipe_images_button.clicked.connect(self.secure_wipe_images)
            self.send_button = QtWidgets.QPushButton('Send')
            self.send_button.setObjectName('primaryButton')
            self.send_button.clicked.connect(self.send_current_message)
            composer_layout.addWidget(self.message_edit, 1)
            composer_layout.addWidget(self.upload_button)
            composer_layout.addWidget(self.wipe_images_button)
            composer_layout.addWidget(self.send_button)
            main_layout.addWidget(composer)
            root.addWidget(main, 1)

            right = QtWidgets.QFrame()
            right.setObjectName('memberPanel')
            right.setFixedWidth(330)
            right_layout = QtWidgets.QVBoxLayout(right)
            right_layout.setContentsMargins(14, 16, 14, 14)
            right_layout.setSpacing(10)

            right_layout.addWidget(self._section_label('Online Members'))
            self.user_list = QtWidgets.QListWidget()
            self.user_list.setObjectName('memberList')
            self.user_list.itemDoubleClicked.connect(self._user_double_click)
            right_layout.addWidget(self.user_list, 1)

            right_layout.addWidget(self._section_label('DM Activity'))
            self.dm_log = QtWidgets.QTextBrowser()
            self.dm_log.setObjectName('dmLog')
            self.dm_log.setReadOnly(True)
            self.dm_log.setOpenExternalLinks(False)
            self.dm_log.anchorClicked.connect(self._handle_log_link)
            self.dm_log.setFont(self._body_font)
            right_layout.addWidget(self.dm_log, 1)
            root.addWidget(right)

        def _save_settings_from_ui(self, *_args) -> None:
            if getattr(self, '_settings_loading', False):
                return
            remember = bool(self.settings.get('remember_connection', True))
            self.settings.update({
                'remember_connection': remember,
                'last_ip': self.ip_edit.text().strip() if remember else '',
                'last_username': sanitize_token(self.nick_edit.text().strip(), default='user', max_len=48) if remember else '',
                'stream_guard': bool(self.settings.get('stream_guard', True)),
                'strip_image_metadata': bool(self.settings.get('strip_image_metadata', True)),
            })
            self._persist_settings()

        def _persist_settings(self) -> None:
            apply_runtime_settings(self.settings)
            try:
                save_local_settings(self.settings)
            except Exception as exc:
                add_message(status_line('WARN', f'Could not save encrypted settings: {exc}'))

        def open_settings(self) -> None:
            dialog = SettingsDialog(
                self,
                self.settings,
                self.ip_edit.text().strip() or '127.0.0.1',
                self.nick_edit.text().strip() or getpass.getuser(),
            )
            if dialog.exec() != QtWidgets.QDialog.DialogCode.Accepted:
                return
            self.settings.update(dialog.values())
            if self.settings.get('remember_connection', True):
                saved_ip = str(self.settings.get('last_ip') or '').strip()
                saved_user = sanitize_token(str(self.settings.get('last_username') or ''), default='', max_len=48)
                if saved_ip:
                    self.ip_edit.setText(saved_ip)
                if saved_user:
                    self.nick_edit.setText(saved_user)
            self._persist_settings()
            add_message(status_line('OK', 'Encrypted settings saved'))

        def _remember_connection(self, ip: str, nickname: str) -> None:
            if bool(self.settings.get('remember_connection', True)):
                self.settings['last_ip'] = ip
                self.settings['last_username'] = sanitize_token(nickname, default='user', max_len=48)
                self._persist_settings()

        def _section_label(self, text: str):
            label = QtWidgets.QLabel(text.upper())
            label.setObjectName('sectionLabel')
            return label

        def _stylesheet(self) -> str:
            return '''
            QMainWindow#mainWindow, QWidget { background: #313338; color: #dbdee1; font-family: "Segoe UI", Arial; }
            QFrame#serverRail { background: #1e1f22; }
            QLabel#serverIcon, QLabel#serverIconActive, QPushButton#serverIconButton {
                min-width: 48px; min-height: 48px; max-width: 48px; max-height: 48px;
                border-radius: 24px; font-size: 22px; font-weight: 700; padding: 0px;
            }
            QLabel#serverIcon, QPushButton#serverIconButton { background: #313338; color: #b5bac1; }
            QPushButton#serverIconButton:hover { background: #404249; color: white; }
            QLabel#serverIconActive { background: #5865f2; color: white; }
            QLabel#offlineDot { color: #f23f42; font-size: 22px; }
            QLabel#onlineDot { color: #23a55a; font-size: 22px; }
            QFrame#sidebar { background: #2b2d31; border-right: 1px solid #1f2023; }
            QFrame#mainPanel { background: #313338; }
            QFrame#memberPanel { background: #2b2d31; border-left: 1px solid #1f2023; }
            QFrame#chatHeader { background: #313338; border-bottom: 1px solid #242529; }
            QFrame#composer { background: #313338; border-top: 1px solid #242529; }
            QLabel#appTitle, QLabel#headerTitle { color: #f2f3f5; font-weight: 700; }
            QLabel#mutedLabel, QLabel#helpText { color: #949ba4; }
            QLabel#typingLabel { color: #949ba4; font-style: italic; }
            QLabel#sectionLabel { color: #949ba4; font-size: 11px; font-weight: 800; letter-spacing: 1px; padding-top: 12px; }
            QLabel#statusPill, QLabel#channelCardActive {
                background: #383a40; color: #dbdee1; border-radius: 8px; padding: 9px 10px;
            }
            QLabel#channelCardActive { background: #404249; color: #ffffff; font-weight: 700; }
            QFrame#settingsCard { background: #2b2d31; border: 1px solid #1f2023; border-radius: 10px; }
            QCheckBox { spacing: 9px; color: #dbdee1; font-weight: 700; }
            QCheckBox::indicator { width: 18px; height: 18px; border-radius: 5px; border: 1px solid #202225; background: #1e1f22; }
            QCheckBox::indicator:checked { background: #5865f2; border: 1px solid #5865f2; }
            QDialog { background: #313338; color: #dbdee1; }
            QLineEdit {
                background: #1e1f22; color: #dbdee1; border: 1px solid #202225;
                border-radius: 8px; padding: 9px 10px; selection-background-color: #5865f2;
            }
            QLineEdit:focus { border: 1px solid #5865f2; }
            QLineEdit#messageInput { background: #383a40; border: none; border-radius: 10px; padding: 12px 14px; }
            QPushButton {
                background: #4e5058; color: #ffffff; border: none; border-radius: 8px;
                padding: 9px 12px; font-weight: 700;
            }
            QPushButton:hover { background: #5c5f68; }
            QPushButton:pressed { background: #3f4147; }
            QPushButton#primaryButton { background: #5865f2; }
            QPushButton#primaryButton:hover { background: #4752c4; }
            QTextBrowser#chatLog, QTextBrowser#dmLog {
                background: #313338; color: #dbdee1; border: none; padding: 16px;
            }
            QTextBrowser#dmLog { background: #2b2d31; }
            QListWidget#memberList {
                background: #2b2d31; color: #dbdee1; border: none; outline: 0;
            }
            QListWidget#memberList::item {
                padding: 10px 8px; border-radius: 8px; margin: 1px 0px;
            }
            QListWidget#memberList::item:selected { background: #404249; color: #ffffff; }
            QScrollBar:vertical { background: transparent; width: 10px; margin: 4px; }
            QScrollBar::handle:vertical { background: #1e1f22; border-radius: 5px; min-height: 28px; }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0px; }
            QMessageBox { background: #313338; color: #dbdee1; }
            '''

        def _extract_image_token_from_line(self, line: str) -> str:
            clean = strip_ansi(str(line)).rstrip('\n')
            match = re.search(r'\[image:([0-9a-fA-F]{24})\]', clean)
            if not match:
                return ''
            token = sanitize_token(match.group(1), default='', max_len=32)
            return token if get_memory_image_record(token) else ''

        def _line_without_image_token(self, line: str) -> str:
            return re.sub(r'\s*\[image:[0-9a-fA-F]{24}\]', '', strip_ansi(str(line))).rstrip('\n')

        def _normalize_image_token(self, token: str) -> str:
            safe_token = sanitize_token(token, default='', max_len=32)
            return safe_token if get_memory_image_record(safe_token) else ''

        def _image_preview_html(self, token: str) -> str:
            import html
            record = get_memory_image_record(token)
            if not record:
                return ''
            pixmap = QtGui.QPixmap()
            image_bytes = bytearray(record.get('raw', b''))
            try:
                pixmap.loadFromData(bytes(image_bytes))
            finally:
                secure_wipe_buffer(image_bytes)
                del image_bytes
            if pixmap.isNull():
                return ''
            max_w, max_h = 420, 280
            shown = pixmap.scaled(max_w, max_h, QtCore.Qt.AspectRatioMode.KeepAspectRatio, QtCore.Qt.TransformationMode.SmoothTransformation)
            name = html.escape(str(record.get('filename') or 'image'))
            safe_token = sanitize_token(token, default='', max_len=32)
            src = f'bcimgthumb:{safe_token}'
            return (
                '<div style="margin-top:8px;">'
                f'<a href="bcimg:{safe_token}">'
                f'<img src="{src}" width="{shown.width()}" height="{shown.height()}" />'
                '</a>'
                f'<div style="margin-top:6px;"><a style="color:#8ea1e1;" href="bcimg:{safe_token}">View full image</a>'
                f'<span style="color:#949ba4;"> · {name} · memory only</span></div>'
                '</div>'
            )

        def _message_html(self, line: str, accent: str = '#5865f2') -> str:
            import html
            raw_line = strip_ansi(str(line)).rstrip('\n')
            image_token = self._extract_image_token_from_line(raw_line)
            display_line = self._line_without_image_token(raw_line) if image_token else raw_line
            cleaned = html.escape(display_line)
            if not cleaned:
                cleaned = '&nbsp;'
            image_html = self._image_preview_html(image_token) if image_token else ''
            return (
                f'<div style="margin:7px 0; padding:9px 11px; border-radius:10px; '
                f'background:#383a40; border-left:4px solid {accent}; color:#dbdee1;">'
                f'<span style="white-space:pre-wrap;">{cleaned}</span>{image_html}</div>'
            )

        def _handle_log_link(self, url) -> None:
            link = url.toString()
            if link.startswith('bcimg:'):
                token = self._normalize_image_token(link[len('bcimg:'):])
                if token:
                    viewer = ImageViewerDialog(self, token)
                    viewer.exec()
                else:
                    self._show_error(APP_TITLE, 'Image is no longer in memory. It was not saved locally.')
                return
            QtGui.QDesktopServices.openUrl(url)

        def _add_image_resource_to_log(self, widget, token: str) -> None:
            safe_token = self._normalize_image_token(token)
            if not safe_token:
                return
            record = get_memory_image_record(safe_token)
            if not record:
                return
            pixmap = QtGui.QPixmap()
            image_bytes = bytearray(record.get('raw', b''))
            try:
                pixmap.loadFromData(bytes(image_bytes))
            finally:
                secure_wipe_buffer(image_bytes)
                del image_bytes
            if pixmap.isNull():
                return
            shown = pixmap.scaled(420, 280, QtCore.Qt.AspectRatioMode.KeepAspectRatio, QtCore.Qt.TransformationMode.SmoothTransformation)
            widget.document().addResource(
                QtGui.QTextDocument.ResourceType.ImageResource,
                QtCore.QUrl(f'bcimgthumb:{safe_token}'),
                shown,
            )

        def _append_text_ui(self, widget, line: str, accent: str) -> None:
            token = self._extract_image_token_from_line(str(line))
            if token:
                self._add_image_resource_to_log(widget, token)
            widget.append(self._message_html(line, accent))
            scrollbar = widget.verticalScrollBar()
            scrollbar.setValue(scrollbar.maximum())

        def append_chat_line(self, line: str) -> None:
            self.chat_line_signal.emit(str(line))

        def append_dm_line(self, line: str) -> None:
            self.dm_line_signal.emit(str(line))

        def _append_chat_line_ui(self, line: str) -> None:
            self._append_text_ui(self.chat_log, line, '#5865f2')

        def _append_dm_line_ui(self, line: str) -> None:
            self._append_text_ui(self.dm_log, line, '#eb459e')

        def refresh_state(self) -> None:
            self.refresh_signal.emit()

        def _refresh_state_ui(self) -> None:
            secure_state = 'ON' if channel_key else 'OFF'
            dm_state = display_name(dm_target) if dm_target else 'None'
            user_state = display_name(current_username) if current_username else 'None'
            conn_state = 'Connected' if self.connected else 'Not connected'
            self.status_pill.setText(f'{conn_state}\n#{current_channel}  •  DM: {dm_state}\nUSER: {user_state}  •  SECURE: {secure_state}')
            self.secure_dot.setObjectName('onlineDot' if channel_key and self.connected else 'offlineDot')
            self.secure_dot.style().unpolish(self.secure_dot)
            self.secure_dot.style().polish(self.secure_dot)
            self.channel_card.setText(f'# {current_channel}')
            self.header_title.setText(f'# {current_channel}')
            self.header_subtitle.setText('Encrypted channel messages' if channel_key else 'Waiting for channel key')
            self.message_edit.setPlaceholderText(f'Message {display_name(dm_target) if dm_target else "#" + current_channel}')
            self.typing_label.setText(('typing: ' + ', '.join(display_name(name) for name in typing)) if typing else '')

            selected_items = self.user_list.selectedItems()
            selected_name = selected_items[0].data(QtCore.Qt.ItemDataRole.UserRole) if selected_items else None
            self.user_list.clear()
            for name in users:
                item = QtWidgets.QListWidgetItem(f'●  {display_name(name)}')
                item.setData(QtCore.Qt.ItemDataRole.UserRole, name)
                if name == current_username:
                    item.setText(f'●  {display_name(name)}  (you)')
                self.user_list.addItem(item)
                if name == selected_name:
                    item.setSelected(True)

        def _ask_yes_no(self, title: str, message: str) -> bool:
            if QtCore.QThread.currentThread() == self.thread():
                return self._ask_yes_no_dialog(title, message)
            result = {'value': False}
            done = threading.Event()
            self.question_signal.emit(title, message, (result, done))
            done.wait()
            return bool(result['value'])

        def _ask_yes_no_ui(self, title: str, message: str, payload: object) -> None:
            result, done = payload
            try:
                result['value'] = self._ask_yes_no_dialog(title, message)
            finally:
                done.set()

        def _ask_yes_no_dialog(self, title: str, message: str) -> bool:
            answer = QtWidgets.QMessageBox.question(
                self,
                title,
                message,
                QtWidgets.QMessageBox.StandardButton.Yes | QtWidgets.QMessageBox.StandardButton.No,
                QtWidgets.QMessageBox.StandardButton.No,
            )
            return answer == QtWidgets.QMessageBox.StandardButton.Yes

        def _show_error(self, title: str, message: str) -> None:
            self.error_signal.emit(str(title), str(message))

        def _show_error_ui(self, title: str, message: str) -> None:
            QtWidgets.QMessageBox.critical(self, title, message)

        def _user_double_click(self, item=None) -> None:
            if item is None:
                selected = self.user_list.selectedItems()
                if not selected:
                    return
                item = selected[0]
            target = item.data(QtCore.Qt.ItemDataRole.UserRole)
            if target:
                self.set_dm_text_signal.emit(target)
                self.start_dm(target)

        def start_server(self) -> None:
            if self.server_thread and self.server_thread.is_alive():
                add_message(status_line('INFO', f'Server is already running on {HOST}:{PORT}'))
                return
            self.server_thread = threading.Thread(target=server, daemon=True)
            self.server_thread.start()
            add_message(status_line('OK', f'Server starting on {HOST}:{PORT}'))

        def connect(self) -> None:
            if self.connected:
                add_message(status_line('INFO', 'Already connected'))
                return
            ip = self.ip_edit.text().strip() or '127.0.0.1'
            nickname = sanitize_token(self.nick_edit.text().strip(), default='user', max_len=48)
            password = self.password_edit.text()
            if not password:
                self._show_error(APP_TITLE, 'Enter the channel password first.')
                return
            self._remember_connection(ip, nickname)
            self.connect_button.setEnabled(False)
            self.status_pill.setText(f'Connecting to {ip}:{PORT}...')
            threading.Thread(target=self._connect_worker, args=(ip, nickname, password), daemon=True).start()

        def _connect_worker(self, ip: str, nickname: str, password: str) -> None:
            global current_channel, dm_target, current_username, local_enc_private_key, local_signing_key
            global peer_pins, peer_bundles, peer_info_pending, peer_info_retrying
            global master_password_key, server_context_key, current_channel_salt, channel_key, current_channel_authenticated
            global receive_running, channel_send_seq, channel_send_session_id

            _reset_client_runtime_state()
            add_message(status_line('INFO', f'Connecting to {ip}:{PORT}'))
            sock = None
            try:
                raw = socket.create_connection((ip, PORT), timeout=8.0)
                raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                tls_context = build_client_ssl_context()
                sock = tls_context.wrap_socket(raw, server_hostname=TLS_COMMON_NAME)
                sock.settimeout(None)
                cert_der = sock.getpeercert(binary_form=True)
                if not cert_der:
                    raise RuntimeError('Server did not provide a TLS certificate')

                tls_fp, tls_pin_state, known_tls_fp = pin_or_verify_server_certificate(f'{ip}:{PORT}', cert_der)
                printable_fp = fingerprint_key(bytes.fromhex(tls_fp))
                if tls_pin_state == 'new':
                    if not self._ask_yes_no(APP_TITLE, f'First connection to {ip}:{PORT}.\n\nServer fingerprint:\n{printable_fp}\n\nTrust and pin this server?'):
                        raise RuntimeError('Server certificate not trusted')
                    save_tls_pin(f'{ip}:{PORT}', tls_fp)
                    tls_pin_state = 'pinned'
                elif tls_pin_state == 'mismatch':
                    old_printable_fp = fingerprint_key(bytes.fromhex(known_tls_fp)) if known_tls_fp else 'UNKNOWN'
                    if not self._ask_yes_no(APP_TITLE, f'TLS certificate fingerprint mismatch.\n\nKnown fp: {old_printable_fp}\nNew fp:    {printable_fp}\n\nReplace the saved pin?'):
                        raise RuntimeError('Server certificate mismatch not accepted')
                    save_tls_pin(f'{ip}:{PORT}', tls_fp)
                    tls_pin_state = 're-pinned'

                server_context_key = bytes.fromhex(tls_fp)
                add_message(status_line('SECURE', f'TLS/OpenSSL {tls_pin_state} | fp {printable_fp}'))

                prompt = recv_line(sock)
                if prompt != 'NICK':
                    raise RuntimeError(f'Unexpected server handshake: {prompt!r}')

                if len(password) < MIN_PASSWORD_LEN:
                    raise RuntimeError(f'Password must be at least {MIN_PASSWORD_LEN} characters')
                charset_count = sum([
                    any(ch.islower() for ch in password),
                    any(ch.isupper() for ch in password),
                    any(ch.isdigit() for ch in password),
                    any(not ch.isalnum() for ch in password),
                ])
                if charset_count < 3:
                    raise RuntimeError('Password must use at least 3 of: lowercase, uppercase, digits, symbols')

                current_username = nickname
                current_channel = 'general'
                dm_target = None
                peer_pins = load_peer_pins()
                peer_bundles = {}
                peer_info_pending = set()
                peer_info_retrying = set()
                local_enc_private_key, local_signing_key = ensure_local_identity_material()
                master_password_key = derive_master_password_key(password, server_context_key)
                password = ''
                current_channel_salt = b''
                channel_key = b''
                current_channel_authenticated = False
                channel_send_seq = 0
                channel_send_session_id = session_id_from_key(get_random_bytes(32), b'channel-session')

                if not send_line(sock, current_username):
                    raise RuntimeError('Failed to send nickname')
                local_bundle = build_identity_bundle(current_username, local_enc_private_key, local_signing_key)
                if not send_line(sock, f"KEYREG|{local_bundle['enc_pub']}|{local_bundle['sign_pub']}|{local_bundle['bundle_sig']}"):
                    raise RuntimeError('Failed to register E2E identity')

                self.sock = sock
                self.connected = True
                receive_running = True
                threading.Thread(target=receive, args=(sock,), daemon=True).start()
                threading.Thread(target=cleanup, daemon=True).start()
                add_message(status_line('OK', f'Connected as {display_name(current_username)}'))
                self.refresh_state()
            except Exception as exc:
                if sock is not None:
                    try:
                        sock.close()
                    except OSError:
                        pass
                self.sock = None
                self.connected = False
                receive_running = False
                add_message(status_line('ERR', f'Failed to connect securely: {exc}'))
                self._show_error(APP_TITLE, str(exc))
            finally:
                self.set_connect_enabled_signal.emit(True)
                self.refresh_state()

        def disconnect(self) -> None:
            global receive_running
            receive_running = False
            if self.sock is not None:
                try:
                    self.sock.close()
                except OSError:
                    pass
            self.sock = None
            self.connected = False
            add_message(status_line('WARN', 'Disconnected'))
            self.refresh_state()

        def join_channel(self) -> None:
            channel = sanitize_token(self.channel_edit.text().strip(), default='general')
            if not self.sock or not self.connected:
                add_message(status_line('WARN', 'Connect first'))
                return
            self._join_channel(channel)

        def _join_channel(self, channel: str) -> None:
            global current_channel, current_channel_salt, channel_key, channel_send_session_id, dm_target, channel_send_seq, current_channel_authenticated
            current_channel = sanitize_token(channel, default='general')
            current_channel_salt = b''
            channel_key = b''
            current_channel_authenticated = False
            channel_send_session_id = session_id_from_key(get_random_bytes(32), b'channel-session')
            dm_target = None
            message_window.clear_all()
            typing.clear()
            dh_keys.clear()
            dm_send_chain.clear()
            dm_recv_chain.clear()
            dm_session_ids.clear()
            pending_dh.clear()
            dm_queue.clear()
            dm_window.clear_all()
            dm_nonce_cache.clear()
            dm_send_seq.clear()
            dm_recv_seq.clear()
            dm_message_count.clear()
            channel_send_seq = 0
            channel_recv_seq.clear()
            channel_auth_failed_salts.clear()
            channel_auth_reset_attempts.clear()
            channel_nonce_cache._deque.clear()
            channel_nonce_cache._set.clear()
            self._clear_text_widgets()
            if not send_line(self.sock, f'/join {current_channel}'):
                add_message(status_line('ERR', 'Failed to join channel'))
            else:
                add_message(status_line('INFO', f'Joining #{current_channel}'))
            self.refresh_state()

        def _clear_text_widgets(self) -> None:
            self.clear_logs_signal.emit()

        def _clear_text_widgets_ui(self) -> None:
            self.chat_log.clear()
            self.dm_log.clear()

        def start_dm_from_entry(self) -> None:
            self.start_dm(self.dm_edit.text().strip())

        def start_dm(self, target_text: str) -> None:
            global dm_target
            if not self.sock or not self.connected:
                add_dm_message(status_line('WARN', 'Connect first'))
                return
            target = resolve_user_reference(target_text)
            if not target:
                add_dm_message(status_line('ERR', 'Invalid DM target'))
                return
            if target == current_username:
                add_dm_message(status_line('WARN', 'Cannot DM yourself'))
                return
            dm_target = target
            self.set_dm_text_signal.emit(target)
            if target not in peer_bundles:
                if request_peer_bundle(self.sock, target):
                    add_dm_message(status_line('SECURE', f'Requesting E2E identity for {color_user(target)}'))
                else:
                    add_dm_message(status_line('ERR', f'Failed to request E2E identity for {color_user(target)}'))
            else:
                add_dm_message(status_line('SECURE', f'E2E DM ready for {color_user(target)} | fp {peer_bundle_fingerprint(peer_bundles[target])}'))
            self.refresh_state()

        def back_to_chat(self) -> None:
            global dm_target
            dm_target = None
            add_dm_message(status_line('INFO', 'Back to channel chat'))
            self.refresh_state()


        def secure_wipe_images(self) -> None:
            wipe_all_image_memory()
            try:
                QtGui.QPixmapCache.clear()
                self.chat_log.clear()
                self.dm_log.clear()
            except Exception:
                pass
            gc.collect()
            add_message(status_line('OK', 'Image memory wiped; inline image previews cleared.'))

        def upload_picture(self) -> None:
            if not self.sock or not self.connected:
                add_message(status_line('WARN', 'Connect first'))
                return
            path, _selected_filter = QtWidgets.QFileDialog.getOpenFileName(
                self,
                'Upload encrypted picture',
                '',
                'Images (*.png *.jpg *.jpeg *.webp *.bmp);;All files (*)',
            )
            if not path:
                return
            threading.Thread(target=self._send_image_worker, args=(path,), daemon=True).start()

        def _send_image_worker(self, path: str) -> None:
            try:
                packet = build_image_packet(path)
            except Exception as exc:
                add_message(status_line('ERR', f'Image upload failed: {exc}'))
                self._show_error(APP_TITLE, f'Image upload failed: {exc}')
                return
            self._send_message_worker(packet)

        def send_current_message(self) -> None:
            msg = self.message_edit.text()
            if not msg:
                return
            self.message_edit.clear()
            threading.Thread(target=self._send_message_worker, args=(msg,), daemon=True).start()

        def _send_message_worker(self, msg: str) -> None:
            global current_channel, current_channel_salt, channel_key, channel_send_session_id, dm_target, channel_send_seq
            if not self.sock or not self.connected:
                add_message(status_line('WARN', 'Connect first'))
                return

            if msg == '/help':
                add_message(status_line('INFO', 'Use /join room, /dm user, /back, /users, /img path, /resetchannelpass. Buttons also work.'))
                return
            if msg == '/users':
                add_message(status_line('INFO', 'Users: ' + (', '.join(color_user(name) for name in users) if users else 'none')))
                return

            if msg == '/resetchannelpass':
                if not try_reset_channel_auth(self.sock, current_channel, 'manual reset'):
                    add_message(status_line('ERR', f'Failed to reset saved channel password for #{current_channel}'))
                return

            is_image_upload = isinstance(msg, str) and (msg.startswith(IMAGE_PACKET_PREFIX) or msg.startswith('/img '))
            if not is_image_upload:
                send_line(self.sock, '/typing on')
                threading.Timer(0.08, lambda: send_line(self.sock, '/typing off')).start()

            if msg.startswith('/join '):
                new_channel = sanitize_token(msg.split(' ', 1)[1].strip(), default='general')
                self.set_channel_text_signal.emit(new_channel)
                self._join_channel(new_channel)
                return

            if msg.startswith('/dm '):
                self.start_dm(msg.split(' ', 1)[1].strip())
                return

            if msg == '/back':
                self.back_to_chat()
                return

            if msg.startswith('/img '):
                image_path = msg.split(' ', 1)[1].strip().strip('"')
                try:
                    msg = build_image_packet(image_path)
                except Exception as exc:
                    add_message(status_line('ERR', f'Image upload failed: {exc}'))
                    return

            try:
                if dm_target:
                    bundle = peer_bundles.get(dm_target)
                    if not bundle:
                        queue_dm_message(dm_target, msg)
                        if request_peer_bundle(self.sock, dm_target):
                            add_dm_message(status_line('WARN', f'E2E identity not ready for {color_user(dm_target)}; message queued until their identity is online'))
                        else:
                            add_dm_message(status_line('ERR', f'Failed to request E2E identity for {color_user(dm_target)}'))
                        return
                    if not send_encrypted_dm_message(self.sock, dm_target, msg):
                        add_dm_message(status_line('ERR', f'Failed to send DM to {color_user(dm_target)}'))
                    else:
                        add_dm_message(format_entry(c(f'[{now()}]', Colors.BRIGHT_BLACK), get_user_color(current_username), f'{color_user(current_username)} → {color_user(dm_target)}: {message_preview(msg)}'))
                else:
                    if not ensure_channel_auth_ready(self.sock):
                        return
                    if not send_encrypted_channel_message(self.sock, msg):
                        add_message(status_line('ERR', 'Failed to send channel message'))
                    elif msg.startswith(IMAGE_PACKET_PREFIX):
                        add_message(format_entry(c(f'[{now()}]', Colors.BRIGHT_BLACK), get_user_color(current_username), f'{color_user(current_username)}: {message_preview(msg)}'))
            except ValueError as exc:
                add_message(status_line('ERR', str(exc)))
            except Exception as exc:
                add_message(status_line('ERR', f'Unexpected send error: {exc}'))
            finally:
                if isinstance(msg, str) and msg.startswith(IMAGE_PACKET_PREFIX):
                    msg = ''
                    gc.collect()

        def closeEvent(self, event) -> None:
            try:
                wipe_all_image_memory()
                QtGui.QPixmapCache.clear()
                self.chat_log.clear()
                self.dm_log.clear()
                gc.collect()
                self.disconnect()
            finally:
                event.accept()

    return BlackCloudGUI


def launch_gui() -> None:
    global GUI_APP, COLOR_ENABLED
    COLOR_ENABLED = False
    try:
        QtCore, QtGui, QtWidgets = ensure_pyqt6()
    except Exception as exc:
        print(status_line('ERR', f'PyQt6 GUI is not available: {exc}'))
        print(status_line('INFO', 'Run with --cli to use the command-line mode.'))
        return

    app = QtWidgets.QApplication(sys.argv)
    app.setApplicationName(APP_TITLE)
    GuiClass = _make_black_cloud_gui_class(QtCore, QtGui, QtWidgets)
    GUI_APP = GuiClass()
    GUI_APP.show()
    sys.exit(app.exec())


# ===================== MAIN =====================
if __name__ == '__main__':
    if '--cli' in sys.argv:
        print_banner()
        print(c('1 = server\n2 = client', Colors.BRIGHT_CYAN))
        mark_local_activity()
        choice = input('> ').strip()
        if choice == '1':
            server()
        else:
            mark_local_activity()
            settings = load_local_settings()
            apply_runtime_settings(settings)
            default_ip = str(settings.get('last_ip') or '127.0.0.1')
            begin_stream_guard_input()
            ip = input(f'IP [{default_ip}]: ').strip() or default_ip
            end_stream_guard_input()
            if settings.get('remember_connection', True):
                settings['last_ip'] = ip
                save_local_settings(settings)
            client(ip)
    else:
        launch_gui()
