from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
import os
import base64


# The .pem key file will always start with this prefix string
PEM_START = '-----BEGIN'
w1_length = 16
w1_iteration = 4096
w2_length = 16
w2_iteration = 2048


def password_to_w(salt, password, iteration, key_size):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_size,
        salt=salt,
        iterations=iteration,
        backend=default_backend()
    )
    return kdf.derive(password)


# load public key from key file
def load_public(filename):
    with open(filename, "rb") as key_file:
        try:
            content = key_file.read()
            return deserialize_public_key(content)
        except (IOError, ValueError, TypeError, UnsupportedAlgorithm) as e:
            print 'fail reading key file', e
            raise e


# load public key from string
def deserialize_public_key(content):
    try:
        # if it is a .pem type file, we call load_pem_private_key()
        if content[:10] == PEM_START:
            return serialization.load_pem_public_key(
                content,
                backend=default_backend())
        # otherwise it is a .der file
        else:
            return serialization.load_der_public_key(
                content,
                backend=default_backend())
    except (ValueError, TypeError, UnsupportedAlgorithm) as e:
        print 'error when deserialize private key', e
        raise e


# load private key from key file
def load_private(filename):
    with open(filename, "rb") as key_file:
        try:
            content = key_file.read()
            return deserialize_private_key(content)
        except (IOError, ValueError, TypeError, UnsupportedAlgorithm) as e:
            print 'fail reading key file', e
            raise e


# load private key from string
def deserialize_private_key(content):
    try:
        # if it is a .pem type file, we call load_pem_private_key()
        if content[:10] == PEM_START:
            return serialization.load_pem_private_key(
                content,
                password=None,
                backend=default_backend())
        # otherwise it is a .der file
        else:
            return serialization.load_der_private_key(
                content,
                password=None,
                backend=default_backend())
    except (ValueError, TypeError, UnsupportedAlgorithm) as e:
        print 'error when deserialize private key', e
        raise e


def encrypt_private_key(filename, password, salt):
    with open(filename, "rb") as key_file:
        try:
            content = key_file.read()
            key = password_to_w(salt, password, w2_iteration, w2_length)
            return salt + aes_cgm_random_iv(content, key)
        except (IOError, ValueError, TypeError, UnsupportedAlgorithm) as e:
            print 'fail reading key file', e
            raise e


def b64encode_aes_ctr(content, key):
    return base64.b64encode(aes_ctr_random_iv(content, key))


def aes_ctr_random_iv(content, key):
    iv = os.urandom(16)
    return iv + aes_ctr_encrypt(content, key, iv)


def aes_ctr_encrypt(content, key, iv):
    cipher = Cipher(algorithms.AES(key),
                    modes.CTR(iv),
                    backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(content) + encryptor.finalize()


def aes_ctr_decrypt(cipher_content, key, iv):
    cipher = Cipher(algorithms.AES(key),
                    modes.CTR(iv),
                    backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(cipher_content) + decryptor.finalize()


def aes_cgm_encrypt(content, key, iv):
    cipher = Cipher(algorithms.AES(key),
                    modes.GCM(iv),
                    backend=default_backend())
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(content) + encryptor.finalize()
    tag = encryptor.tag
    return tag + cipher_text


def aes_cgm_random_iv(content, key):
    iv = os.urandom(16)
    return iv + aes_cgm_encrypt(content, key, iv)


def b64encode_aes_cgm_encrypt(content, key):
    return base64.b64encode(aes_cgm_random_iv(content, key))


def aes_cgm_decrypt(cipher_text, key, iv, tag):
    decryptor = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend()).decryptor()
    return decryptor.update(cipher_text) + decryptor.finalize()


def b64decode_aes_cgm_decrypt(content, key):
    decoded_data = base64.b64decode(content)
    iv, tag, data = decoded_data[:16], decoded_data[16:32], decoded_data[32:]
    return aes_cgm_decrypt(data, key, iv, tag)


def decrypt_private_key(cipher_file, password):
    salt = cipher_file[:16]
    iv = cipher_file[16:32]
    cipher_text = cipher_file[32:]

    key = password_to_w(salt, password, w2_iteration, w2_length)
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    text = decryptor.update(cipher_text) + decryptor.finalize()
    private_key = deserialize_private_key(text)
    return private_key


def add_entry(username, password, private_file, database):
    salt1, salt2 = os.urandom(16), os.urandom(16)
    w1 = salt1 + password_to_w(salt1, password, w1_iteration, w1_length)
    y = encrypt_private_key(private_file, password, salt2)
    with open(database, 'a') as datafile:
        datafile.write(username + '\t' + base64.b64encode(w1) + '\t' + base64.b64encode(y) + '\n')


def add_batch(clear_password, database):
    with open(clear_password, 'r') as pwdfile:
        for line in pwdfile:
            parts = line.split(":")
            add_entry(parts[0], parts[1].strip(), parts[0] + '_private.der', database)


def test_read_entry(clear_password, database):
    pwd_map = {}
    with open(clear_password, 'r') as pwdfile:
        for line in pwdfile:
            parts = line.split(":")
            pwd_map[parts[0]] = parts[1].strip()

    with open(database, 'rb') as datafile:
        for line in datafile:
            parts = line.split('\t')
            print parts[0]
            w1 = base64.b64decode(parts[1])
            y = base64.b64decode(parts[2])
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=w1_length,
                salt=w1[:16],
                iterations=w1_iteration,
                backend=default_backend()
            )
            kdf.verify(pwd_map[parts[0]], w1[16:])


def test_encrypt_private_key():
    salt = os.urandom(16)
    password = 'asd123'
    private_key = decrypt_private_key(encrypt_private_key('Alice_private.der', password, salt), password)
    public_key = load_public('Alice_public.der')
    message = b"encrypted data"
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )
    return plaintext == message
