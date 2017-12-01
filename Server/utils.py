import os
import base64
import json
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.asymmetric import rsa


# The .pem key file will always start with this prefix string
PEM_START = '-----BEGIN'
w1_length = 16
w1_iteration = 4096
w2_length = 16
w2_iteration = 2048


# generate dh key
def generate_dh_key(private_key, public_key):
    shared_key = private_key.exchange(ec.ECDH(), public_key)
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(shared_key)
    return digest.finalize()


# convert password to crypto key
def password_to_w(salt, password, iteration, key_size):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_size,
        salt=salt,
        iterations=iteration,
        backend=default_backend()
    )
    return kdf.derive(password)


# Serialize public key
def serialize_public_key(public_key):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem


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


# encrypt the private key using AES_CGM
def encrypt_private_key(private_key, password, salt):
        key = password_to_w(salt, password, w2_iteration, w2_length)
        # Only serialized key can be encrypted
        pem = private_key.private_bytes(
            encoding = serialization.Encoding.PEM,
            format = serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm = serialization.NoEncryption()
        )
        return salt + aes_cgm_random_iv(pem, key)


# encrypt with AES_CTR, and base64 encode
def b64encode_aes_ctr(content, key):
    return base64.b64encode(aes_ctr_random_iv(content, key))


# encrypt with AES_CTR with random iv
def aes_ctr_random_iv(content, key):
    iv = os.urandom(16)
    return iv + aes_ctr_encrypt(content, key, iv)


# encrypt with AES_CTR with given iv
def aes_ctr_encrypt(content, key, iv):
    cipher = Cipher(algorithms.AES(key),
                    modes.CTR(iv),
                    backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(content) + encryptor.finalize()


# decrypt with AES_CGM with given iv
def aes_ctr_decrypt(cipher_content, key, iv):
    cipher = Cipher(algorithms.AES(key),
                    modes.CTR(iv),
                    backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(cipher_content) + decryptor.finalize()


# use AES_CGM to encrypt, given iv
def aes_cgm_encrypt(content, key, iv):
    cipher = Cipher(algorithms.AES(key),
                    modes.GCM(iv),
                    backend=default_backend())
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(content) + encryptor.finalize()
    tag = encryptor.tag
    return tag + cipher_text


# use AES_CGM to encrypt, randomized iv
def aes_cgm_random_iv(content, key):
    iv = os.urandom(16)
    return iv + aes_cgm_encrypt(content, key, iv)


# use AES_CGM to encrypt, randomized iv, and encode the result by base64
def b64encode_aes_cgm_encrypt(content, key):
    return base64.b64encode(aes_cgm_random_iv(content, key))


# use AES_GCM to decrypt, given iv
def aes_cgm_decrypt(cipher_text, key, iv, tag):
    decryptor = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend()).decryptor()
    return decryptor.update(cipher_text) + decryptor.finalize()


# use base64 to decode, then use AES_GCM to decrypt
def b64decode_aes_cgm_decrypt(content, key):
    decoded_data = base64.b64decode(content)
    iv, tag, data = decoded_data[:16], decoded_data[16:32], decoded_data[32:]
    return aes_cgm_decrypt(data, key, iv, tag)


def generateRSAkeys():
    private_key = rsa.generate_private_key(
        public_exponent = 65537,
        key_size = 2048,
        backend = default_backend()
        )
    public_key = private_key.public_key()
    return [public_key,private_key]


# add one user entry to the database
def add_entry(username, password, database):
    public_key,private_key=generateRSAkeys()
    salt1, salt2 = os.urandom(16), os.urandom(16)
    w1 = salt1 + password_to_w(salt1, password, w1_iteration, w1_length)
    y = encrypt_private_key(private_key, password, salt2)
    public_key=serialize_public_key(public_key)
    with open(database, 'a') as datafile:
        datafile.write(username + '\t' + base64.b64encode(w1) + '\t' + base64.b64encode(y) + '\t'+base64.b64encode(public_key)+'\n')


# Registering user and saving data
def add_batch(clear_password, database):
    with open(clear_password, 'r') as pwdfile:
        for line in pwdfile:
            parts = line.split(":")
            add_entry(parts[0], parts[1].strip(), database)


# load meta information from json file
def load_client_metadata(filename):
    data = json.load(open(filename))
    SERVER_IP_ADDR = data['SERVER_IP_ADDR']
    SERVER_TCP_PORT = data['SERVER_TCP_PORT']
    Client_IP_ADDR = data['Client_IP_ADDR']
    BUFFER_SIZE = data['BUFFER_SIZE']
    TIME_TOLERANCE = data['TIME_TOLERANCE']
    return [SERVER_IP_ADDR, SERVER_TCP_PORT, Client_IP_ADDR, BUFFER_SIZE, TIME_TOLERANCE]


# load meta information from json file
def load_server_metadata(filename):
    data = json.load(open(filename))
    SERVER_IP_ADDR = data['SERVER_IP_ADDR']
    SERVER_TCP_PORT = data['SERVER_TCP_PORT']
    BUFFER_SIZE = data['BUFFER_SIZE']
    TIME_TOLERANCE = data['TIME_TOLERANCE']
    return [SERVER_IP_ADDR, SERVER_TCP_PORT, BUFFER_SIZE, TIME_TOLERANCE]

if __name__ == '__main__':
    add_batch('clear_password', 'database')
