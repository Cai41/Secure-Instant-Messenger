#!/usr/bin/env python

# A very basic program demonstrating protobuf with sockets
# Note that it does not catch any exceptions and of course
# it is very insecure as executes remote commands :)
#
# This is the client side

import select
import socket
from instant_messenger_pb2 import *
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.backends import default_backend
import utils
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
import base64
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import random
import threading
import os


IP_ADDR = '127.0.0.1'  # use loopback interface
TCP_PORT = 5055			# TCP port of server
BUFFER_SIZE = 10240


class Client:
    def __init__(self, name, password):
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.connect((IP_ADDR, TCP_PORT))  # connect to server

        self.listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listen_port = random.randrange(50000, 65535)
        self.listen_sock.bind((IP_ADDR, self.listen_port))
        self.listen_sock.listen(1)

        self.peer_info = {}
        self.conn_info = {}
        self.client_socks = [self.listen_sock]

        rqst = ClientToServer()
        rqst.type = ClientToServer.INITIATOR
        rqst.name = name
        self.server_sock.send(rqst.SerializeToString())
        self.dh_private = None
        self.dh_shared = None
        self.w1_salt = None
        self.w1 = None
        self.w2_salt = None
        self.w2 = None
        self.private_key = None
        self.name = name
        self.password = password

    def __initiate_auth(self, name):
        client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_sock.connect((self.peer_info[name]['ip'], int(self.peer_info[name]['port'])))

        self.client_socks.append(client_sock)
        self.peer_info[name]['conn'] = client_sock
        self.conn_info[client_sock] = {'expect': ClientToClient.RECVER_PUB,
                                       'sender_dh_private': ec.generate_private_key(ec.SECP384R1(), default_backend()),
                                       'name': name}
        self.__send_dh_pub(self.conn_info[client_sock]['sender_dh_private'], ClientToClient.SENDER_PUB, client_sock)
        print 'send peer auth1'

    def __handle_server_sock(self):
        while 1:
            cipher_data = base64.b64decode(self.server_sock.recv(BUFFER_SIZE))
            data = utils.aes_ctr_decrypt(cipher_data[16:], self.dh_shared, cipher_data[:16])
            rply = ServerToClient()
            rply.ParseFromString(data)
            if rply.type == self.peer_info[rply.name]['expect']:
                print rply.ip, rply.port
                self.peer_info[rply.name]['pub'] = utils.deserialize_public_key(base64.b64decode(rply.public_key))
                if 'conn' not in self.peer_info[rply.name]:
                    self.peer_info[rply.name]['expect'] = None
                    self.peer_info[rply.name]['ip'] = rply.ip
                    self.peer_info[rply.name]['port'] = rply.port
                    print 'receive pub key as sender to', rply.name
                    self.__initiate_auth(rply.name)
                else:
                    conn = self.peer_info[rply.name]['conn']
                    self.peer_info[rply.name]['pub'].verify(
                        base64.b64decode(self.conn_info[conn]['sign']),
                        self.conn_info[conn]['sender_dh_pub_bytes'],
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256()
                    )
                    self.__send_identity(self.conn_info[conn]['rcver_dh_private'],
                                         ClientToClient.RECVER_IDENTITY, conn)
                    print 'receive pub key as receiver to', rply.name
                    print 'and send identity'

    def __handle_peer_sock(self):
        while 1:
            readable, _, _ = select.select(self.client_socks, [], [], 2)
            for s in readable:
                if s is self.listen_sock:
                    conn, address = self.listen_sock.accept()  # accept connection from client
                    print 'Connection address:', address
                    self.client_socks.append(conn)
                    self.conn_info[conn] = {}
                else:
                    rqst = ClientToClient()
                    data = s.recv(BUFFER_SIZE)
                    if 'shared_dh' not in self.conn_info[s]:
                        rqst.ParseFromString(data)
                        if rqst.type == ClientToClient.SENDER_PUB:
                            sender_dh_pub_key_bytes = base64.b64decode(rqst.public_key)
                            sender_dh_pub_key = utils.deserialize_public_key(sender_dh_pub_key_bytes)
                            rcver_dh_private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
                            shared_key = rcver_dh_private_key.exchange(ec.ECDH(), sender_dh_pub_key)
                            digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
                            digest.update(shared_key)
                            dh_shared = digest.finalize()

                            self.conn_info[s] = {'shared_dh': dh_shared, 'expect': ClientToClient.SENDER_IDENTITY,
                                                 'rcver_dh_private': rcver_dh_private_key,
                                                 'sender_dh_pub_bytes': sender_dh_pub_key_bytes}

                            self.__send_dh_pub(rcver_dh_private_key, ClientToClient.RECVER_PUB, s)
                            print 'send dh pub as receiver'
                        elif rqst.type == ClientToClient.RECVER_PUB:
                            rcver_dh_pub_bytes = base64.b64decode(rqst.public_key)
                            recver_pub = utils.deserialize_public_key(rcver_dh_pub_bytes)
                            shared_key = self.conn_info[s]['sender_dh_private'].exchange(ec.ECDH(), recver_pub)
                            digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
                            digest.update(shared_key)
                            self.conn_info[s]['shared_dh'] = digest.finalize()
                            self.conn_info[s]['expect'] = ClientToClient.RECVER_IDENTITY
                            self.conn_info[s]['rcver_dh_pub_bytes'] = rcver_dh_pub_bytes

                            self.__send_identity(self.conn_info[s]['sender_dh_private'],
                                                 ClientToClient.SENDER_IDENTITY, s)
                            print 'send identity as sender to ', self.conn_info[s]['name']
                        else:
                            print 'drop...', rqst.type
                    else:
                        iv, cipher_content = data[:16], data[16:]
                        content = utils.aes_ctr_decrypt(cipher_content, self.conn_info[s]['shared_dh'], iv)
                        rqst.ParseFromString(content)
                        if rqst.type == ClientToClient.SENDER_IDENTITY:
                            self.conn_info[s]['name'] = rqst.name
                            if rqst.name not in self.peer_info:
                                self.conn_info[s]['sign'] = rqst.sign
                                self.peer_info[rqst.name] = {'expect': ServerToClient.REPLY_QUERY, 'conn': s}
                                rqst1 = ClientToServer()
                                rqst1.type = ClientToServer.QUERY_PEER
                                rqst1.name = rqst.name
                                iv = os.urandom(16)
                                cipher_query = utils.aes_ctr_encrypt(rqst1.SerializeToString(), self.dh_shared, iv)
                                self.server_sock.send(base64.b64encode(iv + cipher_query))
                                print 'query server as receiver for peer', rqst1.name
                            else:
                                self.peer_info[rqst.name]['pub'].verify(
                                    base64.b64decode(rqst.sign),
                                    self.conn_info[s]['sender_dh_pub_bytes'],
                                    padding.PSS(
                                        mgf=padding.MGF1(hashes.SHA256()),
                                        salt_length=padding.PSS.MAX_LENGTH
                                    ),
                                    hashes.SHA256()
                                )
                                self.__send_identity(self.conn_info[s]['rcver_dh_private'],
                                                     ClientToClient.RECVER_IDENTITY, s)
                                print 'send identity as sender'
                        elif rqst.type == ClientToClient.RECVER_IDENTITY:
                            self.peer_info[rqst.name]['pub'].verify(
                                base64.b64decode(rqst.sign),
                                self.conn_info[s]['rcver_dh_pub_bytes'],
                                padding.PSS(
                                    mgf=padding.MGF1(hashes.SHA256()),
                                    salt_length=padding.PSS.MAX_LENGTH
                                ),
                                hashes.SHA256()
                            )
                            print 'verify receiver identity'
                            chat_msg = ClientToClient()
                            chat_msg.type = ClientToClient.MESSAGE
                            chat_msg.msg = self.peer_info[rqst.name]['msg']
                            iv1 = os.urandom(16)
                            cipher_msg = utils.aes_ctr_encrypt(chat_msg.SerializeToString(),
                                                               self.conn_info[s]['shared_dh'], iv1)
                            s.send(iv1 + cipher_msg)
                        elif rqst.type == ClientToClient.MESSAGE:
                            print self.conn_info[s]['name'] + ": " + rqst.msg
                        else:
                            print 'drop....'

    def __send_dh_pub(self, dh_private_key, rply_type, s):
        rply = ClientToClient()
        rply.type = rply_type
        rply.public_key = base64.b64encode(dh_private_key
                                           .public_key()
                                           .public_bytes(Encoding.DER,
                                                         PublicFormat.SubjectPublicKeyInfo))
        s.send(rply.SerializeToString())

    def __send_identity(self, dh_private, rply_type, s):
        dh_public_key_bytes = dh_private.public_key() \
            .public_bytes(Encoding.DER,
                          PublicFormat.SubjectPublicKeyInfo)
        sign = self.private_key.sign(
            dh_public_key_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        rply = ClientToClient()
        rply.type = rply_type
        rply.sign = base64.b64encode(sign)
        rply.name = self.name
        # rply.public_key = base64.b64encode(sender_dh_public_key_bytes)

        iv = os.urandom(16)
        cipher_content = utils.aes_ctr_encrypt(rply.SerializeToString(),
                                               self.conn_info[s]['shared_dh'], iv)
        s.send(iv + cipher_content)

    def __handle_dos_salt(self, rqst, rply):
        self.w1_salt = base64.b64decode(rply.salt)
        self.w1 = utils.password_to_w(self.w1_salt, self.password, utils.w1_iteration, utils.w1_length)

        rqst.type = ClientToServer.USER_PUBKEY
        rqst.challenge = rply.challenge
        self.dh_private = ec.generate_private_key(ec.SECP384R1(), default_backend())
        rqst.public_key = base64.b64encode(self.dh_private.public_key()
                                           .public_bytes(Encoding.DER,
                                                         PublicFormat.SubjectPublicKeyInfo))
        self.server_sock.send(rqst.SerializeToString())
        print 'processed DOS_SALT rqst'

    def __handle_server_dhpub(self, rqst, rply):
        decoded_pub = base64.b64decode(rply.public_key)
        iv1, cipher_dh_public = decoded_pub[:16], decoded_pub[16:]
        cipher = Cipher(algorithms.AES(self.w1),
                        modes.CTR(iv1),
                        backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_key = decryptor.update(cipher_dh_public) + decryptor.finalize()
        server_dh_public = utils.deserialize_public_key(decrypted_key)
        shared_key = self.dh_private.exchange(ec.ECDH(), server_dh_public)
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(shared_key)
        self.dh_shared = digest.finalize()

        decoded_private = base64.b64decode(rply.private_key)
        iv1, cipher_y = decoded_private[:16], decoded_private[16:]
        cipher = Cipher(algorithms.AES(self.dh_shared),
                        modes.CTR(iv1),
                        backend=default_backend())
        decryptor = cipher.decryptor()
        y = decryptor.update(cipher_y) + decryptor.finalize()

        self.w2_salt, iv2, cipher_private = y[:16], y[16:32], y[32:]
        self.w2 = utils.password_to_w(self.w2_salt, self.password, utils.w2_iteration, utils.w2_length)
        cipher = Cipher(algorithms.AES(self.w2),
                        modes.CTR(iv2),
                        backend=default_backend())
        decryptor = cipher.decryptor()
        private_content = decryptor.update(cipher_private) + decryptor.finalize()

        self.private_key = utils.deserialize_private_key(private_content)
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(self.dh_shared)
        digest.update(base64.b64decode(rply.challenge))

        rqst.type = ClientToServer.USER_SIGN
        hash_value = digest.finalize()
        # rqst.hash = base64.b64encode(hash_value)
        sign = self.private_key.sign(
            hash_value,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        rqst.sign = base64.b64encode(sign)
        rqst.ip = IP_ADDR
        rqst.port = str(self.listen_port)
        self.server_sock.send(rqst.SerializeToString())
        print 'processed SERVER_PUBKEY rqst'

    def run(self):
        while 1:
            data = self.server_sock.recv(BUFFER_SIZE)
            rply = ServerToClient()
            rply.ParseFromString(data)
            rqst = ClientToServer()
            if rply.type == ServerToClient.DOS_SALT:
                self.__handle_dos_salt(rqst, rply)
            elif rply.type == ServerToClient.SERVER_PUBKEY:
                self.__handle_server_dhpub(rqst, rply)
                break
            else:
                print 'unsupported type: ' + rply.type
        # self.sock.close()
        server_handler = threading.Thread(target=self.__handle_server_sock)
        server_handler.start()
        peer_handler = threading.Thread(target=self.__handle_peer_sock)
        peer_handler.start()

        user_cmd = raw_input('+>')
        parts = user_cmd.split()
        cmd = parts[0]
        name = parts[1]
        msg = parts[2]

        if name not in self.peer_info:
            self.peer_info[name] = {'expect': ServerToClient.REPLY_QUERY, 'msg': msg}
            rqst = ClientToServer()
            rqst.type = ClientToServer.QUERY_PEER
            rqst.name = name
            iv = os.urandom(16)
            cipher_query = utils.aes_ctr_encrypt(rqst.SerializeToString(), self.dh_shared, iv)
            self.server_sock.send(base64.b64encode(iv + cipher_query))
        elif 'ip' in self.peer_info[name] and 'pub' in self.peer_info[name]:
            self.peer_info[name]['msg'] = msg
            self.__initiate_auth(name)
        else:
            print 'retrieving peer info, waiting....'


if __name__ == '__main__':
    user_name = raw_input('user name: ')
    user_pwd = raw_input('password: ')
    client = Client(user_name, user_pwd)
    client.run()
