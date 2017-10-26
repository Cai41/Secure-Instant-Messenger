#!/usr/bin/env python

import socket
import select
import threading
import os
import utils
import base64
from utils import b64encode_aes_ctr
from instant_messenger_pb2 import *  # import the module created by protobuf for creating messages
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


IP_ADDR = '127.0.0.1'  # use loopback interface
TCP_PORT = 5055  # TCP port of server
BUFFER_SIZE = 1024


class Server:
    def __init__(self, database):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((IP_ADDR, TCP_PORT))  # bind to port
        self.sock.listen(1)  # listen with one pending connection

        self.client_conn = {}
        self.client_address = {}
        self.inputs = [self.sock]
        self.secret = os.urandom(16)

        self.client_credentials = {}
        with open(database, 'rb') as datafile:
            for line in datafile:
                parts = line.split('\t')
                name = parts[0]
                self.client_credentials[name] = {}
                w1 = base64.b64decode(parts[1])
                self.client_credentials[name]['w1_salt'] = w1[:16]
                self.client_credentials[name]['w1'] = w1[16:]
                self.client_credentials[name]['pub'] = utils.load_public(name + '_public.der')
                self.client_credentials[name]['pri'] = base64.b64decode(parts[2])

    def __handle_new_client(self, conn, address):
        self.inputs.append(conn)
        self.client_conn[conn] = {'addr': address, 'expect': ClientToServer.INITIATOR}

    def __handle_initiator(self, rqst, rply, conn):
        self.client_conn[conn]['expect'] = ClientToServer.USER_PUBKEY
        self.client_conn[conn]['name'] = rqst.name
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(self.client_conn[conn]['addr'][0].encode())
        digest.update(self.secret)
        rply.type = ServerToClient.DOS_SALT
        rply.challenge = base64.b64encode(digest.finalize())
        rply.salt = base64.b64encode(self.client_credentials[rqst.name]['w1_salt'])
        conn.send(rply.SerializeToString())
        print '__handle_initiator: ', rqst.name

    def __handle_user_dh_pubkey(self, rqst, rply, conn):
        self.client_conn[conn]['expect'] = ClientToServer.USER_SIGN
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(self.client_conn[conn]['addr'][0].encode())
        digest.update(self.secret)
        msg_digest = base64.b64encode(digest.finalize())
        if msg_digest != rqst.challenge:
            print '__handle_user_dh_pubkey, wrong hash, possible DoS: ', self.client_conn[conn]['name']
            # forget the connection
            self.client_conn.pop(conn, None)
        else:
            # self.client_conn[conn]['client_pub'] = rqst.public_key
            server_dh_private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
            self.client_conn[conn]['server_pri'] = server_dh_private_key
            client_dh_public = utils.deserialize_public_key(base64.b64decode(rqst.public_key))
            shared_key = server_dh_private_key.exchange(ec.ECDH(), client_dh_public)
            digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
            digest.update(shared_key)
            self.client_conn[conn]['dh_shared_key'] = digest.finalize()
            self.client_conn[conn]['challenge'] = os.urandom(16)

            name = self.client_conn[conn]['name']
            w1 = self.client_credentials[name]['w1']
            server_dh_public_serialized = server_dh_private_key\
                .public_key()\
                .public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

            rply.type = ServerToClient.SERVER_PUBKEY
            rply.public_key = b64encode_aes_ctr(server_dh_public_serialized, w1)
            rply.challenge = base64.b64encode(self.client_conn[conn]['challenge'])
            rply.private_key = b64encode_aes_ctr(self.client_credentials[name]['pri'],
                                                 self.client_conn[conn]['dh_shared_key'])
            conn.send(rply.SerializeToString())
            print '__handle_user_dh_pubkey, successful send dh public key: ', self.client_conn[conn]['name']

    def __handle_user_signedhash(self, rqst, conn):
        self.client_conn[conn]['expect'] = None
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(self.client_conn[conn]['dh_shared_key'])
        digest.update(self.client_conn[conn]['challenge'])
        msg_digest = digest.finalize()
        name = self.client_conn[conn]['name']
        self.client_credentials[name]['pub'].verify(
            base64.b64decode(rqst.sign),
            msg_digest,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        self.client_address[name] = (rqst.ip, rqst.port)
        print 'client listen address: ', self.client_address[name]
        print '__handle_user_signedhash, successful verified signature: ', self.client_conn[conn]['name']

    def __handle_current_client(self, conn, data):
        rqst = ClientToServer()
        rply = ServerToClient()
        expect_type = self.client_conn[conn]['expect']
        # if it is a authentication protocol msg
        if expect_type is not None:
            rqst.ParseFromString(data)
            if expect_type == rqst.type:
                if rqst.type == ClientToServer.INITIATOR:
                    self.__handle_initiator(rqst, rply, conn)
                elif rqst.type == ClientToServer.USER_PUBKEY:
                    self.__handle_user_dh_pubkey(rqst, rply, conn)
                elif rqst.type == ClientToServer.USER_SIGN:
                    self.__handle_user_signedhash(rqst, conn)
        else:
            cipher_content = base64.b64decode(data)
            iv, cipher_query = cipher_content[:16], cipher_content[16:]
            content = utils.aes_ctr_decrypt(cipher_query, self.client_conn[conn]['dh_shared_key'], iv)
            rqst.ParseFromString(content)
            if rqst.type == ClientToServer.QUERY_PEER:
                self.__handle_query_peer(rqst, rply, conn)
            elif rqst.type == ClientToServer.LIST:
                self.__handle_list(rqst, rply, conn)
            elif rqst.type == ClientToServer.LOGOUT:
                self.__handle_logout(rqst, rply, conn)

    def __handle_query_peer(self, rqst, rply, conn):
        name = rqst.name
        print 'querying: ', name
        if name in self.client_address and name in self.client_credentials:
            rply.name = name
            rply.ip = self.client_address[name][0]
            rply.port = self.client_address[name][1]
            public_key_bytes = self.client_credentials[name]['pub'].public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo)

            rply.public_key = base64.b64encode(public_key_bytes)
            rply.type = ServerToClient.REPLY_QUERY
            conn.send(b64encode_aes_ctr(rply.SerializeToString(), self.client_conn[conn]['dh_shared_key']))
            print 'send pubkey of', name

    def __handle_list(self, rqst, rply, conn):
        print 'list rqst'
        rply.type = ServerToClient.REPLY_LIST
        rply.name = self.client_conn[conn]['name']
        for key in self.client_address:
            rply.name_list.append(key)
        conn.send(b64encode_aes_ctr(rply.SerializeToString(), self.client_conn[conn]['dh_shared_key']))

    def __handle_logout(self, rqst, rply, conn):
        self.client_address.pop(self.client_conn[conn]['name'])  # so that subsequent 'list' will not show this user
        rply.type = ServerToClient.LOGOUT
        conn.send(b64encode_aes_ctr(rply.SerializeToString(), self.client_conn[conn]['dh_shared_key']))

    def run(self):
        while 1:
            readable, _, _ = select.select(self.inputs, [], [])
            for s in readable:
                if s is self.sock:
                    conn, address = self.sock.accept()  # accept connection from client
                    print 'Connection address:', address
                    input_handler = threading.Thread(target=self.__handle_new_client, args=(conn, address))
                    input_handler.start()
                else:
                    print 'receive new data....'
                    data = s.recv(BUFFER_SIZE)
                    if len(data) == 0:
                        if self.client_conn[s]['name'] in self.client_address:
                            print 'This should not happen, might be attack!'
                        else:
                            self.client_conn.pop(s)
                            self.inputs.remove(s)
                            s.close()
                            print 'closing socket...'
                    else:
                        print 'processing current client rqst'
                        input_handler = threading.Thread(target=self.__handle_current_client, args=(s, data))
                        input_handler.start()

if __name__ == '__main__':
    server = Server('database')
    server.run()
