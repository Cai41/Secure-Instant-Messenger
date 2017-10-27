#!/usr/bin/env python

import socket
import select
import threading
import os
import base64
import logging
import utils
from instant_messenger_pb2 import *  # import the module created by protobuf for creating messages
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


IP_ADDR = '127.0.0.1'  # use loopback interface
TCP_PORT = 5055  # TCP port of server
BUFFER_SIZE = 1024

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


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

    """""
    Handle new connection from listening socket, add the new socket to self.inputs list
    For each new connection, we are expecting hello msg from client(ClientToServer.INITIATOR)
    """""
    def __handle_new_client(self, conn, address):
        self.inputs.append(conn)
        self.client_conn[conn] = {'addr': address, 'expect': ClientToServer.INITIATOR}

    """""
    Hello msg from client, e.g. A->Server: "Alice"
    Server will respond with challenge = Hash(ip, secret) and a salt for user to compute PBKDF2 derived key
    """""
    def __handle_initiator(self, rqst, rply, conn):
        # server are expecting user's public key form next msg, all other kind of msg will be ignored or warned
        self.client_conn[conn]['expect'] = ClientToServer.USER_PUBKEY
        self.client_conn[conn]['name'] = rqst.name
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(self.client_conn[conn]['addr'][0].encode())
        digest.update(self.secret)
        rply.type = ServerToClient.DOS_SALT
        rply.challenge = base64.b64encode(digest.finalize())
        rply.salt = base64.b64encode(self.client_credentials[rqst.name]['w1_salt'])
        conn.send(rply.SerializeToString())
        logger.debug('__handle_initiator: ' + rqst.name)

    """""
    Client are sending public key and challenge to the server, e.g. A->Server: c, W{g^a mod p}
    Server will check whether it is DoS first. If it is, it simply forget the connection
    Otherwise, it will generate its DH key, send: W{g^b mod p}, (g^ab mod p){Y}, c back to client
    """""
    def __handle_user_dh_pubkey(self, rqst, rply, conn):
        # server are expecting user's public key form next msg, all other kind of msg will be ignored or warned
        self.client_conn[conn]['expect'] = ClientToServer.USER_SIGN
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(self.client_conn[conn]['addr'][0].encode())
        digest.update(self.secret)
        msg_digest = base64.b64encode(digest.finalize())
        if msg_digest != rqst.challenge:
            # log the DoS attack msg, and forget this connection
            logger.eror('__handle_user_dh_pubkey, wrong hash, possible DoS: ' + self.client_conn[conn]['name'])
            # forget the connection
            self.client_conn.pop(conn, None)
            self.inputs.remove(conn)
        else:
            # self.client_conn[conn]['client_pub'] = rqst.public_key
            # generate its own DH key
            server_dh_private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
            self.client_conn[conn]['server_pri'] = server_dh_private_key
            # client's public DH key and shared DH key
            client_dh_public = utils.deserialize_public_key(base64.b64decode(rqst.public_key))
            shared_key = server_dh_private_key.exchange(ec.ECDH(), client_dh_public)
            digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
            digest.update(shared_key)
            # using self.client_conn[conn]['dh_shared_key'] as shared key for further encrypting
            self.client_conn[conn]['dh_shared_key'] = digest.finalize()

            self.client_conn[conn]['challenge'] = os.urandom(16)

            name = self.client_conn[conn]['name']
            w1 = self.client_credentials[name]['w1']
            server_dh_public_serialized = server_dh_private_key\
                .public_key()\
                .public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
            utils.deserialize_public_key(server_dh_public_serialized)

            rply.type = ServerToClient.SERVER_PUBKEY
            rply.public_key = utils.b64encode_aes_cgm_encrypt(server_dh_public_serialized, w1)
            rply.challenge = base64.b64encode(self.client_conn[conn]['challenge'])
            rply.private_key = utils.b64encode_aes_cgm_encrypt(self.client_credentials[name]['pri'],
                                                               self.client_conn[conn]['dh_shared_key'])
            conn.send(rply.SerializeToString())
            logger.debug('__handle_user_dh_pubkey, successful send dh public key: ' + self.client_conn[conn]['name'])

    """""
    Client are sending last msg:Hash{g^ab mod p, c}sign.
    Server will verify the signature
    """""
    def __handle_user_signedhash(self, rqst, conn):
        self.client_conn[conn]['expect'] = None
        # compute the hash{g^ab mod p, c}
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(self.client_conn[conn]['dh_shared_key'])
        digest.update(self.client_conn[conn]['challenge'])
        msg_digest = digest.finalize()
        name = self.client_conn[conn]['name']
        # verify the signature
        self.client_credentials[name]['pub'].verify(
            base64.b64decode(rqst.sign),
            msg_digest,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        # record this address, so that other client may query this one's address and public key
        self.client_address[name] = (rqst.ip, rqst.port)
        logger.debug('client listen address: ' + str(self.client_address[name]))
        logger.debug('__handle_user_signedhash, successful verified signature: ' + self.client_conn[conn]['name'])

    """""
    Handle users that are already connected
    """""
    def __handle_current_client(self, conn, data):
        rqst = ClientToServer()
        rply = ServerToClient()
        expect_type = self.client_conn[conn]['expect']
        # if it is a authentication protocol msg
        if expect_type is not None:
            rqst.ParseFromString(data)
            if expect_type == rqst.type:
                if rqst.type == ClientToServer.INITIATOR:  # if it is hello msg: "Alice"
                    self.__handle_initiator(rqst, rply, conn)
                elif rqst.type == ClientToServer.USER_PUBKEY:    # if it is public DH key:W{g^a mod p}, c
                    self.__handle_user_dh_pubkey(rqst, rply, conn)
                elif rqst.type == ClientToServer.USER_SIGN: # if it is signature of hash{g^ab mod p, c}
                    self.__handle_user_signedhash(rqst, conn)
        else:
            # Otherwise it is a user command
            content = utils.b64decode_aes_cgm_decrypt(data, self.client_conn[conn]['dh_shared_key'])
            rqst.ParseFromString(content)
            if rqst.type == ClientToServer.QUERY_PEER:  # query for public key and address
                self.__handle_query_peer(rqst, rply, conn)
            elif rqst.type == ClientToServer.LIST:   # list command
                self.__handle_list(rqst, rply, conn)
            elif rqst.type == ClientToServer.LOGOUT:  # logout command
                self.__handle_logout(rqst, rply, conn)

    """""
    Hanlde querying peer. Reply with peer's public key and address
    """""
    def __handle_query_peer(self, rqst, rply, conn):
        name = rqst.name
        logger.debug('querying: ' + name)
        if name in self.client_address and name in self.client_credentials:
            rply.name = name
            rply.ip = self.client_address[name][0]
            rply.port = self.client_address[name][1]
            public_key_bytes = self.client_credentials[name]['pub'].public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo)

            rply.public_key = base64.b64encode(public_key_bytes)
            rply.type = ServerToClient.REPLY_QUERY
            conn.send(utils.b64encode_aes_cgm_encrypt(rply.SerializeToString(),
                                                      self.client_conn[conn]['dh_shared_key']))
            logger.debug('send pubkey of ' + name)

    """""
    Handle list command. Reply with all login users
    """""
    def __handle_list(self, rqst, rply, conn):
        logger.debug('list rqst')
        rply.type = ServerToClient.REPLY_LIST
        rply.name = self.client_conn[conn]['name']
        for key in self.client_address:
            rply.name_list.append(key)
        conn.send(utils.b64encode_aes_cgm_encrypt(rply.SerializeToString(),
                                                  self.client_conn[conn]['dh_shared_key']))

    """""
    Handle logout msg
    """""
    def __handle_logout(self, rqst, rply, conn):
        self.client_address.pop(self.client_conn[conn]['name'])  # so that subsequent 'list' will not show this user
        rply.type = ServerToClient.LOGOUT
        conn.send(utils.b64encode_aes_cgm_encrypt(rply.SerializeToString(),
                                                  self.client_conn[conn]['dh_shared_key']))

    def run(self):
        while 1:
            readable, _, _ = select.select(self.inputs, [], [])
            for s in readable:
                if s is self.sock:  # new client connects to server
                    conn, address = self.sock.accept()  # accept connection from client
                    logger.debug('Connection address:' + str(address))
                    #  start new thread to handle this connection
                    input_handler = threading.Thread(target=self.__handle_new_client, args=(conn, address))
                    input_handler.start()
                else:
                    logger.debug('receive new data....')
                    data = s.recv(BUFFER_SIZE)
                    if len(data) == 0:
                        # if receive empty data, it means client are closing socket
                        if self.client_conn[s]['name'] in self.client_address:
                            # This should not happen, since client should send logout nsg first before close the socket
                            logger.error('This should not happen, might be attack!')
                        else:
                            # Client already send logout msg, safely close and delete socket
                            self.client_conn.pop(s)
                            self.inputs.remove(s)
                            s.close()
                            logger.debug('closing client socket...')
                    else:
                        logger.debug('processing current client rqst')
                        #  start new thread to handle this connection
                        input_handler = threading.Thread(target=self.__handle_current_client, args=(s, data))
                        input_handler.start()

if __name__ == '__main__':
    server = Server('database')
    server.run()
