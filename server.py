#!/usr/bin/env python

import socket
import select
import threading
import os
import base64
import logging
import utils
import time
from utils import b64encode_aes_cgm_encrypt
from cryptography.exceptions import InvalidTag
from instant_messenger_pb2 import *  # import the module created by protobuf for creating messages
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


IP_ADDR = '127.0.0.1'  # use loopback interface
TCP_PORT = 50550  # TCP port of server
BUFFER_SIZE = 1024
TIME_TOLERANCE = 15

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger('Server')


class Server:
    def __init__(self, database):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((IP_ADDR, TCP_PORT))  # bind to port
        self.sock.listen(1)  # listen with one pending connection

        # each connection maps to a hashmap, which keySet are {expect, dh_shared_key, addr, challenge, name}
        self.client_conn = {}
        # maps name to his/her ip address: name -> (ip, port)
        self.online_client = {}
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
                self.client_credentials[name]['pub'] = utils.deserialize_public_key(base64.b64decode(parts[3]))
                self.client_credentials[name]['pri'] = base64.b64decode(parts[2])

    """""
    Handle new connection from listening socket, add the new socket to self.inputs list
    For each new connection, we are expecting hello msg from client(ClientToServer.INITIATOR)
    """""
    def __handle_new_client(self, conn, address):
        self.inputs.append(conn)
        self.client_conn[conn] = {'addr': address, 'expect': ClientToServer.INITIATOR}
        logger.debug('__handle_new_client')

    """""
    Hello msg from client, e.g. A->Server: "Alice"
    Server will respond with challenge = Hash(ip, secret) and a salt for user to compute PBKDF2 derived key
    """""
    def __handle_initiator(self, rqst, rply, conn):
        try:
            # server are expecting user's public key form next msg, all other kind of msg will be ignored or warned
            if rqst.name in self.online_client:
                # already online, shouldn't login again
                rply.type = ServerToClient.ERROR
                rply.info = "You already login!"
            elif rqst.name not in self.client_credentials:
                # no such user, username is incorrect
                rply.type = ServerToClient.ERROR
                rply.info = "User name and password don't match!"
            else:
                self.client_conn[conn]['expect'] = ClientToServer.USER_PUBKEY
                self.client_conn[conn]['name'] = rqst.name
                digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
                digest.update(self.client_conn[conn]['addr'][0].encode())
                digest.update(self.secret)
                rply.challenge = base64.b64encode(digest.finalize())
                rply.type = ServerToClient.DOS_SALT
                rply.salt = base64.b64encode(self.client_credentials[rqst.name]['w1_salt'])
        except Exception as e:
            rply.type = ServerToClient.ERROR
            rply.info = "Internal Error"
            logger.error('__handle_initiator: Unknown error ' + str(e))
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
            logger.error('__handle_user_dh_pubkey: Wrong hash, possible DoS: ' + self.client_conn[conn]['name'])
            # forget the connection
            self.inputs.remove(conn)
            self.client_conn.pop(conn, None)
            conn.close()
        else:
            try:
                # self.client_conn[conn]['client_pub'] = rqst.public_key
                # generate its own DH key
                server_dh_private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
                # client's public DH key and shared DH key
                client_dh_public = utils.deserialize_public_key(base64.b64decode(rqst.public_key))
                # using self.client_conn[conn]['dh_shared_key'] as shared key for further encrypting
                self.client_conn[conn]['dh_shared_key'] = utils.generate_dh_key(server_dh_private_key, client_dh_public)
                self.client_conn[conn]['challenge'] = os.urandom(16)

                name = self.client_conn[conn]['name']
                w1 = self.client_credentials[name]['w1']
                server_dh_public_serialized = server_dh_private_key\
                    .public_key()\
                    .public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

                rply.type = ServerToClient.SERVER_PUBKEY
                rply.public_key = b64encode_aes_cgm_encrypt(server_dh_public_serialized, w1)
                rply.challenge = base64.b64encode(self.client_conn[conn]['challenge'])
                rply.private_key = b64encode_aes_cgm_encrypt(self.client_credentials[name]['pri'],
                                                             self.client_conn[conn]['dh_shared_key'])
                conn.send(rply.SerializeToString())
                logger.debug('__handle_user_dh_pubkey: Successful send dh_pub key: ' + self.client_conn[conn]['name'])
            except Exception as e:
                logger.error("__handle_user_dh_pubkey: Fail to finish authentication" + str(e))
                rply.type = ServerToClient.ERROR
                rply.info = "Fail to finish authentication"
                conn.send(rply.SerializeToString())

    """""
    Client are sending last msg:Hash{g^ab mod p, c}sign.
    Server will verify the signature
    """""
    def __handle_user_signedhash(self, rqst, rply, conn):
        try:
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
            self.online_client[name] = (rqst.ip, rqst.port)
            logger.debug('Client listen address: ' + str(self.online_client[name]))
            logger.debug('__handle_user_signedhash: Successful verified signature: ' + self.client_conn[conn]['name'])
        except Exception as e:
            logger.error('__handle_user_signedhash: Fail verify signature, closing client scoket ' + str(e))
            rply.type = ServerToClient.ERROR
            rply.info = "Fail to verify signature"
            conn.send(rply.SerializeToString())

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
                elif rqst.type == ClientToServer.USER_SIGN:  # if it is signature of hash{g^ab mod p, c}
                    self.__handle_user_signedhash(rqst, rply, conn)
        else:
            try:
                # Otherwise it is a user command
                content = utils.b64decode_aes_cgm_decrypt(data, self.client_conn[conn]['dh_shared_key'])
                rqst.ParseFromString(content)
                if abs(rqst.time - time.time()) > TIME_TOLERANCE:
                    logger.warn('__handle_current_client: Message is outdated')
                    return  # simply ignore outdated message
                if rqst.type == ClientToServer.QUERY_PEER:  # query for public key and address
                    self.__handle_query_peer(rqst, rply, conn)
                elif rqst.type == ClientToServer.LIST:   # list command
                    self.__handle_list(rqst, rply, conn)
                elif rqst.type == ClientToServer.LOGOUT:  # logout command
                    self.__handle_logout(rply, conn)
            except InvalidTag:
                rply.type = ServerToClient.ERROR
                rply.info = "Invalid credential from client"
                conn.send(b64encode_aes_cgm_encrypt(rply.SerializeToString(),
                                                    self.client_conn[conn]['dh_shared_key']))
            except Exception as e:
                logger.error('Unknown error ' + str(e))
                rply.type = ServerToClient.ERROR
                rply.info = "Internal Error"
                conn.send(b64encode_aes_cgm_encrypt(rply.SerializeToString(),
                                                    self.client_conn[conn]['dh_shared_key']))

    """""
    Hanlde querying peer. Reply with peer's public key and address
    """""
    def __handle_query_peer(self, rqst, rply, conn):
        name = rqst.name
        rply.time = int(time.time())
        logger.debug('querying: ' + name)
        if name in self.online_client and name in self.client_credentials:
            rply.name = name
            rply.ip = self.online_client[name][0]
            rply.port = self.online_client[name][1]
            public_key_bytes = self.client_credentials[name]['pub'].public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo)

            rply.public_key = base64.b64encode(public_key_bytes)
            rply.type = ServerToClient.REPLY_QUERY
            logger.debug('__handle_query_peer: Send pubkey of ' + name)
        elif name not in self.client_credentials:
            rply.type = ServerToClient.ERROR
            rply.info = "No such user"
        else:
            rply.type = ServerToClient.ERROR
            rply.info = "User not online"
        conn.send(utils.b64encode_aes_cgm_encrypt(rply.SerializeToString(), self.client_conn[conn]['dh_shared_key']))

    """""
    Handle list command. Reply with all login users
    """""
    def __handle_list(self, rqst, rply, conn):
        logger.debug('list rqst')
        rply.type = ServerToClient.REPLY_LIST
        rply.name = self.client_conn[conn]['name']
        rply.time = int(time.time())
        for key in self.online_client:
            rply.name_list.append(key)
        conn.send(b64encode_aes_cgm_encrypt(rply.SerializeToString(), self.client_conn[conn]['dh_shared_key']))

    """""
    Handle logout msg
    """""
    def __handle_logout(self, rply, conn):
        self.online_client.pop(self.client_conn[conn]['name'])  # so that subsequent 'list' will not show this user
        rply.type = ServerToClient.LOGOUT
        rply.time = int(time.time())
        conn.send(b64encode_aes_cgm_encrypt(rply.SerializeToString(), self.client_conn[conn]['dh_shared_key']))

    def run(self):
        while 1:
            readable, _, _ = select.select(self.inputs, [], [], 2)
            for s in readable:
                if s is self.sock:  # new client connects to server
                    conn, address = self.sock.accept()  # accept connection from client
                    logger.debug('run: Connection address:' + str(address))
                    #  start new thread to handle this connection
                    input_handler = threading.Thread(target=self.__handle_new_client, args=(conn, address))
                    input_handler.start()
                else:
                    logger.debug('run: Receive new data....')
                    data = s.recv(BUFFER_SIZE)
                    if len(data) == 0:
                        # if receive empty data, it means client are closing socket
                        if 'name' not in self.client_conn[s]:
                            # This client hasn't finished authentication, but want closing socket
                            # Log this suspicious activity for security concern
                            logger.error('run: Client wants to exist without finishing authentication')
                        elif self.client_conn[s]['name'] in self.online_client:
                            # This should not happen, since client should send logout nsg first before close the socket
                            # Log this suspicious activity for security concern
                            logger.error('run: Unexpected logout, might be attack!')
                        else:
                            # Client already send logout msg, safely close and delete socket
                            logger.debug('run: Closing client socket...')
                        self.online_client.pop(self.client_conn[s].get('name', None), None)
                        self.inputs.remove(s)
                        self.client_conn.pop(s, None)
                        s.close()
                    else:
                        logger.debug('run: Processing current client rqst')
                        #  start new thread to handle this connection
                        input_handler = threading.Thread(target=self.__handle_current_client, args=(s, data))
                        input_handler.start()

if __name__ == '__main__':
    server = Server('database')
    server.run()
