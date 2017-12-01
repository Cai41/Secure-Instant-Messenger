#!/usr/bin/env python

import select
import socket
import base64
import random
import threading
import utils
import re
import time
import logging
from utils import b64decode_aes_cgm_decrypt
from instant_messenger_pb2 import *   # import the module created by protobuf for creating messages
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

IP_ADDR, TCP_PORT, BUFFER_SIZE, TIME_TOLERANCE = utils.load_metadata('ServerInfo.json')

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger('Client')


class Client:
    def __init__(self, name, password):
        self.prog = re.compile('\s*(\S+)\s+(\S+)\s(.*)')
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listen_port = random.randrange(50000, 65535)
        self.listen_sock.bind((IP_ADDR, self.listen_port))
        self.listen_sock.listen(1)

        self.peer_info = {}
        self.conn_info = {}
        self.client_socks = [self.listen_sock]

        # Type of msg we are expecting from server.
        # e.g. if we haven't send 'list', then self.server_expect['list'] should be false
        # Then any list msg from server should be ignored, might replay attack or impersonate
        self.server_expect = {'List': False, 'Query': set(), 'Logout': False}

        self.dh_private = None
        self.dh_shared = None
        self.w1_salt = None
        self.w1 = None
        self.w2_salt = None
        self.w2 = None
        self.private_key = None
        self.name = name
        self.password = password
        self.login = False

    """""
    Initiate authentication protocol with another peer, send: g^a mod p
    """""
    def __initiate_auth(self, name):
        client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_sock.connect((self.peer_info[name]['ip'], int(self.peer_info[name]['port'])))

        self.client_socks.append(client_sock)
        self.peer_info[name]['conn'] = client_sock
        self.conn_info[client_sock] = {'expect': ClientToClient.RECVER_PUB,
                                       'sender_dh_private': ec.generate_private_key(ec.SECP384R1(), default_backend()),
                                       'name': name}
        self.__send_dh_pub(self.conn_info[client_sock]['sender_dh_private'], ClientToClient.SENDER_PUB, client_sock)
        logger.debug('__initiate_auth: Send dh pub as sender ' + self.name)

    """""
    Processing all packets from server side, this thread starts when authentication finishes
    """""
    def __handle_server_sock(self):
        while self.login:
            encrypted_data = self.server_sock.recv(BUFFER_SIZE)
            if len(encrypted_data) == 0:
                # len(encrypted_data) == 0 means server is closing socket, so client can terminate program now
                self.server_sock.close()
                self.login = False
                logger.error('__handle_server_sock: Server is shutting down')
                return
            data = b64decode_aes_cgm_decrypt(encrypted_data, self.dh_shared)
            rply = ServerToClient()
            rply.ParseFromString(data)
            if abs(rply.time - time.time()) > TIME_TOLERANCE:
                # ignore the messages that are outdated
                logger.warn('__handle_server_sock: Message is too outdated')
                continue
            # server is ready to logout the user, prepare to close the socket
            if rply.type == ServerToClient.LOGOUT and self.server_expect['Logout']:
                self.login = False
                self.server_sock.close()
                return
            # server replies with all login users
            if rply.type == ServerToClient.REPLY_LIST and self.server_expect['List']:
                self.server_expect['List'] = False
                online_users = []
                for online_user in rply.name_list:
                    online_users.append(online_user)
                print ', '.join(online_users)
            # server replies with query
            elif rply.type == ServerToClient.REPLY_QUERY and rply.name in self.server_expect['Query']:
                self.server_expect['Query'].remove(rply.name)
                # update meta data, in case of peer re-login or changing public key
                self.peer_info[rply.name]['pub'] = utils.deserialize_public_key(base64.b64decode(rply.public_key))
                self.peer_info[rply.name]['ip'] = rply.ip
                self.peer_info[rply.name]['port'] = rply.port

                # if we are the sender, then we haven't established connection with this peer
                if 'conn' not in self.peer_info[rply.name]:
                    logger.debug('__handle_server_sock: Receive pub key as sender to' + rply.name)
                    self.__initiate_auth(rply.name)
                else:
                    # if we are receiver, then we already establish the connection
                    # we are in the step 3 of authentication protocol. After retrieving peer's public key
                    # we can verify the signature, and sends back our own sign: g^ab mod p{"Bob", [g^b mod p]sign}
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
                    logger.debug('__handle_server_sock: Receive pub key as receiver to' + rply.name)
                    logger.debug('__handle_server_sock: and send identity')
            if rply.type == ServerToClient.ERROR:
                print 'Error information: from server: ' + rply.info

    """""
    The sender sends g^a mod p, we record this msg, compute shared key and reply with our own DH key
    """""
    def __handle_sender_pub(self, rqst, s):
        sender_dh_pub_key_bytes = base64.b64decode(rqst.public_key)
        sender_dh_pub_key = utils.deserialize_public_key(sender_dh_pub_key_bytes)
        # generate our own DH key
        rcver_dh_private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
        # compute shared key
        shared_key = utils.generate_dh_key(rcver_dh_private_key, sender_dh_pub_key)
        # cached sender_dh_pub_key_bytes
        # since we will have to verify signature of public key in the future protocol msg
        self.conn_info[s] = {'shared_dh': shared_key, 'expect': ClientToClient.SENDER_IDENTITY,
                             'rcver_dh_private': rcver_dh_private_key,
                             'sender_dh_pub_bytes': sender_dh_pub_key_bytes}
        # send DH public key back
        self.__send_dh_pub(rcver_dh_private_key, ClientToClient.RECVER_PUB, s)
        logger.debug('__handle_sender_pub: Send dh pub as receiver ' + self.name)

    """""
    The receiver sends back g^b mod p
    """""
    def __handle_recver_pub(self, rqst, s):
        rcver_dh_pub_bytes = base64.b64decode(rqst.public_key)
        recver_pub = utils.deserialize_public_key(rcver_dh_pub_bytes)
        # generate our own DH key
        self.conn_info[s]['shared_dh'] = utils.generate_dh_key(self.conn_info[s]['sender_dh_private'], recver_pub)
        self.conn_info[s]['expect'] = ClientToClient.RECVER_IDENTITY
        # cached sender_dh_pub_key_bytes
        # since we will have to verify signature of public key in the future protocol msg
        self.conn_info[s]['rcver_dh_pub_bytes'] = rcver_dh_pub_bytes
        # According to protocol, send back (g^ab mod p){"Alice", [g^a mod p]sign}
        self.__send_identity(self.conn_info[s]['sender_dh_private'],
                             ClientToClient.SENDER_IDENTITY, s)
        logger.debug('__handle_recver_pub: Send identity as sender to ' + self.conn_info[s]['name'])

    """""
    Receives sender's (g^ab mod p){"Alice", [g^a mod p]sign-A}
    Sends back (g^ab mod p){"Bob", [g^a mod p]sign-B} to prove himself
    """""
    def __handle_sender_identiy(self, rqst, s):
        self.conn_info[s]['name'] = rqst.name
        self.conn_info[s]['sign'] = rqst.sign
        # Do not use self.peer_info[rqst.name] = {'conn':s}
        # Since if client is sending to himself, it will override the self.peer_info[rqst.name]
        if rqst.name not in self.peer_info:
            self.peer_info[rqst.name] = {}
        # Record peer name and its corresponding connection. After we query server for the peer's public key
        # We will continue this protocol
        self.peer_info[rqst.name]['conn'] = s
        self.server_expect['Query'].add(rqst.name)
        rqst1 = ClientToServer()
        rqst1.type = ClientToServer.QUERY_PEER
        rqst1.name = rqst.name
        rqst1.time = int(time.time())
        self.server_sock.send(utils.b64encode_aes_cgm_encrypt(rqst1.SerializeToString(), self.dh_shared))
        logger.debug('__handle_sender_identiy: Query server as receiver for peer ' + rqst1.name)

    """""
    Receives receiver's (g^ab mod p){"Bob", [g^a mod p]sign-B}. After we verify it's
    valid signature, we can send our encrypted message
    """""
    def __handle_recver_identity(self, rqst, s):
        self.peer_info[rqst.name]['pub'].verify(
            base64.b64decode(rqst.sign),
            self.conn_info[s]['rcver_dh_pub_bytes'],
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        logger.debug('__handle_recver_identity: Verify receiver identity')
        chat_msg = ClientToClient()
        chat_msg.type = ClientToClient.MESSAGE
        chat_msg.msg = self.peer_info[rqst.name]['msg']
        chat_msg.time = int(time.time())
        s.send(utils.b64encode_aes_cgm_encrypt(chat_msg.SerializeToString(), self.conn_info[s]['shared_dh']))

    """""
    Handle msg received from peer
    """""
    def __handle_peer_sock(self):
        while self.login:
            readable, _, _ = select.select(self.client_socks, [], [], 2)
            for s in readable:
                if s is self.listen_sock:
                    conn, address = self.listen_sock.accept()  # accept connection from another peer
                    logger.debug('__handle_peer_sock: Connection address:' + str(address))
                    self.client_socks.append(conn)
                    self.conn_info[conn] = {}
                else:
                    rqst = ClientToClient()
                    data = s.recv(BUFFER_SIZE)
                    if len(data) == 0:
                        # len(data) == 0 means other side is closing socket
                        # delete the meta data immediately
                        s.close()
                        # If client sends to himself, then self.peer_info[name] is already
                        # popped when receiving ClientToClient.MESSAGE
                        self.peer_info.pop(self.conn_info[s]['name'], None)
                        self.conn_info.pop(s)
                        self.client_socks.remove(s)
                        logger.debug('__handle_peer_sock: Delete socket on receiving empty packet')
                    # shared key haven't established, so it is the first two msg of authentication protocol
                    elif 'shared_dh' not in self.conn_info[s]:
                        rqst.ParseFromString(data)
                        if rqst.type == ClientToClient.SENDER_PUB:
                            self.__handle_sender_pub(rqst, s)
                        elif rqst.type == ClientToClient.RECVER_PUB:
                            self.__handle_recver_pub(rqst, s)
                        else:
                            logger.debug('__handle_peer_sock: Drop...' + rqst.type)
                    # shared key already established, so it is the last two msg of authentication protocol
                    # or the actual conversation message
                    else:
                        content = b64decode_aes_cgm_decrypt(data, self.conn_info[s]['shared_dh'])
                        rqst.ParseFromString(content)
                        if rqst.type == ClientToClient.SENDER_IDENTITY:
                            self.__handle_sender_identiy(rqst, s)
                        elif rqst.type == ClientToClient.RECVER_IDENTITY:
                            self.__handle_recver_identity(rqst, s)
                        elif rqst.type == ClientToClient.MESSAGE and abs(rqst.time - time.time()) <= TIME_TOLERANCE:
                            # On receiving message, we can safely close the socket and forget
                            # all the shared key
                            print self.conn_info[s]['name'] + ": " + rqst.msg
                            s.close()
                            self.client_socks.remove(s)
                            self.peer_info.pop(self.conn_info[s]['name'])
                            self.conn_info.pop(s)
                        else:
                            logger.warn('__handle_peer_sock: Drop on unknown tyoe or timestamp is outdated')

    """""
    Sends dh public key through sockets
    """""
    def __send_dh_pub(self, dh_private_key, rply_type, s):
        rply = ClientToClient()
        rply.type = rply_type
        rply.public_key = base64.b64encode(dh_private_key
                                           .public_key()
                                           .public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo))
        s.send(rply.SerializeToString())

    """""
    Sends (g^ab mod p){"Bob", [g^a mod p]sign-B}
    """""
    def __send_identity(self, dh_private, rply_type, s):
        dh_public_key_bytes = dh_private.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
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
        s.send(utils.b64encode_aes_cgm_encrypt(rply.SerializeToString(), self.conn_info[s]['shared_dh']))

    """""
    During authentication, receives DoS cookies and W's salt from server.
    Echo back this cookies and compute W using salt
    """""
    def __handle_dos_salt(self, rqst, rply):
        self.w1_salt = base64.b64decode(rply.salt)
        self.w1 = utils.password_to_w(self.w1_salt, self.password, utils.w1_iteration, utils.w1_length)

        rqst.type = ClientToServer.USER_PUBKEY
        rqst.challenge = rply.challenge
        self.dh_private = ec.generate_private_key(ec.SECP384R1(), default_backend())
        rqst.public_key = base64.b64encode(self.dh_private.public_key()
                                               .public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo))
        self.server_sock.send(rqst.SerializeToString())
        logger.debug('__handle_dos_salt')

    """""
    During authentication, Receives W{g^b mod p}, (g^ab mod p){W'{rsa private key}} and c from server
    Sends back [hash(g^ab mod p, c)]sign to server to prove myself
    """""
    def __handle_server_dhpub(self, rqst, rply):
        decrypted_key_bytes = b64decode_aes_cgm_decrypt(rply.public_key, self.w1)
        server_dh_public = utils.deserialize_public_key(decrypted_key_bytes)
        # compute shared key
        self.dh_shared = utils.generate_dh_key(self.dh_private, server_dh_public)

        # So we can compute y = W'{rsa private key} now
        y = b64decode_aes_cgm_decrypt(rply.private_key, self.dh_shared)

        # decrypt with W' and extract rsa private key
        self.w2_salt, iv1, tag, cipher_private = y[:16], y[16:32], y[32:48], y[48:]
        self.w2 = utils.password_to_w(self.w2_salt, self.password, utils.w2_iteration, utils.w2_length)
        private_key_bytes = utils.aes_cgm_decrypt(cipher_private, self.w2, iv1, tag)
        self.private_key = utils.deserialize_private_key(private_key_bytes)

        rqst.type = ClientToServer.USER_SIGN
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(self.dh_shared)
        digest.update(base64.b64decode(rply.challenge))
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
        logger.debug('__handle_server_dhpub: Processed SERVER_PUBKEY rqst')

    """""
    Handle send command. We hav to query peer's public key and address first
    Send K{"query Bob"} to server.
    """""
    def __handle_send(self, name, msg):
        self.peer_info[name] = {'msg': msg}
        self.server_expect['Query'].add(name)
        rqst = ClientToServer()
        rqst.type = ClientToServer.QUERY_PEER
        rqst.time = int(time.time())
        rqst.name = name
        self.server_sock.send(utils.b64encode_aes_cgm_encrypt(rqst.SerializeToString(), self.dh_shared))

    """""
    Send K{"list"} to ask server for all login user
    """""
    def __handle_list(self):
        self.server_expect['List'] = True
        rqst = ClientToServer()
        rqst.type = ClientToServer.LIST
        rqst.time = int(time.time())
        self.server_sock.send(utils.b64encode_aes_cgm_encrypt(rqst.SerializeToString(), self.dh_shared))

    """""
    Send K{"logout"} to tell server we are going to exit
    """""
    def __handle_logout(self):
        self.server_expect['Logout'] = True
        rqst = ClientToServer()
        rqst.type = ClientToServer.LOGOUT
        rqst.time = int(time.time())
        self.server_sock.send(utils.b64encode_aes_cgm_encrypt(rqst.SerializeToString(), self.dh_shared))

    def __login(self):
        try:
            self.server_sock.connect((IP_ADDR, TCP_PORT))  # connect to server
            rqst = ClientToServer()
            rqst.type = ClientToServer.INITIATOR
            rqst.name = self.name
            self.server_sock.send(rqst.SerializeToString())
            while 1:
                data = self.server_sock.recv(BUFFER_SIZE)
                logger.debug('Receive auth msg')
                rply = ServerToClient()
                rply.ParseFromString(data)
                rqst = ClientToServer()
                if rply.type == ServerToClient.DOS_SALT:
                    self.__handle_dos_salt(rqst, rply)
                elif rply.type == ServerToClient.SERVER_PUBKEY:
                    self.__handle_server_dhpub(rqst, rply)
                    return True
                elif rply.type == ServerToClient.ERROR:
                    print 'Error information from server: ' + rply.info
                    self.server_sock.close()
                    return False
                else:
                    print 'Unsupported type: ' + rply.type
        except Exception as e:
            print 'Fail to authenticate. ', e
            self.server_sock.close()
            return False

    def run(self):
        self.login = self.__login()
        if not self.login:
            return
        server_handler = threading.Thread(target=self.__handle_server_sock)
        server_handler.start()
        peer_handler = threading.Thread(target=self.__handle_peer_sock)
        peer_handler.start()

        try:
            while self.login:
                user_cmd = raw_input()
                res = self.prog.match(user_cmd)
                trimmed = user_cmd.strip()
                if not self.login:
                    print 'You are logout, exit program'
                    return
                if trimmed == 'list':
                    self.__handle_list()
                elif trimmed == 'logout':
                    self.__handle_logout()
                elif res is not None and res.group(1) == 'send':
                    peer_name = res.group(2)
                    msg = res.group(3)
                    self.__handle_send(peer_name, msg)
                elif len(trimmed) == 0:
                    continue
                else:
                    print 'Wrong command!'
        except Exception as e:
            print 'Unexpected error: ', str(e)

if __name__ == '__main__':
    user_name = raw_input('user name: ')
    user_pwd = raw_input('password: ')
    client = Client(user_name, user_pwd)
    client.run()
