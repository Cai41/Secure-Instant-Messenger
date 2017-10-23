# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: instant-messenger.proto

import sys
_b=sys.version_info[0]<3 and (lambda x:x) or (lambda x:x.encode('latin1'))
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
from google.protobuf import descriptor_pb2
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='instant-messenger.proto',
  package='',
  syntax='proto3',
  serialized_pb=_b('\n\x17instant-messenger.proto\"\xed\x01\n\x0eServerToClient\x12\"\n\x04type\x18\x01 \x01(\x0e\x32\x14.ServerToClient.Type\x12\x11\n\tchallenge\x18\x02 \x01(\t\x12\x0c\n\x04salt\x18\x03 \x01(\t\x12\x12\n\npublic_key\x18\x04 \x01(\t\x12\x13\n\x0bprivate_key\x18\x05 \x01(\t\x12\n\n\x02ip\x18\x06 \x01(\t\x12\x0c\n\x04port\x18\x07 \x01(\t\x12\x0c\n\x04name\x18\x08 \x01(\t\"E\n\x04Type\x12\x0c\n\x08\x44OS_SALT\x10\x00\x12\x11\n\rSERVER_PUBKEY\x10\x01\x12\x0f\n\x0bREPLY_QUERY\x10\x02\x12\x0b\n\x07INVALID\x10\x03\"\xe6\x01\n\x0e\x43lientToServer\x12\"\n\x04type\x18\x01 \x01(\x0e\x32\x14.ClientToServer.Type\x12\x0c\n\x04name\x18\x02 \x01(\t\x12\x11\n\tchallenge\x18\x03 \x01(\t\x12\x12\n\npublic_key\x18\x04 \x01(\t\x12\x0c\n\x04hash\x18\x05 \x01(\t\x12\x0c\n\x04sign\x18\x06 \x01(\t\x12\n\n\x02ip\x18\x07 \x01(\t\x12\x0c\n\x04port\x18\x08 \x01(\t\"E\n\x04Type\x12\r\n\tINITIATOR\x10\x00\x12\x0f\n\x0bUSER_PUBKEY\x10\x01\x12\r\n\tUSER_SIGN\x10\x02\x12\x0e\n\nQUERY_PEER\x10\x03\"\xd0\x01\n\x0e\x43lientToClient\x12\"\n\x04type\x18\x01 \x01(\x0e\x32\x14.ClientToClient.Type\x12\x0c\n\x04name\x18\x02 \x01(\t\x12\x12\n\npublic_key\x18\x03 \x01(\t\x12\x0c\n\x04sign\x18\x04 \x01(\t\x12\x0b\n\x03msg\x18\x05 \x01(\t\"]\n\x04Type\x12\x0e\n\nSENDER_PUB\x10\x00\x12\x0e\n\nRECVER_PUB\x10\x01\x12\x13\n\x0fSENDER_IDENTITY\x10\x02\x12\x13\n\x0fRECVER_IDENTITY\x10\x03\x12\x0b\n\x07MESSAGE\x10\x04\x62\x06proto3')
)



_SERVERTOCLIENT_TYPE = _descriptor.EnumDescriptor(
  name='Type',
  full_name='ServerToClient.Type',
  filename=None,
  file=DESCRIPTOR,
  values=[
    _descriptor.EnumValueDescriptor(
      name='DOS_SALT', index=0, number=0,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='SERVER_PUBKEY', index=1, number=1,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='REPLY_QUERY', index=2, number=2,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='INVALID', index=3, number=3,
      options=None,
      type=None),
  ],
  containing_type=None,
  options=None,
  serialized_start=196,
  serialized_end=265,
)
_sym_db.RegisterEnumDescriptor(_SERVERTOCLIENT_TYPE)

_CLIENTTOSERVER_TYPE = _descriptor.EnumDescriptor(
  name='Type',
  full_name='ClientToServer.Type',
  filename=None,
  file=DESCRIPTOR,
  values=[
    _descriptor.EnumValueDescriptor(
      name='INITIATOR', index=0, number=0,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='USER_PUBKEY', index=1, number=1,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='USER_SIGN', index=2, number=2,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='QUERY_PEER', index=3, number=3,
      options=None,
      type=None),
  ],
  containing_type=None,
  options=None,
  serialized_start=429,
  serialized_end=498,
)
_sym_db.RegisterEnumDescriptor(_CLIENTTOSERVER_TYPE)

_CLIENTTOCLIENT_TYPE = _descriptor.EnumDescriptor(
  name='Type',
  full_name='ClientToClient.Type',
  filename=None,
  file=DESCRIPTOR,
  values=[
    _descriptor.EnumValueDescriptor(
      name='SENDER_PUB', index=0, number=0,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='RECVER_PUB', index=1, number=1,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='SENDER_IDENTITY', index=2, number=2,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='RECVER_IDENTITY', index=3, number=3,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='MESSAGE', index=4, number=4,
      options=None,
      type=None),
  ],
  containing_type=None,
  options=None,
  serialized_start=616,
  serialized_end=709,
)
_sym_db.RegisterEnumDescriptor(_CLIENTTOCLIENT_TYPE)


_SERVERTOCLIENT = _descriptor.Descriptor(
  name='ServerToClient',
  full_name='ServerToClient',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='type', full_name='ServerToClient.type', index=0,
      number=1, type=14, cpp_type=8, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='challenge', full_name='ServerToClient.challenge', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='salt', full_name='ServerToClient.salt', index=2,
      number=3, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='public_key', full_name='ServerToClient.public_key', index=3,
      number=4, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='private_key', full_name='ServerToClient.private_key', index=4,
      number=5, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='ip', full_name='ServerToClient.ip', index=5,
      number=6, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='port', full_name='ServerToClient.port', index=6,
      number=7, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='name', full_name='ServerToClient.name', index=7,
      number=8, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
    _SERVERTOCLIENT_TYPE,
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=28,
  serialized_end=265,
)


_CLIENTTOSERVER = _descriptor.Descriptor(
  name='ClientToServer',
  full_name='ClientToServer',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='type', full_name='ClientToServer.type', index=0,
      number=1, type=14, cpp_type=8, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='name', full_name='ClientToServer.name', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='challenge', full_name='ClientToServer.challenge', index=2,
      number=3, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='public_key', full_name='ClientToServer.public_key', index=3,
      number=4, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='hash', full_name='ClientToServer.hash', index=4,
      number=5, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='sign', full_name='ClientToServer.sign', index=5,
      number=6, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='ip', full_name='ClientToServer.ip', index=6,
      number=7, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='port', full_name='ClientToServer.port', index=7,
      number=8, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
    _CLIENTTOSERVER_TYPE,
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=268,
  serialized_end=498,
)


_CLIENTTOCLIENT = _descriptor.Descriptor(
  name='ClientToClient',
  full_name='ClientToClient',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='type', full_name='ClientToClient.type', index=0,
      number=1, type=14, cpp_type=8, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='name', full_name='ClientToClient.name', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='public_key', full_name='ClientToClient.public_key', index=2,
      number=3, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='sign', full_name='ClientToClient.sign', index=3,
      number=4, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='msg', full_name='ClientToClient.msg', index=4,
      number=5, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
    _CLIENTTOCLIENT_TYPE,
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=501,
  serialized_end=709,
)

_SERVERTOCLIENT.fields_by_name['type'].enum_type = _SERVERTOCLIENT_TYPE
_SERVERTOCLIENT_TYPE.containing_type = _SERVERTOCLIENT
_CLIENTTOSERVER.fields_by_name['type'].enum_type = _CLIENTTOSERVER_TYPE
_CLIENTTOSERVER_TYPE.containing_type = _CLIENTTOSERVER
_CLIENTTOCLIENT.fields_by_name['type'].enum_type = _CLIENTTOCLIENT_TYPE
_CLIENTTOCLIENT_TYPE.containing_type = _CLIENTTOCLIENT
DESCRIPTOR.message_types_by_name['ServerToClient'] = _SERVERTOCLIENT
DESCRIPTOR.message_types_by_name['ClientToServer'] = _CLIENTTOSERVER
DESCRIPTOR.message_types_by_name['ClientToClient'] = _CLIENTTOCLIENT
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

ServerToClient = _reflection.GeneratedProtocolMessageType('ServerToClient', (_message.Message,), dict(
  DESCRIPTOR = _SERVERTOCLIENT,
  __module__ = 'instant_messenger_pb2'
  # @@protoc_insertion_point(class_scope:ServerToClient)
  ))
_sym_db.RegisterMessage(ServerToClient)

ClientToServer = _reflection.GeneratedProtocolMessageType('ClientToServer', (_message.Message,), dict(
  DESCRIPTOR = _CLIENTTOSERVER,
  __module__ = 'instant_messenger_pb2'
  # @@protoc_insertion_point(class_scope:ClientToServer)
  ))
_sym_db.RegisterMessage(ClientToServer)

ClientToClient = _reflection.GeneratedProtocolMessageType('ClientToClient', (_message.Message,), dict(
  DESCRIPTOR = _CLIENTTOCLIENT,
  __module__ = 'instant_messenger_pb2'
  # @@protoc_insertion_point(class_scope:ClientToClient)
  ))
_sym_db.RegisterMessage(ClientToClient)


# @@protoc_insertion_point(module_scope)
