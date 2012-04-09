from pywowd.opcodes import CMSG_AUTH_SESSION, CMSG_READY_FOR_ACCOUNT_DATA_TIMES,\
    CMSG_CHAR_ENUM, CMSG_REALM_SPLIT, CMSG_PLAYER_LOGIN, CMSG_PING
from pywowd.handlers import logon

handlers = {
    CMSG_AUTH_SESSION: logon.handle_auth_session,
    CMSG_READY_FOR_ACCOUNT_DATA_TIMES: logon.handle_account_data_times, 
    CMSG_CHAR_ENUM: logon.handle_char_enum,
    CMSG_REALM_SPLIT: logon.handle_realm_split,
    CMSG_PLAYER_LOGIN: logon.handle_player_login,
    CMSG_PING: logon.handle_ping,
}
