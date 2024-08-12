import packet
import grading
from enum import Enum
import socket
import ipaddress


class Window(object):
    # For receiving buffer
    last_byte_read = 0
    last_byte_rcvd = 0
    next_byte_expected = 0
    # For sending buffer
    last_byte_acked = 0
    last_byte_sent = 0
    last_byte_written = 0

    our_advertised_window = 0
    peer_advertised_window = 0

    time_since_last_new_ack_or_retrans = 0

    def __init__(self):
        pass

class SocketType(Enum):
    TCP_INITIATOR = 0
    TCP_LISTENER = 1

class SockaddrIn(object):
    sinFamily = socket.AF_INET
    sinPort = 0
    sinAddr = '0.0.0.0'

    def __init__(self, addr=None, port=None):
        if addr is not None:
            self.sinAddr = addr
        if port is not None:
            self.sinPort = port

class Socket(object):
    sockFd = None
    thread = None
    myPort = None
    conn = None
    receivedBuf = b""
    recvLock = None
    recvCond = None
    sendingBuf = b""
    sendLock = None
    sendCond = None
    sockType = None
    dying = 0
    deathLock = None
    window = None
    state = 0
    time_wait_start = 0
    packet_sent_timestamp = 0

class ReadMode(Enum):
    NO_FLAG = 0
    NO_WAIT = 1
    TIMEOUT = 2

class TCPState(Enum):
    SYN_SENT = 0
    LISTEN = 1
    SYN_RCVD = 2
    ESTABLISHED = 3
    FIN_WAIT_1 = 4
    FIN_WAIT_2 = 5
    TIME_WAIT = 6
    CLOSE_WAIT = 7
    LAST_ACK = 8
    CLOSING = 9
    CLOSED = 10