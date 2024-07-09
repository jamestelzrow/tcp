import packet
import grading
from enum import Enum
import socket
import ipaddress


class Window(object):
    nextSeqExpected = 0
    lastAckReceived = 0
    # This is equal to the sequence number of the last packet 
    # we have sent, plus the length of that packet's payload.
    # We use it to determine if the peer has received all the
    # data that we sent.
    nextAckDesired = 0

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
    receivedLen = 0
    recvLock = None
    waitCond = None
    sendingBuf = b""
    sendingLen = 0
    sockType = None
    sendLock = None
    dying = 0
    deathLock = None
    window = None
    # My code
    closingState = 0
    time_wait_start = 0
    packet_sent_timestamp = 0

class ReadMode(Enum):
    NO_FLAG = 0
    NO_WAIT = 1
    TIMEOUT = 2

# My code

class ClosingState(Enum):
    ESTABLISHED = 0
    FIN_WAIT_1 = 1
    FIN_WAIT_2 = 2
    TIME_WAIT = 3
    CLOSE_WAIT = 4
    LAST_ACK = 5
    CLOSED = 6
    CLOSING = 7