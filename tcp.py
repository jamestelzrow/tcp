import packet
import grading
from enum import Enum
import socket
import ipaddress


class Window(object):
    nextSeqExpected = 0
    lastAckReceived = 0
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

class ReadMode(Enum):
    NO_FLAG = 0
    NO_WAIT = 1
    TIMEOUT = 2
