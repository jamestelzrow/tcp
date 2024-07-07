from tcp import Socket, Window, SocketType, SockaddrIn, ReadMode
from backend import begin_backend
import socket
from threading import Thread, Lock, Condition

EXIT_SUCCESS = 0
EXIT_ERROR = 1
EXIT_FAILURE = 1

def case_socket(sock, sockType, port, serverIP):
    sockfd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sockFd = sockfd
    sock.recvLock = Lock()
    sock.sendLock = Lock()
    sock.deathLock = Lock()
    sock.sockType = sockType
    sock.window = Window()
    # TODO: to be updated
    sock.window.nextSeqExpected = 0
    sock.window.lastAckReceived = 0

    sock.waitCond = Condition(sock.recvLock)

    if sockType == SocketType.TCP_INITIATOR:
        sock.conn = SockaddrIn(serverIP, socket.ntohs(port))
        sockfd.bind(('', 0))

    elif sockType == SocketType.TCP_LISTENER:
        sock.conn = SockaddrIn(socket.INADDR_ANY, socket.htons(port))
        sockfd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sockfd.bind(('', port))

    else:
        print("Unknown Flag")
        return EXIT_ERROR

    myAddr, myPort = sockfd.getsockname()
    sock.myPort = socket.ntohs(myPort)

    t = Thread(target=begin_backend, args=(sock,), daemon=True)
    sock.thread = t
    t.start()
    return EXIT_SUCCESS

def case_close(sock):
    sock.deathLock.acquire()
    try:
        sock.dying = 1
    finally:
        sock.deathLock.release()

    sock.thread.join()

    if sock is not None:
        sock.receivedBuf = b""
        sock.sendingBuf = b""

    else:
        print("Error null socket")
        return EXIT_ERROR
    
    sock.sockFd.close()
    return EXIT_SUCCESS

def case_read(sock, buf, length, flags):
    readLen = 0
    if length < 0:
        print("ERROR negative length")
        return EXIT_ERROR

    if flags == ReadMode.NO_FLAG:
        with sock.waitCond:
            while sock.receivedLen == 0:
                sock.waitCond.wait()

    sock.recvLock.acquire()
    if flags == ReadMode.NO_WAIT or flags == ReadMode.NO_FLAG:
        if sock.receivedLen > 0:
            if sock.receivedLen > length:
                readLen = length
            else:
                readLen = sock.receivedLen

            buf[0] = sock.receivedBuf

            if readLen < sock.receivedLen:
                sock.receivedLen -= readLen
                sock.receivedBuf = sock.receivedBuf[readLen:]

            else:
                sock.receivedBuf = b""
                sock.receivedLen = 0
    elif flags != ReadMode.NO_FLAG and flags != ReadMode.NO_WAIT:
        print("ERROR Unknown flag")
        readLen = EXIT_ERROR

    sock.recvLock.release()
    return readLen

def case_write(sock, buf, length):
    with sock.sendLock:
        if sock.sendingBuf is None:
            sock.sendingBuf = b""
        sock.sendingBuf += buf[:length].encode()
        sock.sendingLen += length
    return EXIT_SUCCESS
