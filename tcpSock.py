from tcp import Socket, Window, SocketType, SockaddrIn, ReadMode, ClosingState
from backend import begin_backend
import socket
from threading import Thread, Lock, Condition

# My code
from grading import DEFAULT_TIMEOUT
from random import randrange
import select
import errno
import time
import packet
from backend import create_syn_pkt, did_timeout, create_ack_pkt

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

    if sockType == SocketType.TCP_INITIATOR:
        syn_seq = randrange(start = 0, stop=1000)
        syn_msg = create_syn_pkt(seq = syn_seq, src = port, dst = socket.ntohs(sock.conn.sinPort))
        got_synack = False
        should_send_syn = True
        synack_sent_time = 0
        while not got_synack:
            if should_send_syn:
                sock.sockFd.sendto(bytes(syn_msg), (sock.conn.sinAddr, socket.ntohs(sock.conn.sinPort)))
                should_send_syn = False
                synack_sent_time = time.time()
            else:
                epoll = select.epoll()
                epoll.register(sock.sockFd, select.EPOLLIN)
                events = epoll.poll(DEFAULT_TIMEOUT)
                if len(events):
                    try:
                        msg, _ = sock.sockFd.recvfrom(1024, socket.MSG_DONTWAIT|socket.MSG_PEEK)
                        if len(msg) >= len(packet.CaseTCP()):
                            tcpHeader = packet.CaseTCP(msg)
                            pLen = socket.ntohs(tcpHeader.pLen)
                            flags = tcpHeader.flags
                            ack_num = socket.ntohl(tcpHeader.ackNum)
                            if (flags & packet.SYN_FLAG_MASK) and (flags & packet.ACK_FLAG_MASK) and (ack_num == syn_seq + 1) and (pLen <= len(msg)):
                                got_synack = True
                                sock.window.lastAckReceived = socket.ntohl(tcpHeader.ackNum)
                                sock.window.nextSeqExpected = socket.ntohl(tcpHeader.seqNum) + 1
                                sock.window.nextAckDesired = syn_seq + 1
                                sock.sockFd.recvfrom(pLen)
                            else:
                                should_send_syn = did_timeout(synack_sent_time)
                    except IOError as e:
                        if e.errno == errno.EWOULDBLOCK:
                            should_send_syn = did_timeout(synack_sent_time)
                else:
                    should_send_syn = did_timeout(synack_sent_time)

        # Now that we have received the SYN-ACK packet, we ACK it.
        ack_msg = create_ack_pkt(seq = syn_seq, ack = sock.window.nextSeqExpected, src = port, dst = socket.ntohs(sock.conn.sinPort))
        sock.sockFd.sendto(bytes(ack_msg), (sock.conn.sinAddr, socket.ntohs(sock.conn.sinPort)))

    sock.closingState = ClosingState.ESTABLISHED

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
