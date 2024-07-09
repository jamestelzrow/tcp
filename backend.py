import packet
from packet import create_packet
from tcp import Socket, ReadMode, ClosingState
import socket
import select
from grading import DEFAULT_TIMEOUT, MSS
import sys
import errno
import time

from packet import SYN_FLAG_MASK, ACK_FLAG_MASK, FIN_FLAG_MASK
from random import randrange

def has_been_acked(sock, seq):
    """
    Tells if a given sequence number has been acked by the socket.
    
    @param sock - The sock to check for acknowledgements
    @param seq - Sequence number to check

    return True if the sequence number has been acked, False otherwise
    """
    return packet.after(sock.window.lastAckReceived, seq)

def handle_message(sock, pkt):
    """
    Updates the socket infomration to represent the newly received packet.
    Currently, it also sends an acknowledgement for the packet.

    @param sock - The socket used for handling packets received
    @param pkt - The packet data received by the socket
    """
    tcpHeader = packet.CaseTCP(pkt)
    flags = tcpHeader.flags

    src = sock.myPort
    dst = socket.ntohs(sock.conn.sinPort)
    ackNum = socket.ntohl(tcpHeader.ackNum)

    if (flags & packet.ACK_FLAG_MASK) and (flags & packet.FIN_FLAG_MASK):
        if sock.closingState == ClosingState.FIN_WAIT_1 and ackNum == sock.window.nextAckDesired:
            sock.window.nextSeqExpected = socket.ntohl(tcpHeader.seqNum) + 1
            sock.window.lastAckReceived = socket.ntohl(tcpHeader.ackNum)
            msg = create_ack_pkt(
                seq = sock.window.nextAckDesired - 1, 
                ack = sock.window.nextSeqExpected,
                src = src,
                dst = dst
            )
            sock.sockFd.sendto(bytes(msg), (sock.conn.sinAddr, dst))
            print('Setting state TIME_WAIT')
            sock.closingState = ClosingState.TIME_WAIT
            sock.time_wait_start = time.time()
        else:
            pass

    elif flags & packet.ACK_FLAG_MASK:
        if sock.closingState == ClosingState.ESTABLISHED:
            if packet.after(ackNum, sock.window.lastAckReceived):
                sock.window.lastAckReceived = ackNum
            else:
                pass
        elif sock.closingState == ClosingState.FIN_WAIT_1:
            if ackNum == sock.window.nextAckDesired:
                sock.window.nextSeqExpected = socket.ntohl(tcpHeader.seqNum) + 1
                sock.window.lastAckReceived = socket.ntohl(tcpHeader.ackNum)
                print('Setting state FIN_WAIT_2')
                print('updating nSE: {}, lAR: {}'.format(sock.window.nextSeqExpected, sock.window.lastAckReceived))
                sock.closingState = ClosingState.FIN_WAIT_2
            else:
                pass
        elif sock.closingState == ClosingState.FIN_WAIT_2:
            pass
        elif sock.closingState == ClosingState.TIME_WAIT:
            pass
        elif sock.closingState == ClosingState.CLOSE_WAIT:
            pass
        elif sock.closingState == ClosingState.LAST_ACK and ackNum == sock.window.nextAckDesired:
            sock.window.nextSeqExpected = socket.ntohl(tcpHeader.seqNum) + 1
            sock.window.lastAckReceived = socket.ntohl(tcpHeader.ackNum)
            print('Setting state CLOSED')
            print('updating nSE: {}, lAR: {}'.format(sock.window.nextSeqExpected, sock.window.lastAckReceived))
            sock.closingState = ClosingState.CLOSED
        elif sock.closingState == ClosingState.CLOSED:
            pass
        elif sock.closingState == ClosingState.CLOSING and ackNum == sock.window.nextAckDesired:
            sock.window.nextSeqExpected = socket.ntohl(tcpHeader.seqNum) + 1
            sock.window.lastAckReceived = socket.ntohl(tcpHeader.ackNum)
            print('Setting state TIME_WAIT')
            print('updating nSE: {}, lAR: {}'.format(sock.window.nextSeqExpected, sock.window.lastAckReceived))
            sock.closingState = ClosingState.TIME_WAIT
            sock.time_wait_start = time.time()

    elif flags & packet.FIN_FLAG_MASK:
        if sock.closingState == ClosingState.ESTABLISHED:
            sock.window.nextSeqExpected = socket.ntohl(tcpHeader.seqNum) + 1
            sock.window.lastAckReceived = socket.ntohl(tcpHeader.ackNum)
            msg = create_ack_pkt(
                seq = sock.window.nextAckDesired - 1,
                ack = sock.window.nextSeqExpected,
                src = src,
                dst = dst
            )
            sock.sockFd.sendto(bytes(msg), (sock.conn.sinAddr, dst))
            print('Setting state CLOSE_WAIT')
            print('updating nSE: {}, lAR: {}'.format(sock.window.nextSeqExpected, sock.window.lastAckReceived))
            sock.closingState = ClosingState.CLOSE_WAIT
        elif sock.closingState == ClosingState.FIN_WAIT_1:
            sock.window.nextSeqExpected = socket.ntohl(tcpHeader.seqNum) + 1
            sock.window.lastAckReceived = socket.ntohl(tcpHeader.ackNum)
            msg = create_ack_pkt(
                seq = sock.window.nextAckDesired - 1,
                ack = sock.window.nextSeqExpected,
                src = src,
                dst = dst
            )
            sock.sockFd.sendto(bytes(msg), (sock.conn.sinAddr, dst))
            print('Setting state CLOSING')
            print('updating nSE: {}, lAR: {}'.format(sock.window.nextSeqExpected, sock.window.lastAckReceived))
            sock.closingState = ClosingState.CLOSING
        elif sock.closingState == ClosingState.FIN_WAIT_2:
            sock.window.nextSeqExpected = socket.ntohl(tcpHeader.seqNum) + 1
            sock.window.lastAckReceived = socket.ntohl(tcpHeader.ackNum)
            msg = create_ack_pkt(
                seq = sock.window.nextAckDesired - 1,
                ack = sock.window.nextSeqExpected,
                src = src,
                dst = dst
            )
            sock.sockFd.sendto(bytes(msg), (sock.conn.sinAddr, dst))
            print('Setting state TIME_WAIT')
            print('updating nSE: {}, lAR: {}'.format(sock.window.nextSeqExpected, sock.window.lastAckReceived))
            sock.closingState = ClosingState.TIME_WAIT
            sock.time_wait_start = time.time()
        elif sock.closingState == ClosingState.TIME_WAIT:
            pass
        elif sock.closingState == ClosingState.CLOSE_WAIT:
            pass
        elif sock.closingState == ClosingState.LAST_ACK:
            pass
        elif sock.closingState == ClosingState.CLOSED:
            pass
        elif sock.closingState == ClosingState.CLOSING:
            pass

    elif flags & packet.SYN_FLAG_MASK:
        syn_ack_seq = randrange(start = 0, stop=1000)

        payload = None
        payloadLen = 0

        extData = None
        ack = socket.ntohl(tcpHeader.seqNum) + 1
        hLen = len(packet.CaseTCP())
        pLen = hLen
        flags = packet.SYN_FLAG_MASK + packet.ACK_FLAG_MASK
        advWindow = 1
        syn_ack_pkt = create_packet(src, dst, syn_ack_seq, ack, hLen, pLen, flags, advWindow, extData, payload, payloadLen)

        sock.sockFd.sendto(bytes(syn_ack_pkt), (sock.conn.sinAddr, dst))

        sock.window.nextSeqExpected = socket.ntohl(tcpHeader.seqNum) + 1
        sock.window.nextAckDesired = syn_ack_seq + 1

    else:
        seqNum = sock.window.lastAckReceived

        # No payload
        payload = None
        payloadLen = 0

        # No extension
        extData = None

        src = sock.myPort
        dst = socket.ntohs(sock.conn.sinPort)
        ack = socket.ntohl(tcpHeader.seqNum) + len(tcpHeader[packet.CaseTCP].payload)
        hLen = len(packet.CaseTCP())
        pLen = hLen + payloadLen;
        flags = packet.ACK_FLAG_MASK
        advWindow = 1
        respPkt = create_packet(src, dst, seqNum, ack, hLen, pLen, flags, advWindow, extData, payload, payloadLen)

        sock.sockFd.sendto(bytes(respPkt), (sock.conn.sinAddr, dst))

        seqNum = socket.ntohl(tcpHeader.seqNum)
        if seqNum == sock.window.nextSeqExpected:
            sock.window.nextSeqExpected = seqNum + len(tcpHeader[packet.CaseTCP].payload)
            payload = tcpHeader[packet.CaseTCP].payload
            payloadLen = len(payload)
            
            sock.receivedBuf += bytes(payload)
            sock.receivedLen += payloadLen

def check_for_data(sock, flags):
    """
    Checks if the socket received any data.

    @param sock - The socket used for receiving data on the connection.
    @param flags - Flags that determine how the socket should wait for data. 
    """
    unknown_flag = True
    msg = ""
    events = []
    sock.recvLock.acquire()
    if flags == ReadMode.NO_FLAG:
        unknown_flag = False
        try:
            msg, addr = sock.sockFd.recvfrom(1024, socket.MSG_PEEK)
            sock.conn.sinAddr = addr[0]
            sock.conn.sinPort = socket.ntohs(addr[1])
        except IOError as e:
            if e.errno == errno.EWOULDBLOCK:
                pass
    
    elif flags == ReadMode.TIMEOUT:
        unknown_flag = False
        epoll = select.epoll()
        epoll.register(sock.sockFd, select.EPOLLIN)
        events = epoll.poll(DEFAULT_TIMEOUT)

    if len(events) or flags == ReadMode.NO_WAIT:
        unknown_flag = False
        try:
            msg, addr = sock.sockFd.recvfrom(1024, socket.MSG_DONTWAIT|socket.MSG_PEEK)
            sock.conn.sinAddr = addr[0]
            sock.conn.sinPort = socket.ntohs(addr[1])
            
        except IOError as e:
            if e.errno == errno.EWOULDBLOCK:
                pass

    if unknown_flag:
        print("ERROR unknown flag")

    if len(msg) >= len(packet.CaseTCP()):
        tcpHeader = packet.CaseTCP(msg)
        pLen = socket.ntohs(tcpHeader.pLen)
        pkt = b""
        bufSize = 0
        while bufSize < pLen:
            data, addr = sock.sockFd.recvfrom(pLen-bufSize)
            sock.conn.sinAddr = addr[0]
            sock.conn.sinPort = socket.ntohs(addr[1])
            pkt += data
            bufSize += len(data)

        handle_message(sock, pkt)
    sock.recvLock.release()

def single_send(sock, data, bufLen):
    """
    Breaks up the data into packets and sends a single packet at a time. 

    @param sock - The socket used for sending data
    @param data - The data to be sent
    @param bufLen - The length of the data being sent
    """
    dataOffset = data
    if bufLen > 0:
        while bufLen != 0:
            payloadLen = min(bufLen, MSS)
            src = sock.myPort
            dst = socket.ntohs(sock.conn.sinPort)
            seq = sock.window.lastAckReceived
            sock.window.nextAckDesired = seq + payloadLen
            ack = sock.window.nextSeqExpected
            hLen = len(packet.CaseTCP())
            pLen = hLen + payloadLen
            flags = 0
            advWindow = 1
            extData = None
            payload = dataOffset
            
            msg = create_packet(src, dst, seq, ack, hLen, pLen, flags, advWindow, extData, payload, payloadLen)
            bufLen -= payloadLen

            while True:
                sock.sockFd.sendto(bytes(msg), (sock.conn.sinAddr, dst))
                check_for_data(sock, ReadMode.TIMEOUT)
                if has_been_acked(sock, seq):
                    break

            dataOffset = dataOffset[payloadLen:]

def begin_backend(sock):
    while True:
        with sock.deathLock:
            death = sock.dying
        
        data = ""
        with sock.sendLock:
            bufLen = sock.sendingLen
            if death == 1 and bufLen == 0:
                seq = sock.window.lastAckReceived - 1
                ack = sock.window.nextSeqExpected
                src = sock.myPort
                dst = socket.ntohs(sock.conn.sinPort)
                if sock.closingState == ClosingState.ESTABLISHED:
                    print('Sending fin seq: {} ack: {}'.format(seq, ack))
                    msg = create_fin_pkt(seq = seq, ack = ack, src = src, dst = dst)
                    sock.sockFd.sendto(bytes(msg), (sock.conn.sinAddr, dst))
                    print('Setting state FIN_WAIT_1')
                    sock.closingState = ClosingState.FIN_WAIT_1
                    sock.packet_sent_timestamp = time.time()
                elif sock.closingState == ClosingState.FIN_WAIT_1:
                    if time.time() - sock.packet_sent_timestamp >= DEFAULT_TIMEOUT:
                        print('Sending fin seq: {} ack: {}'.format(seq, ack))
                        msg = create_fin_pkt(seq = seq, ack = ack, src = src, dst = dst)
                        sock.sockFd.sendto(bytes(msg), (sock.conn.sinAddr, dst))
                        sock.packet_sent_timestamp = time.time()
                    else:
                        pass
                elif sock.closingState == ClosingState.FIN_WAIT_2:
                    pass
                elif sock.closingState == ClosingState.TIME_WAIT:
                    if time.time() - sock.time_wait_start >= 2 * DEFAULT_TIMEOUT:
                        print('Setting state CLOSED')
                        sock.closingState = ClosingState.CLOSED
                    else:
                        pass
                elif sock.closingState == ClosingState.CLOSE_WAIT:
                    print('Sending fin seq: {} ack: {}'.format(seq, ack))
                    msg = create_fin_pkt(seq = seq, ack = ack, src = src, dst = dst)
                    sock.sockFd.sendto(bytes(msg), (sock.conn.sinAddr, dst))
                    print('Setting state LAST_ACK')
                    sock.closingState = ClosingState.LAST_ACK
                    sock.packet_sent_timestamp = time.time()
                elif sock.closingState == ClosingState.LAST_ACK:
                    if time.time() - sock.packet_sent_timestamp >= DEFAULT_TIMEOUT:
                        print('Sending fin seq: {} ack: {}'.format(seq, ack))
                        msg = create_fin_pkt(seq = seq, ack = ack, src = src, dst = dst)
                        sock.sockFd.sendto(bytes(msg), (sock.conn.sinAddr, dst))
                        sock.packet_sent_timestamp = time.time()
                    else:
                        pass
                elif sock.closingState == ClosingState.CLOSED:
                    break
                elif sock.closingState == ClosingState.CLOSING:
                    if time.time() - sock.packet_sent_timestamp >= DEFAULT_TIMEOUT:
                        print('Sending fin seq: {} ack: {}'.format(seq, ack))
                        msg = create_fin_pkt(seq = seq, ack = ack, src = src, dst = dst)
                        sock.sockFd.sendto(bytes(msg), (sock.conn.sinAddr, dst))
                        sock.packet_sent_timestamp = time.time()
                    else:
                        pass

            if bufLen > 0:
                data = sock.sendingBuf[:bufLen]
                sock.sendingLen = 0
                sock.sendingBuf = b""

        if len(data):
            single_send(sock, data, bufLen)

        check_for_data(sock, ReadMode.NO_WAIT)

        with sock.recvLock:
            send_signal = True if sock.receivedLen > 0 else False
            
            if send_signal:
                sock.waitCond.notify()

    sys.exit(0)

# My code

def create_syn_pkt(seq, src, dst):
    hLen = len(packet.CaseTCP())
    pLen = hLen
    advWindow = 1

    return create_packet(src, dst, seq, 1, hLen, pLen, SYN_FLAG_MASK, advWindow, None, b"", 0)

def did_timeout(time_last_sent):
    if time.time() - time_last_sent > DEFAULT_TIMEOUT:
        return True
    else:
        return False
    
def create_ack_pkt(seq, ack, src, dst):
    hLen = len(packet.CaseTCP())
    pLen = hLen
    advWindow = 1

    return create_packet(src, dst, seq, ack, hLen, pLen, ACK_FLAG_MASK, advWindow, None, b"", 0)

def create_fin_pkt(seq, ack, src, dst):
    hLen = len(packet.CaseTCP())
    pLen = hLen
    advWindow = 1

    return create_packet(src, dst, seq, ack, hLen, pLen, FIN_FLAG_MASK, advWindow, None, b"", 0)