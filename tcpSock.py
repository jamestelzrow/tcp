from backend import begin_backend, create_ack_pkt, create_packet, did_timeout
import errno
from grading import DEFAULT_TIMEOUT, MAX_NETWORK_BUFFER
import packet
from random import randrange
import select
import socket
from tcp import Window, SocketType, SockaddrIn, ReadMode, TCPState
from threading import Thread, Lock, Condition
import time

EXIT_SUCCESS = 0
EXIT_ERROR = 1
EXIT_FAILURE = 1

def case_socket(sock, sockType, port, serverIP):
    sockfd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sockFd = sockfd

    sock.recvLock = Lock()
    sock.recvCond = Condition(sock.recvLock)
    sock.sendLock = Lock()
    sock.sendCond = Condition(sock.sendLock)
    sock.deathLock = Lock()

    sock.sockType = sockType
    sock.window = Window()

    sock.state = TCPState.CLOSED

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

        syn_packet_seq_num = randrange(start = 0, stop=1000)
        syn_packet_ack_num = 0
        syn_packet_src = sock.myPort
        syn_packet_dst = socket.ntohs(sock.conn.sinPort)
        syn_packet_advertised_window = MAX_NETWORK_BUFFER

        syn_packet_payload = None
        syn_packet_payload_len = 0
        syn_packet_extension_data = None
        syn_packet_header_len = len(packet.CaseTCP())
        syn_packet_len = syn_packet_header_len + syn_packet_payload_len
        syn_packet_flags = packet.SYN_FLAG_MASK

        syn_packet = create_packet(
            syn_packet_src,
            syn_packet_dst,
            syn_packet_seq_num,
            syn_packet_ack_num,
            syn_packet_header_len,
            syn_packet_len,
            syn_packet_flags,
            syn_packet_advertised_window,
            syn_packet_extension_data,
            syn_packet_payload,
            syn_packet_payload_len
        )

        # Here it is safe to do this "subtract one" approach discussed (and NOT used) in backend.py, since we don't continue until we receive the ACK data.
        sock.window.last_byte_acked = syn_packet_seq_num - 1
        sock.window.last_byte_written = syn_packet_seq_num
        sock.window.last_byte_sent = syn_packet_seq_num
        sock.window.our_advertised_window = MAX_NETWORK_BUFFER

        sock.sendingBuf = []
        sock.receivedBuf = []
        for _ in range(MAX_NETWORK_BUFFER):
            sock.sendingBuf.append(None)
            sock.receivedBuf.append(None)

        got_synack = False
        should_send_syn = True
        synack_sent_time = 0
        while not got_synack:
            if should_send_syn:
                sock.sockFd.sendto(bytes(syn_packet), (sock.conn.sinAddr, socket.ntohs(sock.conn.sinPort)))
                sock.state = TCPState.SYN_SENT
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
                            if (flags & packet.SYN_FLAG_MASK) and (flags & packet.ACK_FLAG_MASK) and (ack_num == syn_packet_seq_num + 1) and (pLen <= len(msg)):
                                got_synack = True
                                sock.window.last_byte_acked = ack_num - 1
                                sock.window.last_byte_read = socket.ntohl(tcpHeader.seqNum)
                                sock.window.last_byte_rcvd = socket.ntohl(tcpHeader.seqNum)
                                sock.window.next_byte_expected = socket.ntohl(tcpHeader.seqNum) + 1
                                sock.window.peer_advertised_window = socket.ntohs(tcpHeader.advWin)
                                sock.sockFd.recvfrom(pLen)
                            else:
                                should_send_syn = did_timeout(synack_sent_time)
                    except IOError as e:
                        if e.errno == errno.EWOULDBLOCK:
                            should_send_syn = did_timeout(synack_sent_time)
                else:
                    should_send_syn = did_timeout(synack_sent_time)

        # Now that we have received the SYN-ACK packet, we ACK it.

        ack_packet_seq_num = sock.window.last_byte_sent + 1
        ack_packet_ack_num = sock.window.next_byte_expected
        ack_packet_src = sock.myPort
        ack_packet_dst = socket.ntohs(sock.conn.sinPort)
        ack_packet_advertised_window = sock.window.our_advertised_window

        ack_packet = create_ack_pkt(
            ack_packet_seq_num,
            ack_packet_ack_num,
            ack_packet_src,
            ack_packet_dst,
            ack_packet_advertised_window
        )

        sock.sockFd.sendto(bytes(ack_packet), (sock.conn.sinAddr, ack_packet_dst))

        sock.state = TCPState.ESTABLISHED

    else:

        sock.state = TCPState.LISTEN

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
        sock.sendingBuf = []
        sock.receivedBuf = []
        for _ in range(MAX_NETWORK_BUFFER):
            sock.sendingBuf.append(None)
            sock.receivedBuf.append(None)

        sock.receivedBuf = b""
        sock.sendingBuf = b""

    else:
        print("Error null socket")
        return EXIT_ERROR
    
    sock.sockFd.close()
    return EXIT_SUCCESS

def case_read(sock, buf, length, flags):
    number_of_bytes_read = 0
    if length < 0:
        print("ERROR negative length")
        return EXIT_ERROR

    # Indicates whether we should wait on the receiving Condition and then try to read data again.
    must_wait_to_read = True
    
    with sock.recvLock:

        if sock.window.last_byte_read < sock.window.next_byte_expected - 1:
            # We do have some data left to read, so regardless of what state we are in, we get it and pass it off to the user.
            number_of_bytes_to_read = min((sock.window.next_byte_expected - 1) - sock.window.last_byte_read, length)
            bytes_read = sock.receivedBuf[:number_of_bytes_to_read]

            sock.receivedBuf = sock.receivedBuf[number_of_bytes_to_read:]
            for _ in range(number_of_bytes_to_read):
                sock.receivedBuf.append(None)

            sock.window.last_byte_read = sock.window.last_byte_read + number_of_bytes_to_read
            sock.window.our_advertised_window = MAX_NETWORK_BUFFER - ((sock.window.next_byte_expected - 1) - sock.window.last_byte_read)

            buf[0] = bytes(bytes_read)
            number_of_bytes_read = number_of_bytes_to_read
            must_wait_to_read = False
        else:
            # We don't have any data to read.
            # If we got the NO_WAIT flag (meaning that the user doesn't want to wait for any new data even if some might arrive)
            # or if we are in the CLOSING, TIME_WAIT, CLOSE_WAIT, LAST_ACK, or CLOSED states (which are all the states that we may 
            # be in if we have received a FIN message from the peer, indicating that they won't be sending any more data) then we
            # return immediately and don't wait for any more data.
            if flags == ReadMode.NO_WAIT or (
                sock.state == TCPState.CLOSING or 
                sock.state == TCPState.TIME_WAIT or 
                sock.state == TCPState.CLOSE_WAIT or 
                sock.state == TCPState.LAST_ACK or 
                sock.state == TCPState.CLOSED
                ):
                # The user is not willing to wait for some new data, and there isn't any available right now.
                must_wait_to_read = False
            else:
                # There isn't any data available right now, but the user wants to wait for it.
                # So, we will.
                # (This happens below; we don't need to do anything here, since must_wait_to_read is already set to True)
                pass
        
    if must_wait_to_read:
        sock.recvCond.acquire()
        sock.recvCond.wait()
            
        number_of_bytes_to_read = min((sock.window.next_byte_expected - 1) - sock.window.last_byte_read, length)
        bytes_read = sock.receivedBuf[:number_of_bytes_to_read]

        sock.receivedBuf = sock.receivedBuf[number_of_bytes_to_read:]
        for _ in range(number_of_bytes_to_read):
            sock.receivedBuf.append(None)

        sock.window.last_byte_read = sock.window.last_byte_read + number_of_bytes_to_read
        sock.window.our_advertised_window = MAX_NETWORK_BUFFER - ((sock.window.next_byte_expected - 1) - sock.window.last_byte_read)

        buf[0] = bytes(bytes_read)
        number_of_bytes_read = number_of_bytes_to_read

        sock.recvCond.release()

    return number_of_bytes_read

def case_write(sock, buf, length):
    if length < 0:
        print("ERROR negative length")
        return EXIT_ERROR
    total_data_to_send = buf[:length].encode()

    must_wait_to_write = True

    while len(total_data_to_send) > 0:

        with sock.sendLock:

            # These correspond to states in which we can be if we have not yet sent a FIN packet but we HAVE a connection with a peer,
            # meaning they are the states we can be in when we can still send data.
            can_send_data = (
                sock.state == TCPState.SYN_SENT or 
                sock.state == TCPState.LISTEN or 
                sock.state == TCPState.SYN_RCVD or 
                sock.state == TCPState.ESTABLISHED or 
                sock.state == TCPState.CLOSE_WAIT
                )

            if sock.window.last_byte_written - sock.window.last_byte_acked < MAX_NETWORK_BUFFER and can_send_data:

                number_of_bytes_available_in_buffer = MAX_NETWORK_BUFFER - (sock.window.last_byte_written - sock.window.last_byte_acked)
                first_empty_index_in_buffer = (sock.window.last_byte_written - sock.window.last_byte_acked)

                number_of_bytes_to_write_into_buffer = min(number_of_bytes_available_in_buffer, len(total_data_to_send))

                for data_to_send_index in range(number_of_bytes_to_write_into_buffer):
                    sock.sendingBuf[first_empty_index_in_buffer + data_to_send_index] = total_data_to_send[data_to_send_index]

                sock.window.last_byte_written = sock.window.last_byte_written + number_of_bytes_to_write_into_buffer
                total_data_to_send = total_data_to_send[number_of_bytes_to_write_into_buffer:]
                must_wait_to_write = False
            elif can_send_data or sock.state == TCPState.SYN_SENT or sock.state == TCPState.LISTEN:
                must_wait_to_write = True
            else:
                # can_send_data is false and we aren't in the SYN_SENT or LISTEN state, so we can no longer send any data.
                # So, we just return here.
                return

        if must_wait_to_write:
            sock.sendCond.acquire()
            sock.sendCond.wait()

            can_send_data = (
                sock.state == TCPState.SYN_RCVD or 
                sock.state == TCPState.ESTABLISHED or 
                sock.state == TCPState.CLOSE_WAIT
                )

            if sock.window.last_byte_written - sock.window.last_byte_acked < MAX_NETWORK_BUFFER and can_send_data:

                number_of_bytes_available_in_buffer = MAX_NETWORK_BUFFER - (sock.window.last_byte_written - sock.window.last_byte_acked)
                first_empty_index_in_buffer = (sock.window.last_byte_written - sock.window.last_byte_acked)

                number_of_bytes_to_write_into_buffer = min(number_of_bytes_available_in_buffer, len(total_data_to_send))

                for data_to_send_index in range(number_of_bytes_to_write_into_buffer):
                    sock.sendingBuf[first_empty_index_in_buffer + data_to_send_index] = total_data_to_send[data_to_send_index]

                sock.window.last_byte_written = sock.window.last_byte_written + number_of_bytes_to_write_into_buffer
                total_data_to_send = total_data_to_send[number_of_bytes_to_write_into_buffer:]
            elif not can_send_data and (sock.state == TCPState.SYN_SENT or sock.state == TCPState.LISTEN):
                # We can't send the data, but we don't have a connection with a peer yet.
                # So, we just wait until we do.
                pass
            elif not can_send_data:
                # can_send_data is false and we aren't in the SYN_SENT or LISTEN state, so we can no longer send any data and we return here.
                sock.sendCond.release()
                return
        
            sock.sendCond.release()

    return EXIT_SUCCESS
