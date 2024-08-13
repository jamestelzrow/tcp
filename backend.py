import packet
from packet import create_packet
from tcp import ReadMode, TCPState
import socket
import select
from grading import DEFAULT_TIMEOUT, MSS, MAX_NETWORK_BUFFER
import sys
import errno
import time

from random import randrange

def handle_message(sock, pkt):
    """
    @param sock - The socket used for handling packets received
    @param pkt - The packet data received by the socket
    """
    tcpHeader = packet.CaseTCP(pkt)
    flags = tcpHeader.flags

    dst = socket.ntohs(sock.conn.sinPort)
    ackNum = socket.ntohl(tcpHeader.ackNum)
    packet_sequence_number = socket.ntohl(tcpHeader.seqNum)

    new_peer_advertised_window = socket.ntohs(tcpHeader.advWin)
    # Note: This is not used if the received packet doesn't have the ACK flag set
    packet_ack_num = None

    if (flags & packet.ACK_FLAG_MASK) and (flags & packet.FIN_FLAG_MASK):
        if sock.state == TCPState.FIN_WAIT_1 and \
        ackNum == sock.window.last_byte_sent + 1 and \
        packet_sequence_number == sock.window.last_byte_rcvd + 1:

            ack_packet_seq_num = sock.window.last_byte_sent + 1
            ack_packet_ack_num = sock.window.next_byte_expected
            ack_packet_src = sock.myPort
            ack_packet_dst = socket.ntohs(sock.conn.sinPort)
            ack_packet_advertised_window = sock.window.our_advertised_window

            msg = create_ack_pkt(
                ack_packet_seq_num,
                ack_packet_ack_num,
                ack_packet_src,
                ack_packet_dst,
                ack_packet_advertised_window,
            )

            sock.sockFd.sendto(bytes(msg), (sock.conn.sinAddr, dst))
            sock.state = TCPState.TIME_WAIT
            sock.time_wait_start = time.time()
            packet_ack_num = ackNum

        else:
            pass

    elif flags & packet.ACK_FLAG_MASK and \
    sock.state != TCPState.SYN_RCVD and \
    sock.state != TCPState.ESTABLISHED and \
    sock.state != TCPState.CLOSE_WAIT:
        # Here, we do NOT want to handle ACK packets that are acknowledging new data.
        # We can't be in the FIN_WAIT_1, FIN_WAIT_2, CLOSING, TIME_WAIT or LAST_ACK states without sending a FIN message first,
        # and we can't send a FIN message until all data that we have sent has been ACKed.
        # So, we enter this conditional in these states.
        # We do NOT enter this conditional if we are in the SYN_RCVD state; we handle that in the "else" branch of this conditional.
        # This is to avoid getting "stuck" in the SYN_RCVD state:
        # Since ACK packets aren't retransmitted, it is possible that the ACK packet for the SYN_ACK packet may be lost and thus never received
        # by the passive initiator.
        # If we refuse to leave the SYN_RCVD state until we receive exactly this ACK packet, then we would be "stuck" in it forever.
        # So, we allow movement out of the SYN_RCVD state and into the ESTABLISHED state as soon as we receive the first valid ACK packet, 
        # and we do this in the "else" branch rather than here.
        if sock.state == TCPState.SYN_SENT:
            pass
        elif sock.state == TCPState.LISTEN:
            pass
        elif sock.state == TCPState.FIN_WAIT_1:
            if ackNum == sock.window.last_byte_sent + 1:
                sock.state = TCPState.FIN_WAIT_2
                packet_ack_num = ackNum
            else:
                pass
        elif sock.state == TCPState.FIN_WAIT_2:
            pass
        elif sock.state == TCPState.TIME_WAIT:
            pass
        elif sock.state == TCPState.LAST_ACK and ackNum == sock.window.last_byte_sent + 1:
            sock.state = TCPState.CLOSED
        elif sock.state == TCPState.CLOSING and ackNum == sock.window.last_byte_sent + 1:
            sock.state = TCPState.TIME_WAIT
            sock.time_wait_start = time.time()
            packet_ack_num = ackNum
        elif sock.state == TCPState.CLOSED:
            pass

    elif flags & packet.FIN_FLAG_MASK:

        if sock.state == TCPState.SYN_SENT:
            pass
        elif sock.state == TCPState.LISTEN:
            pass
        elif sock.state == TCPState.SYN_RCVD:
            pass
        elif sock.state == TCPState.ESTABLISHED:

            ack_packet_seq_num = sock.window.last_byte_sent + 1
            ack_packet_ack_num = sock.window.next_byte_expected
            ack_packet_src = sock.myPort
            ack_packet_dst = socket.ntohs(sock.conn.sinPort)
            ack_packet_advertised_window = sock.window.our_advertised_window

            msg = create_ack_pkt(
                ack_packet_seq_num,
                ack_packet_ack_num,
                ack_packet_src,
                ack_packet_dst,
                ack_packet_advertised_window,
            )

            sock.sockFd.sendto(bytes(msg), (sock.conn.sinAddr, dst))
            sock.state = TCPState.CLOSE_WAIT

        elif sock.state == TCPState.FIN_WAIT_1:

            ack_packet_seq_num = sock.window.last_byte_sent + 1
            ack_packet_ack_num = sock.window.next_byte_expected
            ack_packet_src = sock.myPort
            ack_packet_dst = socket.ntohs(sock.conn.sinPort)
            ack_packet_advertised_window = sock.window.our_advertised_window

            msg = create_ack_pkt(
                ack_packet_seq_num,
                ack_packet_ack_num,
                ack_packet_src,
                ack_packet_dst,
                ack_packet_advertised_window,
            )

            sock.sockFd.sendto(bytes(msg), (sock.conn.sinAddr, dst))
            sock.state = TCPState.CLOSING

        elif sock.state == TCPState.FIN_WAIT_2:

            ack_packet_seq_num = sock.window.last_byte_sent + 1
            ack_packet_ack_num = sock.window.next_byte_expected
            ack_packet_src = sock.myPort
            ack_packet_dst = socket.ntohs(sock.conn.sinPort)
            ack_packet_advertised_window = sock.window.our_advertised_window

            msg = create_ack_pkt(
                ack_packet_seq_num,
                ack_packet_ack_num,
                ack_packet_src,
                ack_packet_dst,
                ack_packet_advertised_window,
            )

            sock.sockFd.sendto(bytes(msg), (sock.conn.sinAddr, dst))
            sock.state = TCPState.TIME_WAIT
            sock.time_wait_start = time.time()

        elif sock.state == TCPState.TIME_WAIT:
            pass
        elif sock.state == TCPState.CLOSE_WAIT:
            pass
        elif sock.state == TCPState.LAST_ACK:
            pass
        elif sock.state == TCPState.CLOSING:
            pass
        elif sock.state == TCPState.CLOSED:
            pass

    elif flags & packet.SYN_FLAG_MASK and sock.state == TCPState.LISTEN:
        
        syn_ack_packet_seq_num = randrange(start = 1, stop=1000)
        syn_ack_packet_ack_num = packet_sequence_number + 1
        syn_ack_packet_src = sock.myPort
        syn_ack_packet_dst = socket.ntohs(sock.conn.sinPort)
        syn_ack_packet_advertised_window = MAX_NETWORK_BUFFER

        syn_ack_packet_payload = None
        syn_ack_packet_payload_len = 0
        syn_ack_packet_extension_data = None
        syn_ack_packet_header_len = len(packet.CaseTCP())
        syn_ack_packet_len = syn_ack_packet_header_len + syn_ack_packet_payload_len
        syn_ack_packet_flags = packet.SYN_FLAG_MASK + packet.ACK_FLAG_MASK

        syn_ack_packet = create_packet(
            syn_ack_packet_src,
            syn_ack_packet_dst,
            syn_ack_packet_seq_num,
            syn_ack_packet_ack_num,
            syn_ack_packet_header_len,
            syn_ack_packet_len,
            syn_ack_packet_flags,
            syn_ack_packet_advertised_window,
            syn_ack_packet_extension_data,
            syn_ack_packet_payload,
            syn_ack_packet_payload_len
        )

        sock.window.last_byte_read = packet_sequence_number
        sock.window.last_byte_rcvd = packet_sequence_number
        sock.window.next_byte_expected = packet_sequence_number + 1

        # Ordinarily, we set last_byte_acked to one less than the ACK number.
        # (In this case, that should be one more than the sequence number of the SYN-ACK packet.)
        # Since we haven't yet received an ACK for our SYN-ACK packet, it seems as if we should set this to one less than the sequence number of our SYN-ACK packet, so that when we do receive the ACK for that packet, this would be set equal to its sequence number.
        # However, there is no actual data corresponding to the sequence number of the SYN-ACK packet.
        # Additionally, when we receive a new ACK number, begin_backend removes elements from our sending buffer.
        # These two facts cause undesired behavior.
        # For example, suppose that we do set the initial last_byte_acked value to one less than the SYN-ACK packet sequence number,
        # and suppose that we send a SYN-ACK with a seq number of 5, and then send bytes 6, 7 and 8.
        # Additionally, suppose that we have a maximum buffer size of 10.
        # Consider the following two cases:
        # Case 1: we do receive an ACK message for our SYN-ACK packet, which has an ACK number of 6.
        # Then because the ACK number of this packet is TWO more than that of the current value of last_byte_acked, we would drop ONE ((ACK_NUMBER - 1) - last_byte_acked = (6 - 1) - 4 = 1) byte from the end of the buffer.
        # This would be byte 6.
        # So if byte 6 was lost, then we wouldn't be able to retransmit it, which is a problem.
        # Case 2: we do not receive an ACK message for our SYN-ACK packet, but we do receive a packet with an ACK number of 9.
        # Then because the ACK number of this packet is FIVE more than the currrent value of last_byte_acked, we would drop FOUR ((9 - 1) - 4 = 4) bytes from the end of the buffer.
        # However, this would drop all three bytes that we have sent, plus an empty space, which is a problem.
        # 
        # last_byte_acked should always be one less than the number of the first byte in the buffer.
        # Additionally, according to the TCP specification, we may not receive this ACK at all.
        # So, here we just set the last_byte_acked to the sequence number of the SYN-ACK packet.
        sock.window.last_byte_acked = syn_ack_packet_seq_num 
        sock.window.last_byte_written = syn_ack_packet_seq_num
        sock.window.last_byte_sent = syn_ack_packet_seq_num

        sock.window.our_advertised_window = MAX_NETWORK_BUFFER
        sock.window.peer_advertised_window = new_peer_advertised_window

        sock.state = TCPState.SYN_RCVD

        sock.sendingBuf = []
        sock.receivedBuf = []
        for _ in range(MAX_NETWORK_BUFFER):
            sock.sendingBuf.append(None)
            sock.receivedBuf.append(None)

        sock.sockFd.sendto(bytes(syn_ack_packet), (sock.conn.sinAddr, dst))

    else:

        if flags & packet.ACK_FLAG_MASK:
            packet_ack_num = ackNum

        payload = tcpHeader[packet.CaseTCP].payload
        payload_length = len(payload)

        if payload_length > 0:
            if (sock.window.next_byte_expected - 1) - sock.window.last_byte_read < MAX_NETWORK_BUFFER:

                if packet_sequence_number <= sock.window.last_byte_read + MAX_NETWORK_BUFFER and packet_sequence_number + payload_length > sock.window.next_byte_expected:
                    # The sequence number is before the end of our receiving buffer, and the number of the final byte is after that of the last byte we received.
                    # So, this packet contains data within the range of our buffer.
                    payload_subset_start_idx = max(packet_sequence_number, sock.window.next_byte_expected)-packet_sequence_number
                    payload_subset_end_idx = min(packet_sequence_number+payload_length, sock.window.last_byte_read + MAX_NETWORK_BUFFER)-packet_sequence_number
                    payload_subset_to_accept = bytes(payload[payload_subset_start_idx:payload_subset_end_idx])

                    rcv_buff_starting_index_for_copy = max(packet_sequence_number, sock.window.next_byte_expected) - (sock.window.last_byte_read + 1)

                    for payload_subset_idx in range(len(payload_subset_to_accept)):
                        sock.receivedBuf[rcv_buff_starting_index_for_copy + payload_subset_idx] = payload_subset_to_accept[payload_subset_idx]
                    if len(payload_subset_to_accept) > 0:
                        # We have received some new data, so we should notify in case the application layer is waiting on it.
                        sock.recvCond.notify()

                    if packet_sequence_number <= sock.window.next_byte_expected:
                        new_next_byte_expected = sock.window.next_byte_expected
                        # Iterate through the receiving buffer beginning at the byte numbered sock.window.next_byte_expected and search for the first None value
                        # (We know we have already received every byte with a number less than sock.window.next_byte_expected)
                        for rcv_buffer_idx in range(sock.window.next_byte_expected - (sock.window.last_byte_read + 1), MAX_NETWORK_BUFFER):
                            if sock.receivedBuf[rcv_buffer_idx] != None:
                                new_next_byte_expected = new_next_byte_expected + 1
                            else:
                                break
                        sock.window.next_byte_expected = new_next_byte_expected

                    if packet_sequence_number + payload_length - 1 > sock.window.last_byte_rcvd:
                        sock.window.last_byte_rcvd = packet_sequence_number + payload_length - 1

                    sock.window.our_advertised_window = MAX_NETWORK_BUFFER - ((sock.window.next_byte_expected - 1) - sock.window.last_byte_read)

                else:
                    # The payload lies outside the range that we can accept in our receiving buffer.
                    pass

            else:
                # Our receiving buffer is full, so we do nothing with this packet's payload.
                pass

            # It is safe for us to read the peer_advertised_window here without obtaining the sendLock because it only gets written in this thread.
            if sock.window.last_byte_written > sock.window.last_byte_sent and (sock.state == TCPState.ESTABLISHED or sock.state == TCPState.CLOSE_WAIT) and sock.window.peer_advertised_window > 0:
                # The peer can still receive data, and we also have some data to send to the peer.
                # So rather than sending a packet that is just an ack message in response to this packet we have just received, we will ack with a packet containing some data we have to send.
                pass
            else:
                # We don't know if we will send another data packet to the peer, so we send an ack in response immediately.
                ack_packet_seq_num = sock.window.last_byte_acked + 1
                ack_packet_ack_num = sock.window.next_byte_expected
                ack_packet_src = sock.myPort
                ack_packet_dst = socket.ntohs(sock.conn.sinPort)
                ack_packet_advertised_window = sock.window.our_advertised_window

                ack_packet = create_ack_pkt(
                    ack_packet_seq_num,
                    ack_packet_ack_num,
                    ack_packet_src,
                    ack_packet_dst,
                    ack_packet_advertised_window,
                )
                
                sock.sockFd.sendto(bytes(ack_packet), (sock.conn.sinAddr, ack_packet_dst))
        else:
            # We didn't get any payload, so we don't need to fill our receive buffer or ack anything.
            pass

    return new_peer_advertised_window, packet_ack_num

def check_for_data(sock, flags):
    """
    Checks if the socket received any data.

    @param sock - The socket used for receiving data on the connection.
    @param flags - Flags that determine how the socket should wait for data. 
    """
    unknown_flag = True
    msg = ""
    events = []
    new_peer_advertised_window, packet_ack_num = None, None
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

        new_peer_advertised_window, packet_ack_num = handle_message(sock, pkt)
    sock.recvLock.release()
    return new_peer_advertised_window, packet_ack_num

def send_as_packets(buffer_subset_start_index, buffer_subset_end_index, sock, our_advertised_window):
    packet_seq_num = sock.window.last_byte_acked + buffer_subset_start_index + 1
    full_payload = sock.sendingBuf[buffer_subset_start_index:buffer_subset_end_index]
    full_extension_data = None
    packet_src = sock.myPort
    packet_dst = socket.ntohs(sock.conn.sinPort)
    packet_ack_num = sock.window.next_byte_expected
    packet_header_len = len(packet.CaseTCP())
    packet_flags = packet.ACK_FLAG_MASK
    packet_advertised_window = our_advertised_window
    
    while len(full_payload) != 0:
        packet_end_index = min(len(full_payload), MSS)
        packet_payload = full_payload[0:packet_end_index]

        packet_to_send = create_packet(
            packet_src,
            packet_dst,
            packet_seq_num,
            packet_ack_num,
            packet_header_len,
            packet_header_len + len(packet_payload),
            packet_flags,
            packet_advertised_window,
            full_extension_data,
            bytes(packet_payload),
            len(packet_payload)
        )

        sock.sockFd.sendto(bytes(packet_to_send), (sock.conn.sinAddr, packet_dst))

        packet_seq_num = packet_seq_num + len(packet_payload)
        full_payload = full_payload[packet_end_index:]

# Update this to send some data if the timeout is hit, even if the advertised window is zero
def send(sock, our_advertised_window):
    """
    Breaks up the data into packets and sends a single packet at a time. 

    @param sock - The socket used for sending data
    """

    # If we have some new data to send and the peer's advertised window is not zero, we're going to send as much unsent data as we can, regardless of whether or not we're also going to resend some data as a result of an ACK timeout.
    effective_window = sock.window.peer_advertised_window - (sock.window.last_byte_sent - sock.window.last_byte_acked)
    did_timeout = time.time() - sock.window.time_since_last_new_ack_or_retrans >= DEFAULT_TIMEOUT and sock.window.last_byte_sent > sock.window.last_byte_acked
    can_send_unsent_data = effective_window > 0 and sock.window.last_byte_written > sock.window.last_byte_sent

    # 4 cases here:
    # 1: We have some unsent data and the effective window is nonzero, and we are NOT resending due to a timeout.
    # 2: We have some unsent data and the effective window is nonzero, and we ARE resending due to a timeout.
    # 3: We don't have any unsent data OR the effective window is zero, and we ARE resending due to a timeout.
    # 4: Else case, in which we do nothing.

    if can_send_unsent_data and not did_timeout:
        buffer_subset_start_index = sock.window.last_byte_sent - sock.window.last_byte_acked
        buffer_subset_end_index = min((sock.window.last_byte_sent + effective_window) - sock.window.last_byte_acked, sock.window.last_byte_written - sock.window.last_byte_acked)
        send_as_packets(
            buffer_subset_start_index,
            buffer_subset_end_index,
            sock,
            our_advertised_window
        )
        sock.window.last_byte_sent = min(sock.window.last_byte_sent + effective_window, sock.window.last_byte_written)
    elif can_send_unsent_data and did_timeout:
        buffer_subset_start_index = 0 # One byte after the last byte acked
        buffer_subset_end_index = min((sock.window.last_byte_sent + effective_window) - sock.window.last_byte_acked, sock.window.last_byte_written - sock.window.last_byte_acked)
        send_as_packets(
            buffer_subset_start_index,
            buffer_subset_end_index,
            sock,
            our_advertised_window
        )
        sock.window.last_byte_sent = min(sock.window.last_byte_sent + effective_window, sock.window.last_byte_written)
        sock.window.time_since_last_new_ack_or_retrans = time.time()
    elif not can_send_unsent_data and did_timeout:
        buffer_subset_start_index = 0
        buffer_subset_end_index = min(MAX_NETWORK_BUFFER, sock.window.last_byte_sent - sock.window.last_byte_acked)
        send_as_packets(
            buffer_subset_start_index,
            buffer_subset_end_index,
            sock,
            our_advertised_window
        )
        # We are strictly retransmitting here, so we don't need to update our last_byte_sent value
        sock.window.time_since_last_new_ack_or_retrans = time.time()
    else:
        pass

def begin_backend(sock):
    while True:
        with sock.recvLock:
            our_advertised_window = sock.window.our_advertised_window

        with sock.deathLock:
            death = sock.dying

        with sock.sendLock:
            # Don't close the socket until all the data we have written has been ACKed.
            if death == 1 and sock.window.last_byte_written <= sock.window.last_byte_acked:

                fin_packet_seq_num = sock.window.last_byte_sent + 1
                fin_packet_ack_num = sock.window.next_byte_expected
                fin_packet_src = sock.myPort
                fin_packet_dst = socket.ntohs(sock.conn.sinPort)
                fin_packet_advertised_window = our_advertised_window

                fin_packet = create_fin_pkt(
                    fin_packet_seq_num,
                    fin_packet_ack_num,
                    fin_packet_src,
                    fin_packet_dst,
                    fin_packet_advertised_window,
                )

                if sock.state == TCPState.SYN_SENT or \
                    sock.state == TCPState.LISTEN or \
                    sock.state == TCPState.SYN_RCVD or \
                    sock.state == TCPState.ESTABLISHED:

                    sock.sockFd.sendto(bytes(fin_packet), (sock.conn.sinAddr, fin_packet_dst))
                    sock.state = TCPState.FIN_WAIT_1
                    sock.packet_sent_timestamp = time.time()

                elif sock.state == TCPState.FIN_WAIT_1:

                    if time.time() - sock.packet_sent_timestamp >= DEFAULT_TIMEOUT:
                        sock.sockFd.sendto(bytes(fin_packet), (sock.conn.sinAddr, fin_packet_dst))
                        sock.packet_sent_timestamp = time.time()
                    else:
                        pass

                elif sock.state == TCPState.FIN_WAIT_2:
                    pass
                elif sock.state == TCPState.TIME_WAIT:

                    if time.time() - sock.time_wait_start >= 2 * DEFAULT_TIMEOUT:
                        sock.state = TCPState.CLOSED
                    else:
                        pass

                elif sock.state == TCPState.CLOSE_WAIT:

                    sock.sockFd.sendto(bytes(fin_packet), (sock.conn.sinAddr, fin_packet_dst))
                    sock.state = TCPState.LAST_ACK
                    sock.packet_sent_timestamp = time.time()

                elif sock.state == TCPState.LAST_ACK:

                    if time.time() - sock.packet_sent_timestamp >= DEFAULT_TIMEOUT:
                        sock.sockFd.sendto(bytes(fin_packet), (sock.conn.sinAddr, fin_packet_dst))
                        sock.packet_sent_timestamp = time.time()
                    else:
                        pass

                elif sock.state == TCPState.CLOSING:

                    if time.time() - sock.packet_sent_timestamp >= DEFAULT_TIMEOUT:
                        sock.sockFd.sendto(bytes(fin_packet), (sock.conn.sinAddr, fin_packet_dst))
                        sock.packet_sent_timestamp = time.time()
                    else:
                        pass

                elif sock.state == TCPState.CLOSED:
                    break

            elif sock.state == TCPState.SYN_RCVD or sock.state == TCPState.ESTABLISHED or sock.state == TCPState.CLOSE_WAIT:
                # We only allow sending data if we have a connection with a peer, and we have not yet sent a FIN packet to that peer.
                send(sock, our_advertised_window)

        new_peer_advertised_window, packet_ack_num = check_for_data(sock, ReadMode.NO_WAIT)
        with sock.sendLock:
            if new_peer_advertised_window != None:
                # We got a packet with an advertised window size in it, so we update our copy of the peer's advertised window here
                sock.window.peer_advertised_window = new_peer_advertised_window
            else:
                pass

            if packet_ack_num != None:
                # We got a packet with the ACK flag set.
                # Recall: the ack number in the packet is the next byte that the peer WANTS to receive, but last_byte_acked is the number of the last byte that the peer HAS received.
                # (Or at least has told us they have received.)
                if packet.after(packet_ack_num, sock.window.last_byte_acked + 1):
                    # We got an ACK number after the last one we received, so we update the necessary values and flush the appropriate number of bytes from the buffer
                    old_last_byte_acked = sock.window.last_byte_acked
                    sock.window.last_byte_acked = packet_ack_num - 1
                    num_bytes_to_flush_from_send_buff = sock.window.last_byte_acked - old_last_byte_acked
                    sock.sendingBuf = sock.sendingBuf[num_bytes_to_flush_from_send_buff:]
                    for _ in range(0, num_bytes_to_flush_from_send_buff):
                        sock.sendingBuf.append(None)
                    sock.window.time_since_last_new_ack_or_retrans = time.time()
                    sock.sendCond.notify()
                    # Here we handle the case in which the ACK message for our SYN_ACK packet was dropped, but we received a subsequent ACK message.
                    if sock.state == TCPState.SYN_RCVD:
                        sock.state = TCPState.ESTABLISHED
                elif packet_ack_num == sock.window.last_byte_acked + 1 and sock.state == TCPState.SYN_RCVD:
                    # We have just received the ACK packet for our SYN_ACK packet, so we move from the SYN_RCVD state to the ESTABLISHED state
                    sock.state = TCPState.ESTABLISHED

    sys.exit(0)

def did_timeout(time_last_sent):
    if time.time() - time_last_sent > DEFAULT_TIMEOUT:
        return True
    else:
        return False
    
def create_ack_pkt(seq_num, ack_num, src, dst, advertised_window):

    ack_packet_payload = None
    ack_packet_payload_len = 0
    ack_packet_extension_data = None
    ack_packet_header_len = len(packet.CaseTCP())
    ack_packet_len = ack_packet_header_len + ack_packet_payload_len
    ack_packet_flags = packet.ACK_FLAG_MASK

    ack_packet = create_packet(
        src,
        dst,
        seq_num,
        ack_num,
        ack_packet_header_len,
        ack_packet_len,
        ack_packet_flags,
        advertised_window,
        ack_packet_extension_data,
        ack_packet_payload,
        ack_packet_payload_len
    )

    return ack_packet

def create_fin_pkt(seq_num, ack_num, src, dst, advertised_window):

    fin_packet_payload = None
    fin_packet_payload_len =  0
    fin_packet_extension_data = None
    fin_packet_header_len = len(packet.CaseTCP())
    fin_packet_len = fin_packet_header_len + fin_packet_payload_len
    fin_packet_flags = packet.FIN_FLAG_MASK

    fin_packet = create_packet(
        src,
        dst,
        seq_num,
        ack_num,
        fin_packet_header_len,
        fin_packet_len,
        fin_packet_flags,
        advertised_window,
        fin_packet_extension_data,
        fin_packet_payload,
        fin_packet_payload_len
    )

    return fin_packet