from scapy.all import *
import socket
import struct

class CaseTCP(Packet):
    oName = "Case TCP Header"

    fields_desc = [
            IntField("identifier", 0),
            ShortField("sport", 0),
            ShortField("dport", 0),
            IntField("seqNum", 0),
            IntField("ackNum", 0),
            ShortField("hLen", 0),
            ShortField("pLen", 0),
            ByteField("flags", 0),
            ShortField("advWin", 0),
            FieldLenField("extLen", None, length_of="extData", fmt="!H"),
            StrLenField("extData", "", length_from = lambda pkt:pkt.extLen)
    ]


SYN_FLAG_MASK = 0x8
ACK_FLAG_MASK = 0x4
FIN_FLAG_MASK = 0x2
IDENTIFIER = 3425

def create_packet(src, dst, seq, ack, hLen, pLen, flags, advWin, extData, payload, payloadLen):
    if hLen < len(CaseTCP()):
        return None
    if pLen < hLen:
        return None

    pH = CaseTCP()  
    pH.identifier = socket.htonl(IDENTIFIER)
    pH.sport = socket.htons(src)
    pH.dport = socket.htons(dst)
    pH.seqNum = socket.htonl(seq)
    pH.ackNum = socket.htonl(ack)
    pH.hLen = socket.htons(hLen)
    pH.pLen = socket.htons(pLen)
    pH.flags = flags
    pH.advWin = socket.htons(advWin)
    if extData is not None:
        pH.extData = extData
        pH.extLen = socket.htons(len(extData))
    if payload is not None:
        return pH / payload[:payloadLen]
    else:
        return pH

def before(seq1, seq2):
    if seq1 < seq2:
        return True
    return False

def after(seq1, seq2):
    return before(seq2, seq1)

def between(seq, low, high):
    if high - low >= seq - low:
        return True
    return False
