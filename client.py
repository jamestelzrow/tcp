from tcp import ReadMode, Socket, SocketType
from tcpSock import *
import array
import sys
import os

def functionality(sock):
    buf = [b""]
    case_write(sock, "hi there", 8)
    case_write(sock, "https://www.youtube.com/watch?v=dQw4w9WgXcQ", 43)
    case_write(sock, "https://www.youtube.com/watch?v=Yb6dZ1IFlKc", 43)
    case_write(sock, "https://www.youtube.com/watch?v=xvFZjo5PgG0", 43)
    case_write(sock, "https://www.youtube.com/watch?v=8ybW48rKBME", 43)
    case_write(sock, "https://www.youtube.com/watch?v=xfr64zoBTAQ", 43)
    case_read(sock, buf, 200, ReadMode.NO_FLAG)

    print("receive: ", buf[0])
    case_write(sock, "hi there", 8)
    case_read(sock, buf, 200, ReadMode.NO_FLAG)
    print("R: ", buf[0])

    read = case_read(sock, buf, 200, ReadMode.NO_WAIT)
    print("Read: ", read)

    fp = open("./tcp.py", "rb")
    read = 1
    a = array.array("B")
    while read > 0:
        try:
            a.fromfile(fp, 20)
        except Exception as e:
            pass
        read = len(a)
        if read > 0:
            case_write(sock, a.tobytes().decode(), read)
            del a[:]
    fp.close()

def main():
    serverIP = os.getenv('server325', '127.0.0.1')
    serverPort = os.getenv('serverport325', "3425")
    portNo = int(serverPort)

    sock = Socket()
    if case_socket(sock, SocketType.TCP_INITIATOR, portNo, serverIP) < 0:
        sys.exit(EXIT_FAILURE)

    functionality(sock)

    if case_close(sock) < 0:
        sys.exit(EXIT_FAILURE)

    return EXIT_SUCCESS

if __name__ == '__main__':
    main()
