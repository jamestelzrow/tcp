from tcp import ReadMode, Socket, SocketType
from tcpSock import * 
import time
import os
import sys


BUF_SIZE = 10000

def functionality(sock):
    buf = [b""]
    n = case_read(sock, buf, BUF_SIZE, ReadMode.NO_FLAG)
    print("R: ", buf[0])
    print("N: ", n)
    case_write(sock, "hi there", 8)
    buf = [b""]
    n = case_read(sock, buf, 200, ReadMode.NO_FLAG)
    print("2R: ", buf[0])
    print("2N: ", n)
    case_write(sock, "https://www.youtube.com/watch?v=dQw4w9WgXcQ", 43)

    time.sleep(1)
    n = case_read(sock, buf, BUF_SIZE, ReadMode.NO_FLAG)
    print("N: ", n)
    fp = open("/tmp/file.py", "w")
    fp.write(buf[0].decode())
    fp.close()

def main():
    serverIP = os.getenv('server325', '127.0.0.1')
    serverPort = os.getenv('serverport325', "3425")
    portNo = int(serverPort)
    sock = Socket()
    if case_socket(sock, SocketType.TCP_LISTENER, portNo, serverIP) < 0:
        sys.exit(EXIT_FAILURE)

    functionality(sock)

    if case_close(sock) < 0:
        sys.exit(EXIT_FAILURE)

    return EXIT_SUCCESS

if __name__ == '__main__':
    main()
