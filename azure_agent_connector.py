import socket

HOST = '127.0.0.1'
PORT = 514


def send_sentinel_data(records):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        for record in records:
            s.sendall(bytes(record))

        s.close()
