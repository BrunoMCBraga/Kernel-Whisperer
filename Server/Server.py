import socket
import subprocess

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server_address = ('0.0.0.0', 5000)
sock.bind(server_address)

sock.listen(1000)

while True:
    connection, client_address = sock.accept()
    try:
        while True:
            data = connection.recv(4096)
            unicode_data = data.decode('utf-8')
            print(unicode_data)
            result = subprocess.check_output(['mysql','-u', 'root', '-e', unicode_data.rstrip()]) #If mysql fails, this will stop with an exception. Will keep it to debug erroneous situations.

    finally:
        connection.close()