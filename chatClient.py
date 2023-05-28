import datetime
import socket
import struct
import sys
import threading
import ssl

PORT = 1234
HEADER_LENGTH = 2

ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ssl_context.load_cert_chain(certfile='client1_cert.pem', keyfile='client1_key.pem')
ssl_context.set_ciphers('ECDHE-RSA-AES128-GCM-SHA256')
ssl_context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE

def receive_fixed_length_msg(sock, msglen):
    message = b''
    while len(message) < msglen:
        chunk = sock.recv(msglen - len(message))
        if chunk == b'':
            raise RuntimeError("socket connection broken")
        message = message + chunk

    return message

def receive_message(sock):
    header = receive_fixed_length_msg(sock,
                                      HEADER_LENGTH)
    message_length = struct.unpack("!H", header)[0]

    message = None
    if message_length > 0:
        message = receive_fixed_length_msg(sock, message_length)
        message = message.decode("utf-8")

    return message

def send_message(sock, message):
    encoded_message = message.encode("utf-8")

    header = struct.pack("!H", len(encoded_message))

    message = header + encoded_message
    sock.sendall(message)

def message_receiver():
    while True:
        msg_received = receive_message(sock)
        if len(msg_received) > 0:
            print("[RKchat] " + msg_received)

print("[system] connecting to chat server ...")
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock = ssl_context.wrap_socket(sock)
sock.connect(("localhost", PORT))
print("[system] connected!")

thread = threading.Thread(target=message_receiver)
thread.daemon = True
thread.start()

msgC = 0
while True:
    try:
        msg_send = input("")
        timestamp = ""
        if msgC > 0:
            now = datetime.datetime.now()
            timestamp = "["+now.strftime("%H:%M:%S")+"] "
        send_message(sock, timestamp + msg_send)
        msgC += 1
    except KeyboardInterrupt:
        sys.exit()