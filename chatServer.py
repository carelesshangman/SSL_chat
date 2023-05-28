import ssl
import signal
signal.signal(signal.SIGINT, signal.SIG_DFL)
import socket
import struct
import threading

PORT = 1234
HEADER_LENGTH = 2

ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ssl_context.load_cert_chain(certfile='server_cert.pem', keyfile='server_key.pem')
ssl_context.set_ciphers('ECDHE-RSA-AES128-GCM-SHA256')
ssl_context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1

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

usernames = []

def client_thread(client_sock, client_addr):
    global clients
    global usernames

    send_message(client_sock, "Enter your username:")
    username = receive_message(client_sock)
    usernames.append((username, client_sock))
    print("[system] connected with " + client_addr[0] + ":" + str(client_addr[1]) + " as " + username)
    print("[system] we now have " + str(len(clients)) + " clients")

    try:

        while True:
            msg_received = receive_message(client_sock)

            if not msg_received:
                break

            if (msg_received.split(" ")[1] == '/whisper' or msg_received.split(" ")[1] == '/w') and len(msg_received.split(" ")) >= 4:
                timestamp = msg_received.split(" ")[0]
                sendTo = msg_received.split(" ")[2]
                textBlob = msg_received.split(" ")[3:]
                flagRecipient = False
                for sendToUsername, client_socket in usernames:
                    if sendToUsername == sendTo:
                        flagRecipient = True
                        result = ' '.join(textBlob)
                        send_message(client_socket, f"{timestamp} [{username}]->[{sendToUsername}]: {result}")
                        send_message(client_sock, f"{timestamp} [{username}]->[{sendToUsername}]: {result}")
                if flagRecipient == False:
                    send_message(client_sock, f"{timestamp} [System]: User '{sendTo}' not found.")
                continue

            msg_with_username = "[" + username + "] " + msg_received

            print("[RKchat] " + msg_with_username)

            for client in clients:
                send_message(client, msg_with_username.upper())
    except:

        pass

    with clients_lock:
        clients.remove(client_sock)
    print("[system] we now have " + str(len(clients)) + " clients")
    client_sock.close()

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket = ssl_context.wrap_socket(server_socket, server_side=True)
server_socket.bind(("localhost", PORT))
server_socket.listen(1)

print("[system] listening ...")
clients = set()
clients_lock = threading.Lock()
while True:
    try:

        client_sock, client_addr = server_socket.accept()
        with clients_lock:
            clients.add(client_sock)

        thread = threading.Thread(target=client_thread, args=(client_sock, client_addr));
        thread.daemon = True
        thread.start()

    except KeyboardInterrupt:
        break

print("[system] closing server socket ...")
server_socket.close()