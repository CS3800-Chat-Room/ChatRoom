import rsa
import socket
import threading
from datetime import datetime
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

HOST = '192.168.4.113'
PORT = 9090

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))

# rsa setup (server keys)
public_key, __private_key = rsa.newkeys(1024)
key_chain = []

# aes setup (session key)
salt = get_random_bytes(32)
password = "CS 3800 - Hidden Hermits"   # can be randomly generated string
aes_key = PBKDF2(password, salt, dkLen=32)

server.listen()

clients = []
nicknames = []


# broadcast
def broadcast(message):
    text = aes_encrypt(message)
    for i in range(len(clients)):
        clients[i].send(text)


def handle(client):
    while True:
        try:
            message = aes_decrypt(client.recv(1024))
            now = datetime.now()
            current_time = now.strftime("%I:%M %p")
            message = ("[" + current_time + "] " + message)

            print(f"{current_time} {nicknames[clients.index(client)]} says {message}")
            broadcast(message)
        except:
            index = clients.index(client)
            clients.remove(client)
            client.close()
            nickname = nicknames[index]
            broadcast(f"\nUser {nickname.strip()} left the chat \n")
            nicknames.remove(nickname)
            key = key_chain[index]
            key_chain.remove(key)
            break


# receive
def receive():
    while True:
        client, address = server.accept()
        print(f"Connected with {str(address)}!")

        # rsa setup (client keys)
        client.send(public_key.save_pkcs1("PEM"))
        key_chain.append(rsa.PublicKey.load_pkcs1(client.recv(1024)))

        # aes send key
        client.send(rsa.encrypt(aes_key, key_chain[-1]))

        client.send(aes_encrypt("NICK"))
        nickname = aes_decrypt(client.recv(1024))

        nicknames.append(nickname)
        clients.append(client)

        print(f"Nickname of the client is \'{nickname}\'")
        broadcast(f"\n{nickname.strip()} connected to the server!\n")

        thread = threading.Thread(target=handle, args=(client,))
        thread.start()

        threading.Timer(3, display_clients, args=(client,)).start()

        display_clients(client)


def display_clients(client):
    message = "Connected to the server.\n"
    if len(nicknames) > 1:
        message += "People in this chat: "
        for i in range(len(nicknames) - 1):
            message += nicknames[i]
            if len(nicknames) >= 2 and i != len(nicknames) - 2:
                message += ", "

    client.send(aes_encrypt(message))


def aes_encrypt(out_message):
    cipher = AES.new(aes_key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(out_message.encode('utf-8'), AES.block_size))
    return cipher.iv + ciphertext


def aes_decrypt(in_message):
    iv = in_message[:16]
    text = in_message[16:]
    cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)
    plaintext = unpad(cipher.decrypt(text), AES.block_size).decode('utf-8')
    return plaintext


print("Server running...")
receive()
