import socket
import os
import time
from _thread import *
from sympy import *
from arc4 import ARC4


ServerSocket = socket.socket()
host = '127.0.0.1'
port = 1233


def primitiveRoot(number):
    if number < 4:
        number += 4

    while not isprime(number):
        number += 1

    for i in range(2, number - 1):
        x = []
        found = True
        for j in range(0, number - 1):
            prim = (i ** j) % number
            if prim in x:
                found = False
                break
            else:
                x.append(prim)

        if found:
            return i
    return -1


# secure random number
def random_number(maxN):
    return (int.from_bytes(os.urandom(1), "big")) % maxN


def socket_send(connection, message):
    connection.sendall(str.encode(str(message)))


def socket_receive(connection):
    return connection.recv(2048).decode('utf-8')


def exchange_keys(connection, send):
    received = int(socket_receive(connection))
    time.sleep(0.1)
    socket_send(connection, send)

    return received


# public key (+ 4 so if it's 0 it doesn't ruin the rest of the algorithm)
def generate_public_key(number, power, mod):
    return (number ** power) % mod + 4


def round(connection, shared_key):
    primRoot = primitiveRoot(shared_key)
    randomNum = random_number(50)

    publicKey1 = generate_public_key(primRoot, randomNum, shared_key)
    received_publicKey = exchange_keys(connection, publicKey1)

    publicKey2 = generate_public_key(received_publicKey, randomNum, shared_key)

    return publicKey2


def threaded_client(connection):
    p = int(socket_receive(connection))

    round1_key = round(connection, p)
    round2_key = round(connection, round1_key)
    round3_key = round(connection, round2_key + round1_key)

    # Enhancement
    j = random_number(1000)
    U = round3_key

    X = U * j
    Y = exchange_keys(connection, X)

    finalKey = X if Y == 0 else Y if X == 0 else X * Y

    print('X: ' + str(X))
    print('Y: ' + str(Y))
    print('Final Key: ' + str(finalKey))
    print('\n\n-----| Conversation starts here |-----')

    while true:
        cipher = ARC4(str(finalKey))

        print("\nWaiting for a message from the client...")
        data = connection.recv(2048)
        plaintext = cipher.decrypt(data)
        print("Message Received: " + str(plaintext)[2:-1])

        data = input('Type Message: ')
        ciphertext = cipher.encrypt(data)
        connection.send(ciphertext)
    connection.close()


try:
    ServerSocket.bind((host, port))
except socket.error as e:
    print(str(e))

print('Waiting for a Connection..')
ServerSocket.listen(5)

while True:
    Client, address = ServerSocket.accept()
    start_new_thread(threaded_client, (Client,))
