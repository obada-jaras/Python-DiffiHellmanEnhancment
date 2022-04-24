import socket
import random
import time
import os
from sympy import *
from arc4 import ARC4


ClientSocket = socket.socket()
host = '127.0.0.1'
port = 1233


def generate_random_prime(minNum=1, maxNum=1000):
    primes = [i for i in range(minNum, maxNum) if isprime(i)]
    n = random.choice(primes)
    return n


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


def socket_send(message):
    ClientSocket.send(str.encode(str(message)))


def socket_receive():
    return ClientSocket.recv(1024).decode('utf-8')


def exchange_keys(send):
    time.sleep(0.1)
    socket_send(send)

    return int(socket_receive())


# public key (+ 4 so if it's 0 it doesn't ruin the rest of the algorithm)
def generate_public_key(number, power, mod):
    return (number ** power) % mod + 4


def round(shared_key):
    primRoot = primitiveRoot(shared_key)
    randomNum = random_number(50)

    publicKey1 = generate_public_key(primRoot, randomNum, shared_key)
    received_publicKey = exchange_keys(publicKey1)

    publicKey2 = generate_public_key(received_publicKey, randomNum, shared_key)

    return publicKey2


def main():
    try:
        ClientSocket.connect((host, port))
    except socket.error as e:
        print(str(e))
    print('Waiting for connection')

    p = generate_random_prime()
    socket_send(p)

    round1_key = round(p)
    round2_key = round(round1_key)
    round3_key = round(round2_key + round1_key)

    # Enhancement
    k = random_number(1000)
    U = round3_key

    Y = U * k
    X = exchange_keys(Y)

    finalKey = X if Y == 0 else Y if X == 0 else X*Y

    print('X: ' + str(X))
    print('Y: ' + str(Y))
    print('Final Key: ' + str(finalKey))
    print('\n\n-----| Conversation starts here |-----')

    while true:
        cipher = ARC4(str(finalKey))

        data = input('Type Message: ')
        ciphertext = cipher.encrypt(data)
        ClientSocket.send(ciphertext)
        print("\nWaiting for a message from the server...")

        data = ClientSocket.recv(2048)
        plaintext = cipher.decrypt(data)
        print("Message Received: " + str(plaintext)[2:-1])

    ClientSocket.close()


if __name__ == "__main__":
    main()
