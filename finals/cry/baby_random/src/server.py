#!/usr/bin/env python3
import random
import sys

class Unbuffered(object):
    def __init__(self, stream):
        self.stream = stream
    def write(self, data):
        self.stream.write(data)
        self.stream.flush()
    def writelines(self, datas):
        self.stream.writelines(datas)
        self.stream.flush()
    def __getattr__(self, attr):
        return getattr(self.stream, attr)

sys.stdout = Unbuffered(sys.stdout)

FLAG = open('flag.txt', 'rb').read()

class BabyRandom:
    def __init__(self):
        self.p = 0xffffffffffffffc5
        self.a = random.randrange(self.p - 1)
        self.b = random.randrange(self.p - 1)

    def next(self):
        self.a = pow(self.a, 0x1337, self.p)
        self.b = pow(self.b, 0x7331, self.p)
        return self.a * self.b

xor = lambda a, b: bytes([a[i] ^ b[i % len(b)] for i in range(len(a))])

def user_input(s):
    inp = input(s).strip()
    assert len(inp) < 1024
    return inp

def main():
    br = BabyRandom()
    for _ in range(3):
        opt = user_input('> ')
        if opt == '1':
            print(br.next())
        elif opt == '2':
            guess = int(user_input('guess: '))
            if guess == br.next():
                q = int.to_bytes(br.next(), 16, 'big')
                c = xor(FLAG, q)
                print(c.hex())
            else:
                print('try again...')
        else:
            break

if __name__ == '__main__':
    main()
