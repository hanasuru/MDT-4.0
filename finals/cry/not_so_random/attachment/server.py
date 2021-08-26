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

class NotSoRandom:
    def __init__(self, seed):
        self.p = 0xffffffffffffffffffffffffffffff61
        assert seed < self.p
        self.a, self.b = seed, seed

    def next(self):
        self.a, self.b = pow(self.b, 0x1337, self.p), pow(self.a, 0x7331, self.p)
        return (self.a * 0x69420 + self.b) % self.p

xor = lambda a, b: bytes([a[i] ^ b[i % len(b)] for i in range(len(a))])

def user_input(s):
    inp = input(s).strip()
    assert len(inp) < 1024
    return inp

def main():
    seed = random.getrandbits(128)
    nsr = NotSoRandom(seed)
    for _ in range(3):
        opt = user_input('> ')
        if opt == '1':
            print(nsr.next())
        elif opt == '2':
            guess = int(user_input('guess: '))
            if guess == nsr.next():
                q = int.to_bytes(nsr.next(), 16, 'big')
                c = xor(FLAG[:len(FLAG)//2], q[0::2]) + xor(FLAG[len(FLAG)//2:], q[1::2])
                print(c.hex())
            else:
                print('try again...')
        else:
            break

if __name__ == '__main__':
    main()
