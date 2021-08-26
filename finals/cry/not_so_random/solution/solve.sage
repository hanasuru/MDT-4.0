#!/usr/bin/sage
from pwn import *

from server import NotSoRandom

# r = process('./server.py', level='warn')
r = remote('localhost', 30002, level='warn')
r.sendlineafter(b'> ', b'1')
r.sendlineafter(b'> ', b'1')
s2 = Integer(r.recvline(0).decode())

p = 0xffffffffffffffffffffffffffffff61
P = GF(p)

sama = P(s2) / (0xf04e + 1)
seed = sama.nth_root(0x7295 * 0x7827)
seed = Integer(seed)
print(f'seed: {seed}')

nsr = NotSoRandom(seed)
calc_s1 = nsr.next(); print(f'state 1: {calc_s1}')
calc_s2 = nsr.next(); print(f'state 2: {calc_s2}')
calc_s3 = nsr.next(); print(f'state 3: {calc_s3}')
calc_s4 = nsr.next(); print(f'state 4: {calc_s4}')

r.sendlineafter(b'> ', b'2')
r.sendlineafter(b'guess: ', str(calc_s3).encode())
enc = bytes.fromhex(r.recvline(0).decode())

q = int.to_bytes(int(calc_s4), 16, 'big')
FLAG = xor(enc[:len(enc)//2], q[0::2]) + xor(enc[len(enc)//2:], q[1::2])
print(FLAG.decode())
