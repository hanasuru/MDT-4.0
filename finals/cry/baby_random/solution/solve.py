from deom import *

# r = process('./server.py')
r = remote('localhost', 30002)

r.sendlineafter('> ', '1')
s1 = int(r.recvline(0))

r.sendlineafter('> ', '1')
s2 = int(r.recvline(0))

def next(a, b):
    p = 0xffffffffffffffc5
    xa = pow(a, 0x1337, p)
    xb = pow(b, 0x7331, p)
    return xa, xb

div_s1 = eval(os.popen('sage factorize.sage {}'.format(s1)).read())

for a in div_s1:
    b = s1 // a
    ta, tb = next(a, b)

    if ta * tb == s2:
        a, b = ta, tb
        a, b = next(a, b)
        s3 = a * b
        
        r.sendlineafter('> ', '2')
        r.sendlineafter('guess: ', str(s3))
        enc = r.recvline(0).decode('hex')

        a, b = next(a, b)
        s4 = a * b
        q = n2s(s4)
        print xor(enc, q)
        break
