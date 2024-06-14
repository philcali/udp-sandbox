import asyncio
import json
import logging
import zlib
from Crypto.Cipher import AES
from Crypto.Hash import SHA256, CMAC
from base64 import b64decode, b64encode


logger = logging.getLogger(__name__)


class Channel:
    def __init__(
            self,
            name,
            addr,
            port,
            direction,
            key,
            auth=False,
            send_port=None,
            send_addr=None) -> None:
        self.name = name
        self.addr = addr
        self.port = port
        self.key = key
        self.auth = auth
        self.send_port = send_port
        self.send_addr = send_addr
        self.direction = direction

    def set_connection_future(self, on_con_lost):
        self.on_con_lost = on_con_lost
        return self

    def generate_checksum(self, data):
        checksum = zlib.crc32(data)
        return checksum

    def authenticate(self, data):
        cobj = CMAC.new(self.key.encode(), ciphermod=AES)
        cobj.update(data)
        return cobj.digest()

    def verify(self, data, mac):
        cobj = CMAC.new(self.key.encode(), ciphermod=AES)
        cobj.update(data)
        cobj.verify(mac)

    def encrypt(self, data):
        aes = AES.new(
            key=SHA256.new(self.key.encode('utf-8')).digest(),
            mode=AES.MODE_GCM
        )
        aes.update(self.name.encode('utf-8'))
        ciphertext, tag = aes.encrypt_and_digest(data)
        payload = json.dumps({
            'nonce': b64encode(aes.nonce).decode('utf-8'),
            'payload': b64encode(ciphertext).decode('utf-8'),
            'tag': b64encode(tag).decode('utf-8'),
        }).encode('utf-8')
        return b64encode(payload)

    def decrypt(self, data):
        values = json.loads(b64decode(data).decode('utf-8'))
        aes = AES.new(
            key=SHA256.new(self.key.encode('utf-8')).digest(),
            mode=AES.MODE_GCM,
            nonce=b64decode(values['nonce']),
        )
        aes.update(self.name.encode('utf-8'))
        plaintext = aes.decrypt_and_verify(
            b64decode(values['payload']),
            b64decode(values['tag'])
        )
        return plaintext

    def validate(self):
        if self.direction is None:
            raise Exception("Invalid direction specified")
        directions = ['encrypt', 'decrypt']
        if self.direction not in directions:
            raise Exception(
                f"Invalid direction: provided {self.direction}, expected {directions}")

    def connection_made(self, transport):
        logger.info(f'Channel {self.name} is connected')
        self.transport = transport

    def error_received(self, exc):
        self.on_con_lost.set_result(True)

    def connection_lost(self, exc):
        self.on_con_lost.set_result(True)

    def datagram_received(self, data, addr):
        logger.info(f'Received data from {addr} -> {self.send_addr}:{self.send_port}')
        if self.direction == 'encrypt':
            self.transport.sendto(self.encrypt(data), (self.send_addr, self.send_port))
        else:
            self.transport.sendto(self.decrypt(data), (self.send_addr, self.send_port))


class Encryptor:
    def __init__(self, channels) -> None:
        self.channels = channels

    async def run_channel(self, channel):
        logger.info(f'Running {channel.name} for {channel.direction} on {channel.addr}:{channel.port} -> {channel.send_addr}:{channel.send_port}')
        loop = asyncio.get_running_loop()

        on_con_lost = loop.create_future()
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: channel.set_connection_future(on_con_lost),
            local_addr=(channel.addr, channel.port)
        )

        try:
            await on_con_lost
        finally:
            transport.close()

    async def run(self):
        tasks = [asyncio.create_task(self.run_channel(channel)) for channel in self.channels]
        return await asyncio.gather(*tasks)
