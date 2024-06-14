import argparse
import asyncio
import logging
import struct
import sys
import time
from math import floor
from uuid import uuid4
from udp import set_stream_logger
from udp.channel import Channel


logger = logging.getLogger(__name__)


class ReceiveChannel(Channel):
    def datagram_received(self, data, addr):
        logger.info(f'Data received from {addr}')
        udp_header = data[:16]
        udp_header_struct = struct.unpack("!IIII", udp_header)
        ptu_header = data[16:32]
        ptu_header_struct = struct.unpack("!IccchxhI", ptu_header)
        if self.auth:
            output = data[32:-16]
            mac = data[32 + len(output):]
            self.verify(ptu_header + output, mac)
        else:
            output = data[32:]
        checksum = self.generate_checksum(output)
        if checksum != udp_header_struct[3]:
            logger.warning(f'Recevied corrupted UDP data')
        checksum = self.generate_checksum(ptu_header[:-4])
        if checksum != ptu_header_struct[-1]:
            logger.warning(f'Received corrupted PTU data')
        if self.direction == 'encrypt':
            output = self.decrypt(data)
        logger.info(f'Data received was "{output.decode()}"')


class SendChannel(Channel):
    def generate_message_data(self):
        return f'Channel message {uuid4()} from {self.name} on {floor(time.time())}'.encode('utf-8')

    def generate_udp_header(self, data):
        udp_checksum = self.generate_checksum(data)
        length = len(data)
        return struct.pack("!IIII", self.port + 1, self.port, length, udp_checksum)

    def generate_ptu_header(self, data):
        ptu_header_sans_crc = struct.pack(
            "!Iccchxh",
            1234,
            b'\x0f',
            b'\x0f',
            b'\x0f' if self.auth else b'\x00',
            len(data),
            1337
        )
        crc = self.generate_checksum(ptu_header_sans_crc)
        return ptu_header_sans_crc + struct.pack("!I", crc)

    def post_at_interval(self):
        while not self.transport.is_closing():
            data = self.generate_message_data()
            logger.info(f'Sending {data.decode()}')
            if self.direction == 'encrypt':
                data = self.encrypt(data)
            try:
                udp_header = self.generate_udp_header(data)
                ptu_data = self.generate_ptu_header(data) + data
                packet = udp_header + ptu_data
                if self.auth:
                    packet += self.authenticate(ptu_data)
                self.transport.sendto(packet, (self.addr, self.port))
                time.sleep(self.delay)
            except Exception as e:
                logger.warning(f'Failed to send message {e}', exc_info=e)

    def connection_made(self, transport):
        super().connection_made(transport)
        asyncio.to_thread(self.post_at_interval())


async def run_channel(function, channel):
    loop = asyncio.get_running_loop()

    on_con_lost = loop.create_future()
    kwargs = {}
    if function == 'send':
        kwargs['remote_addr'] = (channel.addr, channel.port)
        kwargs['local_addr'] = (channel.addr, channel.port + 1)
    else:
        kwargs['local_addr'] = (channel.addr, channel.port)

    transport, protocol = await loop.create_datagram_endpoint(
        lambda: channel.set_connection_future(on_con_lost),
        **kwargs,
    )

    try:
        await on_con_lost
    finally:
        transport.close()


def _create_parser():
    parser = argparse.ArgumentParser(
        f"{__package__.replace('.', '-')}",
        description=f"Example UDP {__package__.split('.')[-1]} application"
    )
    parser.add_argument(
        "--channel-name",
        help="name of the channel",
        required=True,
    )
    parser.add_argument(
        "--channel-key",
        help="secret key for the channel",
        required=True
    )
    parser.add_argument(
        "--channel-port",
        help="port of the channel",
        type=int,
        required=True,
    )
    parser.add_argument(
        "--channel-direction",
        help="direction of the channel, encrypt or decrypt",
        required=True
    )
    parser.add_argument(
        "--channel-function",
        help="function of the client, send or receive",
        default="receive",
    )
    parser.add_argument(
        "--channel-delay",
        help="sending interval delay",
        type=float,
        default=1.0
    )
    parser.add_argument(
        "--channel-address",
        help="address of the channel",
        default="127.0.0.1",
    )
    parser.add_argument(
        "--enable-authentication",
        help="used with decrypt to authenticate message",
        action="store_true",
        default=False,
    )
    return parser


def main():
    set_stream_logger("udp")
    parser = _create_parser()
    args = parser.parse_args(sys.argv[1:])
    channel_class = SendChannel if args.channel_function == 'send' else ReceiveChannel
    channel = channel_class(
        name=args.channel_name,
        key=args.channel_key,
        addr=args.channel_address,
        port=args.channel_port,
        direction=args.channel_direction,
        auth=args.enable_authentication,
    )
    channel.validate()
    channel.delay = args.channel_delay
    asyncio.run(run_channel(function=args.channel_function, channel=channel))


if __name__ == "__main__":
    main()
