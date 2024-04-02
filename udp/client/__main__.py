import argparse
import asyncio
import logging
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
        output = data
        if self.direction == 'encrypt':
            output = self.decrypt(data)
        logger.info(f'Data received was "{output.decode()}"')


class SendChannel(Channel):
    def post_at_interval(self):
        while not self.transport.is_closing():
            data = f'Channel message {uuid4()} from {self.name} on {floor(time.time())}'.encode('utf-8')
            logger.info(f'Sending {data.decode()}')
            if self.direction == 'encrypt':
                data = self.encrypt(data)
            try:
                self.transport.sendto(data, (self.addr, self.port))
                time.sleep(self.delay)
            except Exception as e:
                logger.warning(f'Failed to send message {e}')

    def connection_made(self, transport):
        super().connection_made(transport)
        asyncio.to_thread(self.post_at_interval())


async def run_channel(function, channel):
    loop = asyncio.get_running_loop()

    on_con_lost = loop.create_future()
    kwargs = {}
    if function == 'send':
        kwargs['remote_addr'] = (channel.addr, channel.port)
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
    )
    channel.validate()
    channel.delay = args.channel_delay
    asyncio.run(run_channel(function=args.channel_function, channel=channel))


if __name__ == "__main__":
    main()
