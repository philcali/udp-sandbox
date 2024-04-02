import argparse
import asyncio
import sys
from udp import set_stream_logger
from udp.channel import Channel, Encryptor


CHANNELS = 3


def _create_parser():
    parser = argparse.ArgumentParser(
        f"{__package__.replace('.', '-')}",
        description=f"Example UDP {__package__.split('.')[-1]} application"
    )
    for index in range(1, CHANNELS + 1):
        group = parser.add_argument_group(
            f"channel-{index}",
        )
        group.add_argument(
            f"--channel-name-{index}",
            help=f"name of the channel on index {index}",
        )
        group.add_argument(
            f"--channel-key-{index}",
            help=f"key of the channel on index {index}",
        )
        group.add_argument(
            f"--channel-port-{index}",
            help=f"port for channel on index {index}",
            type=int,
            default=5004 + index,
        )
        group.add_argument(
            f"--channel-address-{index}",
            help=f"address for channel on index {index}",
            default="127.0.0.1",
        )
        group.add_argument(
            f"--channel-direction-{index}",
            help=f"direction of channel on index {index}",
        )
        group.add_argument(
            f"--channel-send-port-{index}",
            type=int,
            help=f"send data to port from channel on index {index}",
            default=5024 + index,
        )
        group.add_argument(
            f"--channel-send-address-{index}",
            help=f"send data to address from channel on index {index}",
            default="127.0.0.1",
        )
    return parser


def main():
    set_stream_logger("udp")
    parser = _create_parser()
    args = parser.parse_args(sys.argv[1:])
    channels = []
    for index in range(1, CHANNELS + 1):
        name = getattr(args, f'channel_name_{index}')
        key = getattr(args, f'channel_key_{index}')
        if name is None or key is None:
            continue
        recv_port = getattr(args, f'channel_port_{index}')
        recv_addr = getattr(args, f'channel_address_{index}')
        direction = getattr(args, f'channel_direction_{index}')
        send_port = getattr(args, f'channel_send_port_{index}')
        send_addr = getattr(args, f'channel_send_address_{index}')
        channel = Channel(
            name=name,
            key=key,
            addr=recv_addr,
            port=recv_port,
            send_port=send_port,
            send_addr=send_addr,
            direction=direction,
        )
        channel.validate()
        channels.append(channel)
    if len(channels) == 0:
        parser.print_help()
    else:
        encryptor = Encryptor(channels)
        asyncio.run(encryptor.run())


if __name__ == "__main__":
    main()
