import argparse

import netlas
import json
from scapy.all import *
from scapy.layers.inet import TCP, IP


class RATTool:
    def __init__(self, token):
        self.token = token
        self.connect = netlas.Netlas(api_key=self.token)

    def get_responses(self, response):
        responses_count = int(self.connect.count(query=response)['count'])
        search_result = self.connect.download(query=response, size=responses_count)

        return list(map(lambda x: json.loads(x.decode('utf-8')), search_result))

    def async_rat(self):
        responses_list = self.get_responses("(jarm:22b22b00022b22b22b22b22b22b22bd3b67dd3674d9af9dd91c1955a35d0e9)"
                                            " AND certificate.signature_algorithm.name:\"SHA512-RSA\"")

        print(f"Find {len(responses_list)} RATs\n")

        for index, response in enumerate(responses_list):
            count = 2

            if int(((response['data']['certificate']['validity']['end']).split('-'))[0]) >= 9999:
                count += 1

            if int(response['data']['certificate']['version']) == 3:
                count += 1

            if (response['data']['http']['http_version']['name']) == "HTTP/0.9":
                count += 1

            if (response['data']['port'] == 6606) or (response['data']['port'] == 7707) or (response['data']['port'] == 8808):
                count += 0.5

            print(f"{index + 1}. {round((count / 5.5) * 100, 2)}% of AsyncRat - {response['data']['isp']},"
                  f" {response['data']['geo']['country']} -> {response['data']['ip']}:{response['data']['port']}")

    def njrat(self):
        synack = sr1(IP(dst="192.168.95.99") / TCP(dport=5552, sport=69, flags='S', seq=1000,
                                                   options=[('MSS', 1460), ("NOP", None), ("WScale", 8), ("NOP", None), ("NOP", None), ("SAckOK", "")], window=64240))

        psh = sr1(IP(dst="192.168.95.99") / TCP(dport=5552, sport=69, flags='A', ack=(synack.seq+1), seq=1001))

        count = 0
        diff = [('MSS', 1460), ('NOP', None), ('WScale', 4), ('NOP', None), ('NOP', None), ('SAckOK', b'')]

        if chexdump(psh[TCP].payload, dump=True) == "0x30, 0x00":
            count += 1

        print(f"{((sum([1 for x in diff if x in synack[TCP].options]) + count) / 7) * 100}% of NjAT")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog='RAT Detecting Tool')
    parser.add_argument('--token', type=str, default="0", help="Your Netlas API key")
    parser.add_argument('--rat', type=int, default="0", help="Input number of RAT")
    parser.add_argument('--l', action='store_true', help="View list of RATs")
    args = parser.parse_args()

    if args.l:
        print("RAT's list:\n"
              "1. AsyncRat C#\n"
              "2. NjRAT\n"
              "Using: python rat_tool.py --token=\"your_api_key\" --rat=num_of_rat")

    if args.token == "0":
        print("Require token")
        exit(0)

    rat_tool = RATTool(token=args.token)

    if args.rat == 1:
        rat_tool.async_rat()
    elif args.rat == 2:
        rat_tool.njrat()