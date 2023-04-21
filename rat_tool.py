import argparse
import OpenSSL
import netlas
import ssl
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
            valid = "0-0-0"
            flag = 0

            try:
                cert = ssl.get_server_certificate((response['data']['ip'], int(response['data']['port'])))
                x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
                timestamp = x509.get_notAfter().decode('utf-8')
                valid = (datetime.strptime(timestamp, '%Y%m%d%H%M%S%z').date().isoformat())
                flag += 1
            except:
                valid = response['data']['certificate']['validity']['end']

            count = 2

            if int((valid.split('-'))[0]) == 10000:
                count += 1

            if int(response['data']['certificate']['version']) == 3:
                count += 1

            if (response['data']['http']['http_version']['name']) == "HTTP/0.9":
                count += 1

            if (response['data']['port'] == 6606) or (response['data']['port'] == 7707) or (response['data']['port'] == 8808):
                count += 0.5

            print(f"{index + 1}. {round((count / 5.5) * 100, 2)}% of AsyncRat - {response['data']['isp']},"
                  f" {response['data']['geo']['country']} -> {response['data']['ip']}:{response['data']['port']}"
                  f" via {'Netlas' if not flag else 'TLS'}")

    @staticmethod
    def njrat():
        ip = str(input("Input IP to check if this NjRAT: "))

        synack = sr1(IP(dst=ip) / TCP(dport=5552, sport=69, flags='S', seq=1000,
                                      options=[('MSS', 1460), ("NOP", None), ("WScale", 8), ("NOP", None), ("NOP", None), ("SAckOK", "")], window=64240))

        psh = sr1(IP(dst=ip) / TCP(dport=5552, sport=69, flags='A', ack=(synack.seq+1), seq=1001))

        count = 0
        diff = [('MSS', 1460), ('NOP', None), ('WScale', 4), ('NOP', None), ('NOP', None), ('SAckOK', b'')]

        if chexdump(psh[TCP].payload, dump=True) == "0x30, 0x00":
            count += 1

        print(f"{((sum([1 for x in diff if x in synack[TCP].options]) + count) / 7) * 100}% of NjAT")

    def quasar(self):
        responses_list = self.get_responses("(jarm:2ad2ad0002ad2ad0002ad2ad2ad2adf9fdf4eeac344e8b5003264da73585be)"
                                            " AND certificate.signature_algorithm.name:\"SHA512-RSA\"")

        print(f"Find {len(responses_list)} RATs\n")

        for index, response in enumerate(responses_list):
            valid = "0-0-0"
            flag = 0
            count = 2

            try:
                cert = ssl.get_server_certificate((response['data']['ip'], int(response['data']['port'])))
                x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
                timestamp = x509.get_notAfter().decode('utf-8')
                valid = (datetime.strptime(timestamp, '%Y%m%d%H%M%S%z').date().isoformat())
                flag += 1
            except:
                valid = response['data']['certificate']['validity']['end']

            if int((valid.split('-'))[0]) == 10000:
                count += 1

            if int(response['data']['certificate']['version']) == 3:
                count += 1

            if (response['data']['http']['http_version']['name']) == "HTTP/0.9":
                count += 1

            if response['data']['port'] == 4782:
                count += 0.5

            print(f"{index + 1}. {round((count / 5.5) * 100, 2)}% of Quasar - {response['data']['isp']},"
                  f" {response['data']['geo']['country']} -> {response['data']['ip']}:{response['data']['port']}"
                  f" via {'Netlas' if not flag else 'TLS'}")

    def byob(self):
        responses_list = self.get_responses("http.body:\"Directory listing for \" AND http.status_code:200 AND"
                                            " http.body:\"xmrig\" AND http.body:\"__init__.py\"")

        print(f"Find {len(responses_list)} RATs\n")

        for index, response in enumerate(responses_list):
            print(f"{index + 1}. byob - {response['data']['isp']},"
                  f" {response['data']['geo']['country']} -> {response['data']['ip']}:{response['data']['port']}")

    @staticmethod
    def warzone():
        sport = random.randint(4000, 5000)
        dport = 5200
        ip = str(input("Input IP to check if this Warzone RAT: "))

        synack = sr1(IP(dst=ip) / TCP(dport=dport, sport=sport, flags='S', seq=0, window=64240,
                                      options=[('MSS', 1460), ('NOP', None), ('WScale', 8), ('NOP', None),
                                               ('NOP', None), ('SAckOK', "")]))

        psh = sr1(IP(dst=ip) / TCP(sport=sport, dport=dport, seq=synack.ack, ack=(synack.seq + 1), flags="A",
                                   window=65535))

        try:
            if chexdump(psh[TCP].payload, dump=True) == "0x05, 0x38, 0x6b, 0xf4, 0x62, 0xf4," \
                                                        " 0x9f, 0x3f, 0x35, 0x2f, 0x6e, 0xe6":
                print(f"100% of Warzone RAT - {ip}:{dport}\n")
                return
        except Exception:
            pass

        print(f"0% of Warzone RAT - {ip}:{dport}\n")

    @staticmethod
    def cerberus():
        sport = random.randint(4000, 5000)
        dport = 5150
        ip = str(input("Input IP to check if this Cerberus RAT: "))

        synack = sr1(IP(dst=ip) / TCP(dport=dport, sport=sport, flags='S', seq=0, window=65535))

        ack_packet = IP(dst=ip) / TCP(sport=sport, dport=dport, seq=synack.ack, ack=(synack.seq + 1), flags="A",
                                      window=10233, options=[('WScale', 8)])

        send(ack_packet)

        asd = sr1(IP(dst=ip) / TCP(sport=sport, dport=dport, ack=(synack.seq + 1), seq=synack.ack, flags="PA",
                                   window=10233, options=[('WScale', 8)]) / b'qNl94efYAz227OqEDMP.\n')

        comp = "0x59, 0x70, 0x6d, 0x77, 0x31, 0x53, 0x79, 0x76, 0x30, 0x32, 0x33, 0x51, 0x5a, 0x44, 0x31, 0x35"

        if chexdump(asd[TCP].payload, dump=True)[0:len(comp)] == comp:
            print(f"100% of Cerberus RAT - {ip}:{dport}\n")
            return

        print(f"0% of Cerberus RAT - {ip}:{dport}\n")

    def venom(self):
        responses_list = self.get_responses("(jarm:22b22b00022b22b22b22b22b22b22bd3b67dd3674d9af9dd91c1955a35d0e9)"
                                            " AND certificate.signature_algorithm.name:\"SHA512-RSA\"")

        print(f"Find {len(responses_list)} RATs\n")

        for index, response in enumerate(responses_list):
            count = 2

            if (response['data']['certificate']['validity']['end']) == "2031-10-22":
                count += 1

            if response['data']['port'] == 4782:
                count += 0.5

            print(f"{index + 1}. {round((count / 3.5) * 100, 2)}% of Venom - {response['data']['isp']},"
                  f" {response['data']['geo']['country']} -> {response['data']['ip']}:{response['data']['port']}")

    @staticmethod
    def nanocore():
        sport = random.randint(50000, 60000)
        dport = 53896  # default
        ip = str(input("Input IP to check if this Nanocore RAT: "))

        synack = sr1(IP(dst=ip) / TCP(dport=dport, sport=sport, flags='S', seq=0, window=64240,
                                      options=[('MSS', 1460), ('NOP', None), ('WScale', 8)
                                          , ('NOP', None), ('NOP', None), ('SAckOK', "")]))

        send(IP(dst=ip) / TCP(sport=sport, dport=dport, seq=synack.ack, ack=(synack.seq + 1), flags="A", window=1026))

        hex_data = "40000000e9010494653742abaac7fa887534f79f4e19b73f92d805bbd79d9dfd7cb1c207e956199db4730dce03d8ad" \
                   "34c9623e44cc45d535b6c9a62fb3bfa730e665dac8"

        asd = sr1(IP(dst=ip) / TCP(sport=sport, dport=dport, ack=(synack.seq + 1), seq=synack.ack, flags="PA", window=10233) / bytes.fromhex(hex_data))

        comp = "0x20, 0x00, 0x00, 0x00, 0x74, 0x1f, 0xb7, 0xa5, 0x5f, 0x60, 0xad, 0x3f, 0x06, 0xf4, 0x96, 0xf3," \
               " 0xdd, 0x7b, 0x9c, 0xd6, 0xc9, 0xb7, 0x87, 0xda, 0x56, 0x25, 0x76, 0xb2, 0x92, 0x5d, 0xe2, 0x86," \
               " 0x63, 0x40, 0x41, 0x02"

        if chexdump(asd[TCP].payload, dump=True)[0:len(comp)] == comp:
            print(f"100% of Nanocore RAT - {ip}:{dport}\n")
            return

        print(f"0% of Cerberus RAT - {ip}:{dport}\n")

    # certificate.validity.end: 2053
    # AND
    # certificate.signature.signature_algorithm.name: "SHA1-RSA"
    # AND
    # certificate.version: 3
    def orcus(self):
        for i in range(1, 4):
            responses_list = self.get_responses(f"certificate.validity.end: 205{i}"
                                                " AND certificate.signature_algorithm.name:\"SHA1-RSA\"" " AND certificate.version:3")

            print(f"Find {len(responses_list)} RATs\n")

            for index, response in enumerate(responses_list):
                valid = "0-0-0"
                flag = 0
                # print(f"{response['data']['geo']['country']} -> {response['data']['ip']}:{response['data']['port']}")
            # if ("2051" in response['data']['certificate']['validity']['end']):
                # print(response['data']['certificate']['validity']['end'])
            # if ("2052" in response['data']['certificate']['validity']['end'] and "00:00:00" in response['data']['certificate']['validity']['end']):
                # print(response['data']['certificate']['validity']['end'])
            # if ("2053" in response['data']['certificate']['validity']['end'] and "00:00:00" in response['data']['certificate']['validity']['end']):
                # print(response['data']['certificate']['validity']['end'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog='RAT Detecting Tool')
    parser.add_argument('--token', type=str, default="0", help="Your Netlas API key")
    parser.add_argument('--rat', type=int, default=0, help="Input number of RAT")
    parser.add_argument('--l', action='store_true', help="View list of RATs")
    args = parser.parse_args()

    if args.l:
        print("RAT's list:\n"
              "1. AsyncRat C#\n"
              "2. NjRAT\n"
              "3. Quasar\n"
              "4. byob\n"
              "5. Warzone RAT\n"
              "6. Cerberus RAT\n"
              "7. Venom RAT\n"
              "8. Nanocore RAT\n"
              "Using: python rat_tool.py --token=\"your_api_key\" --rat=num_of_rat")

    if args.token == "0":
        print("Require token")
        exit(0)

    rat_tool = RATTool(token=args.token)

    if args.rat == 1:
        rat_tool.async_rat()
    elif args.rat == 2:
        rat_tool.njrat()
    elif args.rat == 3:
        rat_tool.quasar()
    elif args.rat == 4:
        rat_tool.byob()
    elif args.rat == 5:
        rat_tool.warzone()
    elif args.rat == 6:
        rat_tool.cerberus()
    elif args.rat == 7:
        rat_tool.venom()
    elif args.rat == 8:
        rat_tool.nanocore()
    elif args.rat == 9:
        rat_tool.orcus()
