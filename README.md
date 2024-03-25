# RAT-Detecting-Tool

A utility for searching the Internet for the likely IP addresses of some popular RAT servers using the Netlas service.<br/>
List of supported RAT-servers:
- AsyncRat C#
- NjRAT
- Quasar
- byob
- Warzone RAT
- Cerberus
- Venom
- Nanocore

# Requirements
```
pip install argparse netlas json scapy
```

# Using
```
python rat_tool.py --l -> view list of rats
python rat_tool.py --token="your_netlas_api_key" --rat=num_of_rat -> find rat servers with netlas
```
