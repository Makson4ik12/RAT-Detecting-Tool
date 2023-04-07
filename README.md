# RAT-Detecting-Tool

Utility to search the Internet for the most popular RAT-servers.<br/>
List of supported RAT-servers:
- AsyncRat C#
- NjRAT
- Quasar
- byob
- Warzone RAT

# Requirements
```
pip install argparse netlas json scapy
```

# Using
```
python rat_tool.py --l -> view list of rats <br/>
python rat_tool.py --token="your_netlas_api_key" --rat=num_of_rat -> find rat servers with netlas
```
