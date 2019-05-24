# knocknock
bind_layers(Dot11, Dot11AssoReq, subtype=0, type=0)
bind_layers(Dot11, Dot11AssoResp, subtype=1, type=0)
bind_layers(Dot11, Dot11ReassoReq, subtype=2, type=0)
bind_layers(Dot11, Dot11ReassoResp, subtype=3, type=0)
bind_layers(Dot11, Dot11ProbeReq, subtype=4, type=0)
bind_layers(Dot11, Dot11ProbeResp, subtype=5, type=0)
bind_layers(Dot11, Dot11Beacon, subtype=8, type=0)
bind_layers(Dot11, Dot11ATIM, subtype=9, type=0)
bind_layers(Dot11, Dot11Disas, subtype=10, type=0)
bind_layers(Dot11, Dot11Auth, subtype=11, type=0)
bind_layers(Dot11, Dot11Deauth, subtype=12, type=0)
bind_layers(Dot11, Dot11Ack, subtype=13, type=1)
From: https://github.com/secdev/scapy/blob/master/scapy/layers/dot11.py
