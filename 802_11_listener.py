from scapy.all import sniff
from .802_11_const import *

class Listener(threading.Thread):
    def __init__(self, ap):
        threading.Thread.__init__(self)
        self.ap = ap
        self.setDaemon(True)
        
    def run(self):
        sniff(iface=self.ap.interface, prn=self._pkt_handle,
              store=0, filter=self.ap.bpffilter)

    def _pkt_handle(self, pkt):
        try:
            
