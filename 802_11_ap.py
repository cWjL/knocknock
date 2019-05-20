from scapy.all import RadioTap
from scapy.arch import str2mac, get_if_raw_hwaddr
import time, subprocess

class WAP(object):        

    def __init__(self, iface, ssid):
        self.ssids = [i for i in ssid]
        self.interface = iface
        self.channel = 1
        self.mac = self._hwaddr(iface)
        self.wpa = 0
        self.802_1_x = 0
        self.sc = 0
        self.l_filter = None
        self.hidden = False
        self.ip = '10.10.0.1'
        self.mutex = threading.Lock()
        self.boot = time()
        self.bpffilter = "not ( wlan type mgt subtype beacon ) and ((ether dst host " + self.mac + ") or (ether dst host ff:ff:ff:ff:ff:ff))"

    def get_radiotap(self):
        radiotap = RadioTap(len=18, present='Flags+Rate+Channel+dBm_AntSignal+Antenna',
                            notdecoded='\x00\x6c' +
                            get_frequency(self.channel) +
                            '\xc0\x00\xc0\x01\x00\x00')
        return radiotap

    def incr_sc(self):
        self.mutex.acquire()
        self.sc = (self.sc + 1) % 4096
        temp = self.sc
        self.mutex.release()

    def timestamp(self):
        return (time() - self.boot) * 1000000

    def _hwaddr(self, iface):
        return str2mac(get_if_raw_hwaddr(iface)[1])



