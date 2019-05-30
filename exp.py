#!/usr/bin/env python3
from scapy.all import *
import sys, queue
from threading import Thread
'''
Get doc for scapy element

print sniff.__doc__
'''

thread_queue = queue.Queue()

def main(iface1):
    ssid = "ATT-WIFI-hP2o"
    probe_it = Prober(ssid, iface1)
    probe_it.start()
    sniff(iface=iface1, prn=_handl, store=0)

def _handl(pkt):
    ssid = "ATT-WIFI-hP2o"

    if pkt.haslayer(RadioTap):

        if pkt.type == 0 and pkt.subtype == 5:

            if pkt.info.decode("utf-8") == ssid:
                print("Killing prober")
                thread_queue.put("Kill me")
                print("Got probe response from SSID: %s MAC: %s BSSID: %s" %
                      (pkt.info, pkt.addr2, pkt.addr3))

class Prober(Thread):
    
    def __init__(self, ssid, iface):
        Thread.__init__(self)
        self.ssid = ssid
        self.iface = iface
        self.sc = 0
        self.mutex = Lock()

    def run(self):

        while True:
            if not thread_queue.empty():
                break
            self._send_802_11_probes(self.ssid, self.iface, self._next_sc())

            time.sleep(.5)
        print("YOU KILLED ME!!!")

    def _next_sc(self):
        self.mutex.acquire()
        self.sc += 1
        temp = self.sc
        self.mutex.release()
        return temp
            

    def _send_802_11_probes(self, ssid, iface, seq):

        src = "ac:cb:12:ad:58:27"
        param = Dot11ProbeReq()
        essid = Dot11Elt(ID='SSID',info=ssid)
        rates = Dot11Elt(ID='Rates',info="\x03\x12\x96\x18\x24\x30\x48\x60")
        dsset = Dot11Elt(ID='DSset',info='\x01')
        dot11 = Dot11(type=0,subtype=4,addr1="ff:ff:ff:ff:ff:ff",
                      addr2=src,addr3="ff:ff:ff:ff:ff:ff")

        pkt = RadioTap()/dot11/param/essid/rates/dsset
        sendp(pkt, iface=iface, verbose=False)
        
    
if __name__ == "__main__":

    main(sys.argv[1])
