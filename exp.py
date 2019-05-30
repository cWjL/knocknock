#!/usr/bin/env python3
from scapy.all import *
import sys, queue, os
from threading import Thread
'''
Get doc for scapy element

print sniff.__doc__

Wireshark will show two packets for everyone sent, if monitored from the 
same interface scapy is sending packets from

In Probe Response:
Need to grab Tagged Parameters >> RSN Information >> Group Cipher Suite type: AES (CCM) (4)
'''

thread_queue = queue.Queue()

def main(iface1):
    ssid = "ATT-WIFI-8671"
    probe_it = Prober(ssid, iface1)
    probe_it.start()
    sniff(iface=iface1, prn=_handl, store=0)

def _handl(pkt):
    ssid = "ATT-WIFI-8671"

    if pkt.haslayer(RadioTap):

        if pkt.type == 0 and pkt.subtype == 5: # probe response

            if pkt.info.decode("utf-8") == ssid:
                print("Killing prober")
                thread_queue.put("Kill me")
                print("Got probe response from SSID: %s MAC: %s BSSID: %s" %
                      (pkt.info.decode("utf-8"), pkt.addr2, pkt.addr3))
                print(pkt.summary())
                # print/store relevant probe response info
                # send an auth request

        #elif pkt.type == 0 and pkt.subtype == 

class Prober(Thread):
    
    def __init__(self, ssid, iface):
        Thread.__init__(self)
        self.ssid = ssid
        self.iface = iface
        self.sn = self._in()
        self.mutex = Lock()

    def run(self):

        while True:
            if not thread_queue.empty():
                self._out()
                break
            self._send_802_11_probes(self.ssid, self.iface)

            time.sleep(1)

    def _in(self):
        if "win" in sys.platform:
            fn = "\\sn.conf"
        else:
            fn = "/sn.conf"

        if os.path.exists(os.path.dirname(os.path.realpath(__file__))+fn):
            with open(os.path.dirname(os.path.realpath(__file__))+fn,'r') as o_conf:
                o_conf_lst = o_conf.readlines()
                for item in o_conf_lst:
                    if self.ssid in item:
                        return int(item.split('\t')[1])

        return 0

    def _out(self):
        if "win" in sys.platform:
            fn = "\\sn.conf"
        else:
            fn = "/sn.conf"

        if os.path.exists(os.path.dirname(os.path.realpath(__file__))+fn):
            o_conf_lst = []
            with open(os.path.dirname(os.path.realpath(__file__))+fn,'r') as o_conf:
                o_conf_lst = o_conf.readlines()

                for i,item in enumerate(o_conf_lst):
                    if self.ssid in item:
                        repl = True
                        o_conf_lst[i] = self.ssid+'\t'+self.sn

                if not repl:
                    o_conf_lst.append(self.ssid+'\t'+self.sn)
                    
            with open(os.path.dirname(os.path.realpath(__file__))+fn,'w') as n_conf:
                for item in o_conf_lst:
                    n_conf.write(item)
        else:
            with open(os.path.dirname(os.path.realpath(__file__))+fn, "w+") as conf:
                conf.write(self.ssid+'\t'+self.sn)
        
    def _next_sn(self):
        self.mutex.acquire()
        self.sn = (self.sn + 1) % 4096
        tmp_sn = self.sn
        self.mutex.release()
        return tmp_sn * 16
            
    def _send_802_11_probes(self, ssid, iface):
        src = "ac:cb:12:ad:58:27"
        param = Dot11ProbeReq()
        essid = Dot11Elt(ID='SSID',info=ssid)
        rates = Dot11Elt(ID='Rates',info="\x03\x12\x96\x18\x24\x30\x48\x60")
        dsset = Dot11Elt(ID='DSset',info='\x01')
        dot11 = Dot11(type=0,subtype=4,addr1="ff:ff:ff:ff:ff:ff",
                      addr2=src,addr3="ff:ff:ff:ff:ff:ff", SC=self._next_sn())

        pkt = RadioTap()/dot11/param/essid/rates/dsset
        sendp(pkt, iface=iface, verbose=False)
        
    
if __name__ == "__main__":
    #print(os.path.dirname(os.path.realpath(__file__)))
    #sys.exit(0)
    main(sys.argv[1])
