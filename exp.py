#!/usr/bin/env python3
from scapy.all import *
import sys, queue, os
from threading import Thread, Event

'''
Get doc for scapy element

print sniff.__doc__

Wireshark will show two packets for everyone sent, if monitored from the 
same interface scapy is sending packets from

In Probe Response:
Need to grab Tagged Parameters >> RSN Information >> Group Cipher Suite type: AES (CCM) (4)
'''

th_event = Event()
snf_term = Event()

def main(iface1):

    ssid = "Virus Installer 5GHz" # DEBUG SSID
    client = CLIENT(iface1, "ac:cb:12:ad:58:27", ssid)# iface, mac, tar_ssid
    knock = KNOCKNOCK(client)
    knock.knock()

class KNOCKNOCK(object):
    
    def __init__(self, client):
        self.client = client

    def knock(self):
        prober = Prober(self.client)
        prober.start()
        sniff(iface=self.client.iface, prn=self._handl, store=0, stop_filter=lambda p: snf_term.is_set())

    def _handl(self, pkt):    

        if pkt.haslayer(Dot11): # 802.11 frame
            if pkt.type == DOT11_TYPE.TYPE_MGMT: # management frame
                if pkt.subtype == DOT11_TYPE.SUBTYPE_PROBE_RES: # probe response frame
                
                    if pkt.info.decode("utf-8") == ssid: # frame ssid is target ssid
                        print("Killing prober")
                        th_event.set()
                        print("Got probe response from SSID: %s MAC: %s BSSID: %s" %
                              (pkt.info.decode("utf-8"), pkt.addr2, pkt.addr3))
                        # print/store relevant probe response info
                        # send an auth request

                elif pkt.subtype == DOT11_TYPE.SUBTYPE_AUTH:
                    tmp = 0
                    # print/store relevant auth response info
                    # send an association request
                elif pkt.subtype == DOT11_TYPE.SUBTYPE_ASSOC_RES:
                    tmp = 0
                    # print/store relevant auth response info
                    # send an association request

    def _req_auth():
        #param = Dot11ProbeReq()
        #essid = Dot11Elt(ID='SSID',info=ssid)
        #rates = Dot11Elt(ID='Rates',info="\x03\x12\x96\x18\x24\x30\x48\x60")
        #dsset = Dot11Elt(ID='DSset',info='\x01')
        dot11 = Dot11(type=0,subtype=0x0B,addr1="ff:ff:ff:ff:ff:ff",
                      addr2=self.client.mac,addr3="ff:ff:ff:ff:ff:ff", SC=self.client.next_sn())
    
        pkt = RadioTap()/dot11/param/essid/rates/dsset
        sendp(pkt, iface=iface, verbose=False)

    '''
    def dot11_auth(self, receiver):
        auth_packet = self.ap.get_radiotap_header() \
                      / Dot11(subtype=0x0B, addr1=receiver, addr2=self.ap.mac, addr3=self.ap.mac,SC=self.ap.next_sc()) \
                      / Dot11Auth(seqnum=0x02)

        printd("Sending Authentication (0x0B)...", Level.DEBUG)
        sendp(auth_packet, iface=self.ap.interface, verbose=False)
    '''

class DOT11_TYPE:
    MTU = 4096
    TYPE_MGMT = 0
    TYPE_CONTROL = 1
    TYPE_DATA = 2
    SUBTYPE_DATA = 0x00
    SUBTYPE_PROBE_REQ = 0x04
    SUBTYPE_PROBE_RES = 0x05
    SUBTYPE_AUTH = 0x0B
    SUBTYPE_DEAUTH = 0x0C
    SUBTYPE_ASSOC_REQ = 0x00
    SUBTYPE_ASSOC_RES = 0x01
    SUBTYPE_REASSOC_REQ = 0x02
    SUBTYPE_QOS_DATA = 0x28
    SUBTYPE_ACK = 0x0D
    
class CLIENT(object):
    
    def __init__(self, iface, mac, tar_ssid):
        self.iface = iface
        self.mac = mac
        self.ssid = tar_ssid
        self.sn = self._in()
        self.mutex = Lock()

    def next_sn(self):
        self.mutex.acquire()
        self.sn = (self.sn + 1) % 4096
        tmp_sn = self.sn
        self.mutex.release()
        return tmp_sn * 16
        
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

    def out(self):
        if "win" in sys.platform:
            fn = "\\sn.conf"
        else:
            fn = "/sn.conf"

        if os.path.exists(os.path.dirname(os.path.realpath(__file__))+fn):
            o_conf_lst = []
            repl = False
            with open(os.path.dirname(os.path.realpath(__file__))+fn,'r') as o_conf:
                o_conf_lst = o_conf.readlines()

                for i,item in enumerate(o_conf_lst):
                    if self.ssid in item:
                        repl = True
                        o_conf_lst[i] = self.ssid+'\t'+ str(self.sn)

                if not repl:
                    o_conf_lst.append(self.ssid+'\t'+str(self.sn))
                    
            with open(os.path.dirname(os.path.realpath(__file__))+fn,'w') as n_conf:
                for item in o_conf_lst:
                    n_conf.write(item)
        else:
            with open(os.path.dirname(os.path.realpath(__file__))+fn, "w+") as conf:
                conf.write(self.ssid+'\t'+str(self.sn))

class Prober(Thread):

    def __init__(self, client):
        Thread.__init__(self)
        self.client = client

    def run(self):

        while True:
            if th_event.is_set():
                self.client.out()
                break
            self._send_802_11_probes()

            time.sleep(1)
            
    def _send_802_11_probes(self):
        param = Dot11ProbeReq()
        essid = Dot11Elt(ID='SSID',info=self.client.ssid)
        rates = Dot11Elt(ID='Rates',info="\x03\x12\x96\x18\x24\x30\x48\x60")
        dsset = Dot11Elt(ID='DSset',info='\x01')
        dot11 = Dot11(type=0,subtype=4,addr1="ff:ff:ff:ff:ff:ff",
                      addr2=self.client.mac,addr3="ff:ff:ff:ff:ff:ff", SC=self.client.next_sn())

        pkt = RadioTap()/dot11/param/essid/rates/dsset
        sendp(pkt, iface=self.client.iface, verbose=False)
        
    
if __name__ == "__main__":

    main(sys.argv[1])
