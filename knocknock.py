#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
    WAP beaconing....
    Client sends probe request to WAP
    WAP responds with probe response
    Client sends authentication sequence 1 to WAP
    WAP sends authentication sequence 2 to client
    Client sends association request to WAP
    WAP sends association response to client
    Client to WAP connection established
'''
import argparse, sys
import logging, queue
from threading import Thread

thread_queue = queue.Queue()

def main():
    parser = argparse.ArgumentParser()
    reqd = parser.add_argument_group('required arguments')
    reqd.add_argument('-i','--iface',action='store',dest='iface',help='Interface to listen/send on')
    parser.add_argument('-w','--wap-mode',action='store',dest='ssid',help='WAP mode')
    parser.add_argument('-c','--client-mode',action='store_true',dest='client',help='Client mode')
    log = logging.getLogger(__name__)
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)-8s %(message)s',
                        datefmt='%a, %d %b %Y %H:%M:%S', filename='logs/knock.log', filemode='w')
    try:
        import colorama
        from colorama import Fore, Style
        colorama.init()
        b_prefix = "["+Fore.RED+"FAIL"+Style.RESET_ALL+"] "
        g_prefix = "["+Fore.GREEN+" OK "+Style.RESET_ALL+"] "
        n_prefix = "["+Fore.YELLOW+" ** "+Style.RESET_ALL+"] "
        rolling_1 = "["+Fore.GREEN+"*   "+Style.RESET_ALL+"] "
        rolling_2 = "["+Fore.YELLOW+" *  "+Style.RESET_ALL+"] "
        rolling_3 = "["+Fore.RED+"  * "+Style.RESET_ALL+"] "
        rolling_4 = "["+Fore.BLUE+"   *"+Style.RESET_ALL+"] "
    except ImportError:
        b_prefix = "[FAIL] "
        g_prefix = "[ OK ] "
        n_prefix = "[ ** ] "
        rolling_1 = "[*   ] "
        rolling_2 = "[ *  ] "
        rolling_3 = "[  * ] "
        rolling_4 = "[   *] "

    prefixes = [b_prefix, g_prefix,
                n_prefix, rolling_1,
                rolling_2, rolling_3,
                rolling_4]

class Beaconer(Thread):
    '''
    Send a constant stream of beacon frames to anyone who will listen
    '''
    def __init__(self, ap, log):
        Thread.__init__(self)
        try:
            from scapy.all import (Dot11,
                                   Dot11Beacon,
                                   Dot11Elt,
                                   RadioTap,
                                   sendp
            )
        except ImportError:
            raise ImportError("Could not import Dot11 stuff")
        self.ap = ap
        self.setDaemon(True)
        self.log = log

    def run(self):
        while True:
            if not thread_queue.empty():
                break
            for ssid in self.ap.ssids:
                self._send_802_11_frame(ssid)

    def _send_802_11_frame(self, ssid):
        dot11 = Dot11(type=0,subtype=8,addr1="ff:ff:ff:ff:ff:ff",
                      addr2=self.ap.ip,addr3=self.ap.ip)
        beacon = Dot11Beacon()
        essid = Dot11Elt(ID='SSID',info=ssid,len=len(ssid))
        radiotap = RadioTap(len=18, present='Flags+Rate+Channel+dBm_AntSignal+Antenna',
                            notdecoded='\x00\x6c' +
                            get_frequency(self.ap.ch) +
                            '\xc0\x00\xc0\x01\x00\x00')
        frame = radiotap/dot11/beacon/essid
        sendp(frame, iface=self.ap.iface, verbose=False)

class AP(Object):
    '''
    WAP object
    '''
    def __init__(self, iface, ssid, wap_ip=None, channel=None):
        try:
            from scapy.arch import str2mac, get_if_raw_hwaddr
        except ImportError:
            raise ImportError("Could not import str2mac and get_if_raw")
        self.ssids = [i for i in ssid]
        self.iface = iface
        self.ch = channel if channel is not None else 1
        self.mac = str2mac(get_if_raw_hwaddr(iface)[1])
        self.wpa = 0
        self.802_1_x = 0
        self.l_filter = None
        self.hidden = False
        self.ip = wap_ip if wap_ip is not None else '10.10.0.1'
        self.bpffilter = "not ( wlan type mgt subtype beacon ) and ((ether dst host " + self.mac +") or (ether dst host ff:ff:ff:ff:ff:ff))"

class Listener(Thread):
    '''
    Listen for incomming packets
    '''
    def __init__(self, ap, log, mode="CLIENT"):
        Thread.__init__(self)
        try:
            from scapy.layers.dot11 import *
            from scapy.layers.dhcp import *
            from scapy.layers.dns import DNS
            from scapy.layers.inet import TCP, UDP
        except ImportError:
            raise ImportError("Could not get scapy layers")
        
        self.ap = ap
        self.setDaemon(True)
        self.log = log
        self.mode = mode

    def run(self):
        
        if self.mode == "CLIENT":
            prn_func = self._client_pkt_handle
        else:
            prn_func = self._wap_pkt_handle
            
        sniff(iface=self.ap.iface, prn=prn_func,
              store=0, filter=self.ap.bpffilter)

    def _client_pkt_handle(self, pkt):

        try:
            # do client shit
        except Exception:
            raise Exception("Unknown error in CLIENT Listener")    

    def _wap_pkt_handle(self, pkt):

        try:
            if len(pkt.notdecoded[8:9]) > 0:
                flags = ord(pkt.notdecoded[8:9])
                if flags & 64 != 0:
                    if pkt.addr2 is not None:
                        self.log.info("Dropping corrupt packet from %s" % pkt.addr2)
                return

            if pkt.type == 802_TYPE.TYPE_MGMT:
                
                if pkt.subtype == 802_TYPE.SUBTYPE_PROBE_REQ:
                    
                    if Dot11Elt in pkt:
                        ssid = pkt[Dot11Elt].info
                        self.log.info("Probe req by: %s recieved for SSID: %s" % (pkt.addr2,ssid))

                        if ssid in self.ap.ssids or (Dot11Elt in pkt and pkt[Dot11Elt].len == 0):
                            if not self.ap.hidden:
                                # TODO: handle the probe req
                                tmp = 0

                elif pkt.subtype == 802_TYPE.SUBTYPE_AUTH_REQ:
                    
                    if pkt.addr1 == self.ap.mac:
                        # TODO: handle the auth request
                        tmp = 0

                elif pkt.subtype == 802_TYPE.SUBTYPE_ASSOC_REQ or pkt.subtype == 802_TYPE.SUBTYPE_REASSOC_REQ:
                    
                    if pkt.addr1 == self.ap.mac:
                        # TODO: handle the association request
                        if self.ap.802_1_x:
                            # TODO: handle the 802.1x EAP request

            if pkt.type == 802_TYPE.TYPE_DATA:

                if EAPOL in pkt:
                    if pkt.addr1 == self.ap.mac:
                        #EAPOL start
                        if pkt[EAPOL].type == 0x01:
                            # TODO: handle the 802.1x EAP request

                if EAP in pkt:
                    if pkt[EAP].code == EAP_CODE.RESPONSE:
                        if pkt[EAP].type == EAP_TYPE.IDENTITY:
                            identity = str(pkt[Raw])
                            if pkt.addr1 == self.ap.mac:
                                self.log.info("Got identity: "+identity[0:len(identity)-4])

                            # TODO: handle the 802.1x EAP request with LEAP
                elif ARP in packet:
                    if packet[ARP].pdst == self.ap.ip.split('/')[0]:
                        # TODO: handle ARP packet

                elif DHCP in packet:
                    if packet.addr1 == self.ap.mac:
                        if packet[DHCP].options[0][1] == 1:
                            # TODO: handle DHCP discover packet

                        if packet[DHCP].options[0][1] == 3:
                            # TODO: handle DHCP request

                elif DNS in packet:
                    # TODO: handle DNS request

                elif IP in packet:
                    # TODO: handle other request

        except Exception:
            raise Exception("Unknown error in WAP Listener")
        

class 802_TYPE:
    MTU = 4096
    TYPE_MGMT = 0
    TYPE_CONTROL = 1
    TYPE_DATA = 2
    SUBTYPE_DATA = 0x00
    SUBTYPE_PROBE_REQ = 0x04
    SUBTYPE_AUTH_REQ = 0x0B
    SUBTYPE_ASSOC_REQ = 0x00
    SUBTYPE_REASSOC_REQ = 0x02
    SUBTYPE_QOS_DATA = 0x28

class WAP_TYPE:
    AP_WLAN_TYPE_OPEN = 0
    AP_WLAN_TYPE_WPA = 1
    AP_WLAN_TYPE_WPA2 = 2
    AP_WLAN_TYPE_WPA_WPA2 = 3
    AP_AUTH_TYPE_OPEN = 0
    AP_AUTH_TYPE_SHARED = 1
    AP_RATES = "\x0c\x12\x18\x24\x30\x48\x60\x6c"

class EAP_TYPE:
    IDENTITY = 1
    NOTIFICATION = 2
    NAK = 3
    MD5_CHALLENGE = 4
    OTP = 5
    GENERIC_TOKEN_CARD = 6
    EAP_TLS = 13
    EAP_LEAP = 17
    EAP_SIM = 18
    TTLS = 21
    PEAP = 25
    MSCHAP_V2 = 29
    EAP_CISCO_FAST = 43

class EAP_CODE:
    REQUEST = 1
    RESPONSE = 2
    SUCCESS = 3
    FAILURE = 4
        
if __name__ == "__main__":
    main()
