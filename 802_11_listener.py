from scapy.all import sniff
from .802_11_const import *
'''
FCS: Frame Check Sequence
'''

class Listener(threading.Thread):
    def __init__(self, ap, log):
        threading.Thread.__init__(self)
        self.ap = ap
        self.setDaemon(True)
        self.log = log
        
    def run(self):
        sniff(iface=self.ap.interface, prn=self._pkt_handle,
              store=0, filter=self.ap.bpffilter)

    def _pkt_handle(self, pkt):
        
        try:
            if len(pkt.notdecoded[8:9]) > 0:  # radiotap header flags sent by the driver
                flags = ord(pkt.notdecoded[8:9])
                if flags & 64 != 0:  # BAD_FCS flag is set
                    if not pkt.addr2 is None:
                        # log a undiscovered MAC warning if this is a new MAC
                        self.log.info("Dropping corrupt packet from %s" % pkt.addr2)
                        # drop it
                    return
                
            # Client want to connect to us
            if pkt.type == EightOhTwoType.TYPE_MANAGEMENT:
                # Probe request
                if pkt.subtype == EightOhTwoType.SUBTYPE_PROBE_REQ:
                    if Dot11Elt in pkt:
                        ssid = pkt[Dot11Elt].info
                        self.log.info("Probe req by: %s recieved for SSID: %s" % (pkt.addr2,ssid))

                    if ssid in self.ap.ssids or (Dot11Elt in pkt and pkt[Dot11Elt].len == 0):
                        if not self.ap.hidden:
                            # handle the probe req
                            tmp = 0

                # Authentication request
                elif pkt.subtype == EightOhTwoType.SUBTYPE_AUTH_REQ:
                    if pkt.addr1 == self.ap.mac:
                        self.ap.sc = -1 # reset seq num
                        # handle the auth req
                        
                # Association request
                elif pkt.subtype == EightOhTwoType.SUBTYPE_ASSOC_REQ or pkt.subtype == EightOhTwoType.SUBTYPE_REASSOC_REQ:
                    tmp = 0
            else:
                tmp = 0
                
        except:
            return

class EightOhTwoType:
    MTU = 4096
    TYPE_MANAGEMENT = 0
    TYPE_CONTROL = 1
    TYPE_DATA = 2
    SUBTYPE_DATA = 0x00
    SUBTYPE_PROBE_REQ = 0x04
    SUBTYPE_AUTH_REQ = 0x0B
    SUBTYPE_ASSOC_REQ = 0x00
    SUBTYPE_REASSOC_REQ = 0x02
    SUBTYPE_QOS_DATA = 0x28

class WAPAuthType:
    AP_WLAN_TYPE_OPEN = 0
    AP_WLAN_TYPE_WPA = 1
    AP_WLAN_TYPE_WPA2 = 2
    AP_WLAN_TYPE_WPA_WPA2 = 3
    AP_AUTH_TYPE_OPEN = 0
    AP_AUTH_TYPE_SHARED = 1
    AP_RATES = "\x0c\x12\x18\x24\x30\x48\x60\x6c"

class EAPType():
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

class EAPRes():
    REQUEST = 1
    RESPONSE = 2
    SUCCESS = 3
    FAILURE = 4
