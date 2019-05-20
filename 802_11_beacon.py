from scapy.all import ( Dot11,
                        Dot11Beacon,
                        Dot11Elt,
                        sendp
)

class Beaconer(threading.Thread):
    def __init__(self, ap):
        threading.Thread.__init__(self)
        self.ap = ap
        self.setDaemon(True)
        
    def run(self):
        while True:
            for ssid in self.ap.ssids:
                self._802_11_Frame(ssid)

            sleep(0.1)

    def _802_11_Frame(self):
        beacon = self.ap.get_radiotap()
        /Dot11(subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2=self.ap.mac, addr3=self.ap.mac)
        /Dot11Beacon(cap=0x2105)/Dot11Elt(ID='SSID', info=ssid)
        /Dot11Elt(ID='Rates', info=AP_RATES)
        /Dot11Elt(ID='DSset', info=chr(self.ap.channel))

        if self.ap.802_1_x:
            beacon[Dot11Beacon].cap = 0x3101
            rsn_info = Dot11Elt(ID='RSNinfo', info=RSN)
            beacon = beacon / rsn_info

        beacon.SC = self.ap.incr_sc()
        beacon[Dot11Beacon].timestamp = self.ap.timestamp()

        sendp(beacon, iface=self.ap.interface, verbose=False)
