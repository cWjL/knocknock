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
import subprocess


def main():
    parser = argparse.ArgumentParser()
    reqd = parser.add_argument_group('required arguments')
    reqd.add_argument('-i','--iface',action='store',dest='iface',help='Interface to listen/send on')
    parser.add_argument('-w','--wap-mode',action='store',dest='ssid',help='WAP mode')
    parser.add_argument('-c','--client-mode',action='store_true',dest='client',help='Client mode')
        
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



if __name__ == "__main__":
    main()
