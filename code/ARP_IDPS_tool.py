#!/usr/bin/python3
import os.path
import csv # Store Mac Lists
import argparse
from ARP_IDPS import csvMACListTracker as csvList

def parseArguments():
    parser = argparse.ArgumentParser(description='Simple tool to Manage ARP IDPS')
    parser.add_argument('file', type=str, nargs=1, help='CSV file to use')
    parser.add_argument('-l', dest="list", action="store_true", help='List CSV file')
    parser.add_argument('-a', dest="add", type=str, nargs=1, help='Add Mac to CSV')
    parser.add_argument('-d', dest="delete", type=str, nargs=1, help='Delete row Containg MAC to CSV')
    parser.add_argument('-f', dest="flush", action="store_true", help='Flush entire CSV file')

    return parser.parse_args()

def main(args):
    if args.list:
        csvTrack = csvList(args.file[0])
        for Mac, MacDict in csvTrack.macDict.items():
            print("MAC: {}\tDict: {}".format(Mac, MacDict))
    elif args.add:
        csvTrack = csvList(args.file[0])
        csvTrack.add(args.add[0])
        print("Added {} to {}".format(args.add[0], args.file[0]))
    elif args.delete:
        csvTrack = csvList(args.file[0])
        if csvTrack.exists(args.delete[0]):
            with open(args.file[0],'w', newline='') as fd:
                writer = csv.writer(fd)
                for Mac, MacDict in csvTrack.macDict.items():
                    if Mac == args.delete[0]:
                        continue
                    writer.writerow([Mac, MacDict])
            print("Deleted")
        else:
            print("Could not find entry for: {}".format(args.delete[0]))
    elif args.flush:
        open(args.file[0], 'w').close()



if __name__ == "__main__":
    main(parseArguments())
