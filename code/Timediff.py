#!/usr/bin/python3
import time
import datetime
import os.path
import sys
import csv # Store MAC Lists
    
def readCsv(filen,pos):
    fileout = []
    if os.path.exists(filen):
        with open(filen,'r', newline='') as fd:
            vList = csv.reader(fd)
            for row in vList:
                fileout.append(row[pos])
    return fileout

datesOne= readCsv(sys.argv[1],int(sys.argv[2]))
datesTwo= readCsv(sys.argv[3],int(sys.argv[4]))
datetimeFormat = '%Y-%m-%d %H:%M:%S.%f'
highest = 0
lowest = 0
total = 0

for i in range(len(datesOne)):
    time = ((datetime.datetime.strptime(datesOne[i], datetimeFormat)\
    - datetime.datetime.strptime(datesTwo[i], datetimeFormat))/ datetime.timedelta(milliseconds=1))
    print(time)
    total += time
    if time > highest:
        highest = time
    if time < lowest or lowest == 0:
        lowest = time

print("Avg: {}".format(total/len(datesOne)))
print("High: {}".format(highest))
print("low: {}".format(lowest))
