import pyshark
cap=pyshark.FileCapture('C:/Users/Vedant/Mini Project/Network-Intrusion-Detection-System/Sniffer/dumpfile.pcap')
print(cap[0])