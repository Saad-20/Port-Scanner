#!usr/bin/python3
import pyfiglet
import nmap

Scanner = nmap.PortScanner()

ip_Address = input("Enter Ip address: ")

def banner():
 ascii_banner = pyfiglet.figlet_format("LETS SNIFF :D")
 print(ascii_banner)

selection = input("""Select the type of scan:-
	    1)Regular Scan
	    2)Comprehensive Scan
	    3)SYN ACK Scan
	    4)UDP Scan
	    5)Ping Scan
	    6)OS Detection Scan
	    7)Multiple IP""")

print("you have selected",selection)

if selection == '1':
 Scanner.scan(ip_Address)
 print(Scanner.scaninfo())
 print("Ip Status", Scanner[ip_Address].state())
