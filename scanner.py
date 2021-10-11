#!usr/bin/python3
import pyfiglet
import nmap

Scanner = nmap.PortScanner()

def banner():
 ascii_banner = pyfiglet.figlet_format("SNIFF THOSE PORTS OUT :D")
 print(ascii_banner)
 print("@Author: Saad Shahzad\n")
banner()

ip_Address = input("Enter Ip address: ")

selection = input("""Select the type of scan:-
	    1)Regular Scan
	    2)Comprehensive Scan
	    3)SYN ACK Scan
	    4)UDP Scan
	    5)Ping Scan
	    6)OS Detection Scan
	    7)Multiple IP\n""")

print("you have selected",selection)

if selection == '1':
 Scanner.scan(ip_Address)
 print("Ip Status: {0}".format(Scanner[ip_Address].state()))
 for host in Scanner.all_hosts():
  for proto in Scanner[host].all_protocols():
   lport = Scanner[host][proto].keys()
   for port in sorted(lport):
    print("port: {0} state: {1}".format(port, Scanner[host][proto][port]['state']))

elif selection == '2':
 Scanner.scan(ip_Address, '1-1024', '-v -sS -sV -sC -A -O')
 print("Ip Status: ", Scanner[ip_Address].state())
 print("Open Ports: ", Scanner[ip_Address]['tcp'].keys())
 print(Scanner[ip_Address].all_protocols())
else:
 print("Please enter a selection")
