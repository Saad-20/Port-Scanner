#!usr/bin/python3
import pyfiglet
import nmap
import sys
from colorama import Style

#----------Colors----------#
class colors:
 PURPLE = "\033[1;35;40m"
 RED = "\033[91m"
 BLUE = "\033[94m"
 YELLOW = "\033[93m"
 CYAN = "\033[0;36m"
#--------------------------#

Scanner = nmap.PortScanner()

def banner():
 ascii_banner = pyfiglet.figlet_format("SNIFF THOSE PORTS OUT :D")
 print("{0}{1}".format(colors.RED,ascii_banner))
 print("{0}@Author: {1}Saad Shahzad\n{2}".format(colors.YELLOW,colors.CYAN,Style.RESET_ALL))
 print("{0}@Version: {1} 1.0\n{2}".format(colors.YELLOW,colors.CYAN,Style.RESET_ALL))
banner()

try:
 ip_Address = input("{0}Enter Ip address:{1} ".format(colors.RED,Style.RESET_ALL))

 selection = input("""{0}Select the type of scan:-
	   {1} 1)Regular Scan
	    2)Comprehensive Scan
	    3)SYN ACK Scan
	    4)UDP Scan
	    5)Ping Scan
	    6)OS Detection Scan
	    7)Multiple IP\n{2}""".format(colors.RED,colors.YELLOW,Style.RESET_ALL))

 print("{0}you have selected: {1}{2}{3}".format(colors.BLUE,colors.YELLOW,selection,Style.RESET_ALL))

 if selection == '1':
  Scanner.scan(ip_Address, '1-1024', '-v -A -sV -sC -A -O')
  print("Ip Status: {0}".format(Scanner[ip_Address].state()))
  print(Scanner.all_hosts())
  for host in Scanner.all_hosts():
   for proto in Scanner[host].all_protocols():
    lport = Scanner[host][proto].keys()
    print(lport)
    for port in sorted(lport):
     print("port: {0}  state: {1}  service: {2}".format(port, Scanner[host][proto][port]['state'], Scanner[host][proto][port]['name']))

 elif selection == '2':
  print(Scanner.scan(ip_Address, '1-1024', '-v -sS -sV -sC -A -O'))
  print("Ip Status: ", Scanner[ip_Address].state())
  print("Open Ports: ", Scanner[ip_Address]['tcp'].keys())
  print(Scanner[ip_Address].all_protocols())
  print(Scanner[ip_Address].hostname())

 else:
  print("Please enter a selection\n")

except nmap.nmap.PortScannerError:
 print("\n{0}Run sudo privileges to run this option{1}".format(colors.RED,Style.RESET_ALL))

except KeyboardInterrupt:
 print("\n{0}Ctrl + C Detected! {1}Exit system{2}".format(colors.RED,colors.YELLOW,Style.RESET_ALL))
 sys.exit(0)
