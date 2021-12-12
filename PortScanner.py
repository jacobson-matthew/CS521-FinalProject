import nmap
import pyfiglet
import socket


def pingScan(url):
    address = socket.gethostbyname(url)
    openPorts = [0]*5041
    for port in range(1, 5041):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(0.004)
        result = s.connect_ex((address, port))
        if result == 0:
            openPorts[port] = 1
            print("Port {} is open".format(port))
        s.close()



def tcpHalfOpen(ip):
    # initialize the port scanner
    nmScan = nmap.PortScanner()

    nmScan.scan(ip, '1-5041')

    # run a loop to print all the found result about the ports
    for host in nmScan.all_hosts():
        print('Host : %s (%s)' % (host, nmScan[host].hostname()))
        print('State : %s' % nmScan[host].state())
        for proto in nmScan[host].all_protocols():
            print('----------')
            print('Protocol : %s' % proto)

            lport = nmScan[host][proto].keys()
            for port in lport:
                print('port : %s\tstate : %s' % (port, nmScan[host][proto][port]['state']))


if __name__ == "__main__":
    pyfiglet.print_figlet("Port Scanner")
    pyfiglet.print_figlet("Socket Science", font="bubble")
    start = input("Start?: Y/N\n")
    if start == "Y" or start == "y" or start == "Yes" or start == "Yes":
        url = input("Enter a URL to scan:\n")
        pingScan(url)
        tcpHalfOpen(url)


