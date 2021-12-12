
import pyfiglet
import socket
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.layers.inet import IP, TCP, ICMP
from scapy.sendrecv import sr1
from scapy.volatile import RandShort


def pingScan(url):
    address = socket.gethostbyname(url)
    openPorts = [0]*65535
    for port in range(1, 65535):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(0.004)
        result = s.connect_ex((address, port))
        if result == 0:
            openPorts[port] = 1
            print("Port {} is open".format(port))
        s.close()

def tcpHalfOpenScan(url):

    dst_ip = "10.0.0.1"
    src_port = RandShort()
    dst_port = 80
    ip = IP(dst=dst_ip)
    tcp = TCP(sport=src_port, dport=dst_port, flags="S")
    stealth_scan_resp = sr1(ip / tcp, timeout = 10)
    if (str(type(stealth_scan_resp)) ==" < type ‘NoneType’ > "):
        print("Filtered")
    elif(stealth_scan_resp.haslayer(TCP)):
        if (stealth_scan_resp.getlayer(TCP).flags == 0x12):
            send_rst = sr1(IP(dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="R"), timeout = 10)
            print("Open")
        elif(stealth_scan_resp.getlayer(TCP).flags == 0x14):
            print("Closed")
        elif(stealth_scan_resp.haslayer(ICMP)):
            if (int(stealth_scan_resp.getlayer(ICMP).type) == 3 and int(stealth_scan_resp.getlayer(ICMP).code) in [1, 2,
                                                                                                                   3, 9,
                                                                                                                   10,
                                                                                                                   13]):
                print("Filtered")

if __name__ == "__main__":
    tcpHalfOpenScan("a")
    # pyfiglet.print_figlet("Port Scanner")
    # pyfiglet.print_figlet("Socket Science", font="bubble")
    # start = input("Start?: Y/N\n")
    # if start == "Y" or start == "y" or start == "Yes" or start == "Yes":
    #     url = input("Enter a URL to scan:\n")
    #     pingScan(url)


