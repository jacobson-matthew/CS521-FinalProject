import pyfiglet
import socket

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

if __name__ == "__main__":
    pyfiglet.print_figlet("Port Scanner")
    pyfiglet.print_figlet("Socket Science", font="bubble")
    start = input("Start?: Y/N\n")
    if start == "Y" or start == "y" or start == "Yes" or start == "Yes":
        url = input("Enter a URL to scan:\n")
        pingScan(url)
