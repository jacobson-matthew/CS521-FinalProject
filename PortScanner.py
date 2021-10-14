import pyfiglet

def scan(url):
    return ""

if __name__ == "__main__":
    pyfiglet.print_figlet("Port Scanner")
    pyfiglet.print_figlet("Socket Science", font="bubble")
    start = input("Start?: Y/N\n")
    if start == "Y" or start == "y" or start == "Yes" or start == "Yes":
        url = input("Enter a URL to scan:\n")
        print(scan(url))
