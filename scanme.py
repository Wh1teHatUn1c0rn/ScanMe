import warnings
from cryptography.utils import CryptographyDeprecationWarning

# Suppress CryptographyDeprecationWarnings
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

import socket
import threading
import argparse
import random
from termcolor import colored
from queue import Queue
from scapy.all import IP, TCP, sr1, send

# Define a queue to manage threads
queue = Queue()
open_ports = []

# Function to grab the banner from an open port
def grab_banner(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        sock.connect((ip, port))
        banner = sock.recv(1024).decode().strip()
        sock.close()
        return banner
    except:
        return "No banner"

# Function to scan ports with decoys and fragmentation
def scan_port(ip, port, timeout, decoys=None, fragment=False):
    try:
        if decoys:
            decoy_ips = decoys.split(',')
            for decoy_ip in decoy_ips:
                # Send decoy packets
                pkt = IP(src=decoy_ip, dst=ip) / TCP(dport=port, flags="S")
                send(pkt, verbose=False)

        # Real scan packet
        pkt = IP(dst=ip) / TCP(dport=port, flags="S")
        
        if fragment:
            pkt = pkt.fragment(2)  

        # Send the packet and wait for a response
        response = sr1(pkt, verbose=False, timeout=timeout)

        if response is None:
            print(colored(f"[-] Port {port} is filtered or closed", "red"))
        else:
            # Port is open, attempt banner grabbing
            banner = grab_banner(ip, port)
            print(colored(f"[+] Port {port} is open: {banner}", "green"))
            open_ports.append((port, banner))
    except Exception as e:
        print(f"Error scanning port {port}: {e}")
        pass

# Function to handle threads
def worker(ip, timeout, decoys, fragment):
    while not queue.empty():
        port = queue.get()
        print(f"[DEBUG] Scanning port {port}")
        scan_port(ip, port, timeout, decoys, fragment)
        queue.task_done()

# Main function to manage the scanning process
def scan(target, ports, threads, timeout, decoys, fragment):
    print('\n' + f"Starting Fucking With {target}")
    random.shuffle(ports)

    for port in ports:
        queue.put(port)
    print(f"[DEBUG] Ports added to queue: {ports}")

    thread_list = []
    for _ in range(threads):
        thread = threading.Thread(target=worker, args=(target, timeout, decoys, fragment))
        thread_list.append(thread)
        thread.start()

    queue.join()

    for thread in thread_list:
        thread.join()

# Argument parsing
parser = argparse.ArgumentParser(description="Hold your butts here we goooo")
parser.add_argument("target", help="Target IP address or hostname")
parser.add_argument("-p", "--ports", help="Comma-separated list of ports to scan, e.g., 22,80,443")
parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads to use")
parser.add_argument("--timeout", type=float, default=0.5, help="Socket timeout duration")
parser.add_argument("-d", "--decoys", help="Comma-separated list of decoy IPs for stealth scanning")
parser.add_argument("-f", "--fragment", action="store_true", help="Enable packet fragmentation for evasion")
parser.add_argument("-o", "--output", help="Output file to save scan results")
args = parser.parse_args()

# Check if target is a single IP or a list
if ',' in args.target:
    print(colored("[*] Scanning multiple fuckers", "yellow"))
    targets = args.target.split(',')
else:
    targets = [args.target]

# Parse ports from comma-separated list
if args.ports:
    port_list = [int(port.strip()) for port in args.ports.split(',')]
else:
    port_list = list(range(1, 101))

# Start scanning
for target in targets:
    scan(target.strip(), port_list, args.threads, args.timeout, args.decoys, args.fragment)

# Output results to file if specified
if args.output:
    with open(args.output, "w") as file:
        for port, banner in open_ports:
            file.write(f"Port {port} is open: {banner}\n")
    print(colored(f"[*] Results saved to {args.output}", "blue"))
