import argparse
import socket
import ssl
import threading
import asyncio
import random
import ipaddress
import subprocess
import websockets

# TCP Scan
def tcp_scan(ip, port):
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            if s.connect_ex((ip, port)) == 0:
                print(f"[+] TCP {ip}:{port} is open")
    except Exception:
        pass

# WebSocket Scan
async def ws_scan(ip, port):
    uri = f"ws://[{ip}]:{port}"
    try:
        async with websockets.connect(uri) as ws:
            print(f"[+] WebSocket {ip}:{port} is open")
    except Exception:
        pass

# ICMP Ping Scan (Uses System ping6 Command)
def icmp_scan(ip):
    try:
        result = subprocess.run(["ping6", "-c", "1", ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if "1 received" in result.stdout:
            print(f"[+] ICMP Ping {ip} is responsive")
    except Exception:
        pass

# SSL Scan
def ssl_scan(ip, port):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((ip, port), timeout=2) as sock:
            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                print(f"[+] SSL {ip}:{port} is open and valid")
    except Exception:
        pass

# UDP Scan
def udp_scan(ip, port):
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as s:
            s.settimeout(1)
            s.sendto(b"\x00", (ip, port))
            s.recvfrom(1024)  # Attempt to receive response
            print(f"[+] UDP {ip}:{port} is open")
    except socket.timeout:
        pass
    except Exception:
        pass

# Generate Random IPv6 Addresses from a Block
def generate_ipv6_addresses(ipv6_block, num_addresses=10):
    network = ipaddress.IPv6Network(ipv6_block, strict=False)
    return [str(ip) for ip in random.sample(list(network), min(num_addresses, len(network)))]

# Select Scan Method
def scan(ip, port, method):
    if method == "tcp":
        tcp_scan(ip, port)
    elif method == "ws":
        threading.Thread(target=lambda: asyncio.run(ws_scan(ip, port))).start()
    elif method == "ping":
        icmp_scan(ip)
    elif method == "ssl":
        ssl_scan(ip, port)
    elif method == "udp":
        udp_scan(ip, port)

# Main Function
def main():
    parser = argparse.ArgumentParser(description="IPv6 Scanner (No Root Required)")
    parser.add_argument("--block", type=str, required=True, help="IPv6 block to scan (e.g., 2001:db8::/64)")
    parser.add_argument("--method", type=str, choices=["tcp", "ws", "ping", "ssl", "udp"], required=True, help="Scan method")
    parser.add_argument("--port", type=int, default=443, help="Port to scan (default: 443)")
    parser.add_argument("--threads", type=int, default=10, help="Number of threads (default: 10)")

    args = parser.parse_args()

    ipv6_addresses = generate_ipv6_addresses(args.block, args.threads)

    threads = []
    for ip in ipv6_addresses:
        t = threading.Thread(target=scan, args=(ip, args.port, args.method))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

if __name__ == "__main__":
    main()
