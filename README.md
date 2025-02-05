Here's a Python script that uses multithreading to scan all IP addresses in an IPv6 block. It includes support for the following types of scans:

- **Direct Connection Scan (TCP)**
- **WebSocket (WS) Scan**
- **ICMP Ping Scan**
- **SSL Scan**
- **UDP Port Scan**  

### **Features**:
- Uses `argparse` for command-line arguments.
- Uses `threading` for concurrent scanning.
- Supports scanning an IPv6 range.
- Supports user-defined thread count.

---

### **Install Required Dependencies**  
Ensure you have the necessary dependencies installed:

```sh
pip install websockets scapy
```

---

### **IPv6 Scanner Script**


---

### **Usage Examples**
#### **TCP Scan**
```sh
python scanner.py --block 2001:db8::/64 --method tcp --port 80 --threads 20
```

#### **WebSocket Scan**
```sh
python scanner.py --block 2001:db8::/64 --method ws --port 443 --threads 10
```

#### **ICMP Ping Scan**
```sh
python scanner.py --block 2001:db8::/64 --method ping --threads 10
```

#### **SSL Scan**
```sh
python scanner.py --block 2001:db8::/64 --method ssl --port 443 --threads 10
```

#### **UDP Port Scan**
```sh
python scanner.py --block 2001:db8::/64 --method udp --port 53 --threads 10
```

---

### **Notes:**
- This script uses **multithreading** for concurrency.
- For **WebSocket scanning**, it uses **asyncio & websockets**.
- The ICMP Ping scan uses `scapy` to send ICMPv6 Echo requests.
- The script samples a subset of IPs from the IPv6 block to avoid scanning an excessively large range.

Let me know if you need any modifications!
