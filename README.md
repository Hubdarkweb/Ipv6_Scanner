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

The error **"CRITICAL: Can't open /proc/net/dev"** usually occurs when running **Scapy** inside a restricted environment, such as:  

1. Running inside **Docker without necessary privileges**.  
2. Running **without root (sudo) privileges**.  
3. Running in **Windows without administrative rights**.  

---

### **Possible Solutions**

#### **1. Run as Root (Linux)**
If you're running this on Linux, try running the script with **sudo**:  
```sh
sudo python scanner.py --block 2001:db8::/64 --method ws --port 443 --threads 10
```

#### **2. Use --net=host in Docker**  
If running inside Docker, you need to provide **host networking**:  
```sh
docker run --net=host --cap-add=NET_ADMIN --cap-add=NET_RAW -it your-container
```
Or, if using **Docker Compose**, add:
```yaml
cap_add:
  - NET_ADMIN
  - NET_RAW
network_mode: "host"
```

#### **3. Ensure Scapy has Access to /proc Files**  
Check if the `/proc/net/dev` and `/proc/net/route` files exist:
```sh
ls -l /proc/net/dev /proc/net/route
```
If they don't exist, your system might be **hardened**, or the kernel restricts access.

#### **4. Manually Enable Packet Sniffing (Linux)**
Run:
```sh
sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)
```
Then retry your script.

#### **5. Check if You're Running Inside WSL**
If using **WSL (Windows Subsystem for Linux)**, ICMP and raw sockets may have issues. Try running the script in a **native Linux environment** instead.

---

### **Alternative: Use a Different Ping Method**
If `scapy` is the issue, modify the script to use the system **ping** command instead of Scapy:  

```python
import subprocess

def icmp_scan(ip):
    try:
        result = subprocess.run(["ping6", "-c", "1", ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if "1 received" in result.stdout:
            print(f"[+] ICMP Ping {ip} is responsive")
    except Exception as e:
        pass
```
This avoids the **Scapy /proc/net access issue**.

---

Try these fixes and let me know if you're still facing issues!
