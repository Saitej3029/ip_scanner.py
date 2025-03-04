# 🔍 IP Scanner Tool

A powerful and automated **IP scanning tool** that performs multiple security checks, including:
- Ping Scan (Check if the host is online)
- Nmap Scan (TCP, UDP, OS detection, and service detection)
- Shodan Lookup (Get public data about an IP)
- Whois Lookup (Find IP ownership details)
- Reverse DNS Lookup (Check PTR records)
- GeoIP Lookup (Find the location of an IP)
- Subdomain Enumeration (Find subdomains of a target)

##  Features
✅ Real-time output – Results are displayed instantly in the terminal  
✅ Automated scanning – No manual selection needed  
✅ Timeout handling – Skips slow scans after 50 seconds  
✅ Easy installation – Works on **Linux, Windows, and macOS**  
✅ No file saving – All results are printed directly to the terminal  

---

## **🛠 Installation Guide**
###  For Linux (Ubuntu, Debian, Kali, Arch, Fedora, CentOS)**
1️⃣ Install Python & Pip:
   
 ```bash
   sudo apt update && sudo apt install python3 python3-pip -y  # Ubuntu/Debian/Kali
   sudo yum install python3 python3-pip -y  # Fedora/CentOS
   sudo pacman -S python python-pip  # Arch Linux
   ```

2️⃣ Install NMAP :
   ```bash
   sudo apt install nmap -y  # Ubuntu/Debian/Kali
   sudo yum install nmap -y  # Fedora/CentOS
   sudo pacman -S nmap  # Arch Linux
```
3️⃣ Install required Python libraries:
```bash
   pip3 install python-nmap requests shodan
```
4️⃣ Run the script:
```bash
   python3 ip_scanner.py
```
### For macOS
1️⃣ Install Homebrew (if not installed):
```bash
  /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```
 2️⃣ Install Python & Nmap:
 ```bash
    brew install python3 nmap
```
3️⃣ Install required Python libraries:
```bash
   pip3 install python-nmap requests shodan
```
4️⃣ Run the script:
```bash
   python3 ip_scanner.py
```

### For Windows
1️⃣ Install Python 3 from Python Official Site
⚠️ IMPORTANT: During installation, check "Add Python to PATH"
2️⃣ Install Nmap from Nmap Download and add it to system PATH

3️⃣ Install required Python libraries:
```bash
  pip install python-nmap requests shodan
```
4️⃣ Run the script:
```bash
    python ip_scanner.py
```

🎯 How to Use
1️⃣ Run the script:
```bash
   python3 ip_scanner.py  # Linux/macOS
   python ip_scanner.py   # Windows
```
2️⃣ Enter a target IP or domain:
```bash
    Enter target IP or domain: 8.8.8.8
```
📌 Example Output

   ==================================================
[+] Ping Scan - 8.8.8.8
==================================================
[+] Host is online.

==================================================
[+] Nmap Scan - 8.8.8.8
==================================================
[+] TCP Scan (-sT)
    Port 80/tcp -> open
    Port 443/tcp -> open

[+] UDP Scan (-sU)
    Port 53/udp -> open

==================================================
[+] Whois Lookup - 8.8.8.8
==================================================
  Name: Google LLC
  Country: US
  CIDR: 8.8.8.0/24

==================================================
[+] Shodan Lookup - 8.8.8.8
==================================================
  Organization: Google
  ISP: Google LLC
  Country: United States
  Open Ports: 80, 443, 53



🛠 Troubleshooting
🔹 Permission Denied for Nmap?

   #Run the script with sudo on Linux/macOS:
```bash
      sudo python3 ip_scanner.py
```
🔹 ModuleNotFoundError?

   #Install the missing Python package:
```bash
      pip install missing_package_name
```
🔹 Nmap Not Found on Windows?
     Ensure Nmap is added to the system PATH during installation

🔹 Shodan API Key Missing?
    Either remove the shodan_lookup() function or get a free API key from Shodan.io

    

   
 # MIT License

Copyright (c) 2024 [Cyber cafe]

Permission is hereby granted, free of charge, to any person obtaining a copy  
of this software and associated documentation files (the "Software"), to deal  
in the Software without restriction, including without limitation the rights  
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell  
copies of the Software, and to permit persons to whom the Software is  
furnished to do so, subject to the following conditions:

1. The software **must not** be used for illegal activities.  
2. This software is provided "as-is" without warranty of any kind.  
3. The author is **not responsible** for any misuse of this software.  

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR  
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,  
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE  
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER  
LIABILITY.


#  Contributing

Pull requests are welcome! for major changes,please open as issue first.


#  Contact

For any issues,reach out via GitHub Issues or email us at cybercafestu@gmail.com.
