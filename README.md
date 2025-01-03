# PacketFilterX
**PacketFilterX** is an advanced, real-time packet sniffer and network analyzer built for modern cybersecurity needs. This tool is designed to monitor, analyze, and detect suspicious network activities such as port scanning, ARP spoofing, and abnormal traffic patterns, all while providing live alerts and detailed logs.
## Features  

- **Real-Time Monitoring**: Captures and processes network packets as they traverse the interface.  
- **Anomaly Detection**: Detects and flags activities like port scanning and ARP spoofing.  
- **Categorized Packet Status**: Differentiates between normal and suspicious packets for immediate visibility.  
- **Comprehensive Logging**: Maintains detailed logs of activities and alerts for post-event analysis.  
- **Customizable Scans**: Choose your network interface and scanning duration for tailored monitoring.
## Installation  

Follow these steps to install and run PacketFilterX:
1.**Clone the Repository:**  
   ```bash
   git clone https://github.com/aKash-S19/PacketFilterX.git
   cd PacketFilterX
`````
2.**Install dependencies:**
```bash
For Windows :
pip install scapy
For Linux :
sudo pip install scapy
`````
3.**Run PacketFilterX:**
```bash
For Windows :
python PacketFilterX.py
For Linux :
sudo python PacketFilterX.py
`````
## Usage 
Start Monitoring:

- Select the network interface (e.g., eth0, wlan0).
- Define the scan duration.
- View live packet analysis and receive alerts for anomalies.
- View Logs:
```bash
Note:
Check detailed logs saved in PacketFilterX_logs.txt.
Use these logs for further investigation or reporting.
`````
- Stop Monitoring: The tool automatically stops after the defined duration or upon manual termination (Ctrl+C).

