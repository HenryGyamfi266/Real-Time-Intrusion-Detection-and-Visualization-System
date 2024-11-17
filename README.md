# Real-Time-Intrusion-Detection-and-Visualization-System
An advanced network security tool that monitors real time packets. 

## Project Overview
Purpose: To build a network intrusion detection system (IDS) that monitors network traffic, detects malicious activities, and provides real-time visualization of attack patterns.
### Key Technologies:
Scapy: For packet analysis and network traffic monitoring.
Matplotlib: For data visualization of attack patterns.
Threading: For running the IDS and dashboard visualization concurrently.
Python: The main programming language used for development.

## Objectives of the Project:
Real-Time Intrusion Detection: Implement both signature-based and anomaly-based detection mechanisms to identify common attack patterns (e.g., TCP SYN Floods, Ping of Death).
Network Traffic Monitoring: Continuously monitor traffic, detect spikes in activity, and alert for potential malicious behavior.
Data Visualization: Display attack patterns over time using Matplotlib for easy understanding of network security status.
Log Alerts: Record and store alerts for review and further analysis.

## How the Project Works:
Packet Capture and Analysis:
The system captures network packets using Scapy. The packets are analyzed to detect various attack signatures (e.g., SYN Floods, oversized ICMP packets).
Traffic anomalies, such as excessive packets from a single IP, are flagged as potential threats.

Signature-based Detection:
The system checks incoming packets against predefined attack patterns (e.g., TCP SYN Flood targeting port 80).

Anomaly-based Detection:
The system monitors traffic volume from individual IP addresses. If traffic from an IP exceeds a certain threshold, an alert is triggered.

Alert Logging:
Alerts are logged with timestamps and packet details to a file (alerts.log), allowing for easy tracking and review.

Dashboard Visualization:
Matplotlib generates a dynamic bar chart visualizing the attack patterns detected over time.
The dashboard updates at a set interval (e.g., every 5 seconds) to reflect new data.

Continuous Operation:
The IDS runs continuously, with packet sniffing and dashboard visualization operating in separate threads.
The dashboard updates periodically, displaying the most recent data about detected attacks.

## How to Run the Project:
Install Dependencies:
Ensure Python is installed. Install required libraries.

Run the Project:
Update the network interface in the code (e.g., Wi-Fi or Ethernet depending on your system).
Run the Python script:
python main.py

Monitor Output:
The system will continuously monitor network traffic, detect malicious activity, and display attack patterns in real-time on the terminal via Matplotlib.
Alerts will be logged to a file named alerts.log and shown on the console.

## Valuables for the Project:
Scalability: The system can be extended to detect a wider range of attacks or adapt to different network environments.
Security Knowledge: The project showcases a deep understanding of network protocols, security analysis, and real-time monitoring systems.
Real-World Application: This IDS can be deployed in cloud or on-premise environments, contributing to enhanced network security in enterprise systems.
Data Visualization: The ability to visualize network security data helps non-technical stakeholders understand attack trends and take proactive actions.
Alert System: Real-time alerts and logs provide crucial insights for network administrators and security analysts.

