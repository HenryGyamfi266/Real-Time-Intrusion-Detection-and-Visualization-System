import scapy.all as scapy
from datetime import datetime
import matplotlib.pyplot as plt
from collections import Counter
import threading
import time
import os

# Setting up the Configuration
interface = "Wi-Fi"  # Replace with your actual network interface (e.g., "Wi-Fi" or "Ethernet").
alert_log_file = "alerts.log"
dashboard_update_interval = 5  # Seconds between dashboard updates.

# Signature-based detection
signature_rules = {
    "TCP SYN Flood": {"flags": "S", "dport": 80},  # Example: TCP SYN Flood targeting port 80
    "Ping of Death": {"proto": "ICMP", "payload_size": 65535},  # Example: Oversized ICMP packets
}

# Variables for anomaly-based detection (e.g., traffic spikes)
traffic_count = Counter()  # Store traffic stats

# Alerts data for visualization
alerts_over_time = Counter()


#  Here I write the Logging function
def log_alert(alert_type, packet):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(alert_log_file, "a") as f:
        f.write(f"{timestamp} - Alert: {alert_type} - Source: {packet[scapy.IP].src}\n")
    print(f"[ALERT] {alert_type} detected from {packet[scapy.IP].src}")
    alerts_over_time[alert_type] += 1


# Here I do the Packet analysis function
def analyze_packet(packet):
    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        traffic_count[src_ip] += 1

        # Signature-based detection happens here
        for attack, rule in signature_rules.items():
            if (
                    "flags" in rule
                    and packet.haslayer(scapy.TCP)
                    and packet[scapy.TCP].flags == rule["flags"]
                    and packet[scapy.TCP].dport == rule["dport"]
            ):
                log_alert(attack, packet)

            elif (
                    "proto" in rule
                    and rule["proto"] == "ICMP"
                    and packet.haslayer(scapy.ICMP)
                    and len(packet[scapy.Raw]) == rule.get("payload_size", 0)
            ):
                log_alert(attack, packet)

        # Anomaly-based detection (e.g., excessive traffic from one IP)
        if traffic_count[src_ip] > 100:  # Example threshold
            log_alert("Traffic Spike", packet)


# Sniffer function
def start_sniffer():
    print(f"Starting packet capture on interface {interface}...")
    scapy.sniff(iface=interface, store=False, prn=analyze_packet)


# Here I write the Visualization function
def visualize_alerts():
    try:
        while True:
            # Simulate updating the dashboard
            print("No alerts detected yet." if not alerts_over_time else "### Attack Patterns Over Time ###")

            # If any alerts are present in the detection, this code displays them
            if alerts_over_time:
                print("### Attack Patterns Over Time ###")
                plt.bar(alerts_over_time.keys(), alerts_over_time.values(), color="red")
                plt.xlabel("Alert Types")
                plt.ylabel("Frequency")
                plt.title("Attack Patterns Over Time")
                plt.xticks(rotation=45)
                plt.tight_layout()
                plt.show(block=False)
                plt.pause(0.1)

            # Sleep for the specified interval
            time.sleep(dashboard_update_interval)

    except KeyboardInterrupt:
        print("\nExiting dashboard visualization...")


# Clear terminal function (cross-platform)
def clear_terminal():
    if os.name == 'nt':  # Windows
        os.system('cls')
    else:  # Linux/MacOS
        os.system('clear')


# running the Main function
if __name__ == "__main__":
    print("Starting Intrusion Detection System...")

    try:
        # Start the sniffer in a separate thread
        sniffer_thread = threading.Thread(target=start_sniffer, daemon=True)
        sniffer_thread.start()

        # Start dashboard visualization
        visualize_alerts()

    except Exception as e:
        print(f"An error occurred: {e}")
