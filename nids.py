import yaml
from collections import defaultdict
from scapy.all import sniff, IP, TCP
from elasticsearch import Elasticsearch
import smtplib

print("[+] NIDS script started...")

# Load rules
try:
    with open("rules.yml", "r") as file:
        print("[+] Loading rules...")
        rules = yaml.safe_load(file)["rules"]
        print("[+] Rules loaded successfully!")
except Exception as e:
    print(f"[ERROR] Failed to load rules.yml: {e}")
    exit(1)

# Attack counters
attack_counters = defaultdict(int)

# Elasticsearch setup
try:
    print("[+] Connecting to Elasticsearch...")
    es = Elasticsearch(["http://localhost:9200"])
    if not es.ping():
        print("[ERROR] Elasticsearch connection failed!")
        exit(1)
    print("[+] Connected to Elasticsearch successfully!")
except Exception as e:
    print(f"[ERROR] Failed to connect to Elasticsearch: {e}")
    exit(1)

# Email Alert Function
def send_email_alert(message):
    sender = "your_sending_email"
    recipient = "your_recieving_email"
    subject = "NIDS Alert"
    email_body = f"Subject: {subject}\n\n{message}"
    
    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login("eamil_username","password") # try generating app password from gmail by searching app passwords and use that password here not actual passowrd as gmail does not allow login to weak apps.
            server.sendmail(sender, recipient, email_body)
        print("[+] Email alert sent successfully!")
    except Exception as e:
        print(f"[ERROR] Failed to send email alert: {e}")

# Packet Handler
def detect_attack(packet):
    print("[+] Packet captured:", packet.summary())

    if packet.haslayer(TCP):
        try:
            src_ip = packet[IP].src
            dst_port = packet[TCP].dport
            print(f"[+] Checking rules for packet from {src_ip} to port {dst_port}...")

            for rule in rules:
                if rule["protocol"] == "TCP" and dst_port == rule["dst_port"]:
                    print(f"[!] Match found for port {dst_port}! Updating attack counter...")
                    attack_counters[src_ip] += 1

                    if attack_counters[src_ip] >= rule["threshold"]:
                        alert_msg = f"{rule['message']} from {src_ip}"

                        # Log to Elasticsearch
                        print("[+] Logging alert to Elasticsearch...")
                        es.index(index="nids_alerts", body={"message": alert_msg, "ip": src_ip})

                        # Send Email Alert
                        print("[+] Sending email alert...")
                        send_email_alert(alert_msg)

                        print(f"[ALERT] {alert_msg}")
        except Exception as e:
            print(f"[ERROR] Issue in detect_attack function: {e}")

# Start Sniffing
try:
    print("[+] Starting packet sniffing on eth0...")
    sniff(iface="eth0", filter="tcp", prn=detect_attack, store=0)
except Exception as e:
    print(f"[ERROR] Failed to start sniffing: {e}")
