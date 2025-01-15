import json
import random
from datetime import datetime, timedelta

def generate_firewall_logs(filename="firewall_logs.json", num_logs=100):
    """
    Sahte firewall logları oluştur ve bir JSON dosyasına kaydet.
    """
    def random_ip():
        return f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"

    def random_port():
        return random.randint(1024, 65535)

    protocols = ["TCP", "UDP", "ICMP"]
    actions = ["ALLOW", "DENY", "BLOCK"]

    logs = []
    for _ in range(num_logs):
        log = {
            "timestamp": (datetime.now() - timedelta(seconds=random.randint(0, 3600))).strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": random_ip(),
            "src_port": random_port(),
            "dst_ip": random_ip(),
            "dst_port": random_port(),
            "protocol": random.choice(protocols),
            "action": random.choice(actions)
        }
        logs.append(log)

    with open(filename, "w") as file:
        json.dump(logs, file, indent=4)

    print(f"{filename} dosyasına {num_logs} adet log kaydedildi.")

if __name__ == "__main__":
    # 100 adet sahte log oluştur
    generate_firewall_logs("firewall_logs.json", 1000)
