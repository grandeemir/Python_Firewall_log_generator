import json
from collections import Counter

def analyze_firewall_logs(filename="firewall_logs.json", output_file="analysis_report.txt"):
    """
    Firewall loglarını analiz eder ve özet bilgileri hem ekrana hem dosyaya kaydeder.
    """
    try:
        # Log dosyasını oku
        with open(filename, "r") as file:
            logs = json.load(file)
    except FileNotFoundError:
        print(f"{filename} dosyası bulunamadı! Lütfen log dosyasını oluşturun.")
        return

    print(f"{filename} dosyasından {len(logs)} adet log yüklendi.")
    
    # Raporu bir dosyaya yazmak için liste başlat
    report = []

    # İşlem türlerine göre dağılım
    actions = [log["action"] for log in logs]
    action_counts = Counter(actions)
    report.append("İşlem Türlerine Göre Dağılım:")
    for action, count in action_counts.items():
        report.append(f"{action}: {count}")

    # Şüpheli IP adreslerini tespit et (ör. çok fazla 'BLOCK' alan IP'ler)
    blocked_ips = [log["src_ip"] for log in logs if log["action"] == "BLOCK"]
    most_blocked_ips = Counter(blocked_ips).most_common(5)
    report.append("\nEn Çok 'BLOCK' Alan IP Adresleri:")
    for ip, count in most_blocked_ips:
        report.append(f"{ip}: {count} kez")

    # Protokole göre analiz
    protocols = [log["protocol"] for log in logs]
    protocol_counts = Counter(protocols)
    report.append("\nProtokole Göre Trafik Analizi:")
    for protocol, count in protocol_counts.items():
        report.append(f"{protocol}: {count}")

    # En sık kullanılan kaynak ve hedef IP'ler
    src_ips = [log["src_ip"] for log in logs]
    dst_ips = [log["dst_ip"] for log in logs]
    most_common_src_ips = Counter(src_ips).most_common(5)
    most_common_dst_ips = Counter(dst_ips).most_common(5)

    report.append("\nEn Sık Kullanılan Kaynak IP'ler:")
    for ip, count in most_common_src_ips:
        report.append(f"{ip}: {count} kez")

    report.append("\nEn Sık Kullanılan Hedef IP'ler:")
    for ip, count in most_common_dst_ips:
        report.append(f"{ip}: {count} kez")

    # Analiz sonuçlarını ekrana yazdır
    print("\n".join(report))

    # Analiz sonuçlarını bir dosyaya kaydet
    with open(output_file, "w") as file:
        file.write("\n".join(report))
    
    print(f"\nAnaliz raporu '{output_file}' dosyasına kaydedildi.")

if __name__ == "__main__":
    # Log analizini çalıştır ve raporu kaydet
    analyze_firewall_logs("firewall_logs.json", "analysis_report.txt")
