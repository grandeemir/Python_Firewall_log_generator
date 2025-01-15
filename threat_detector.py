import json
from collections import Counter

def detect_threats(filename="firewall_logs.json", threshold_block=5, threshold_attempts=10, output_file="threat_report.txt"):
    """
    Firewall loglarında şüpheli davranışları tespit eder ve raporlar.
    """
    try:
        # Log dosyasını oku
        with open(filename, "r") as file:
            logs = json.load(file)
    except FileNotFoundError:
        print(f"{filename} dosyası bulunamadı! Lütfen log dosyasını oluşturun.")
        return

    print(f"{filename} dosyasından {len(logs)} adet log yüklendi.")

    # Şüpheli davranışlar için rapor başlat
    report = ["Şüpheli Davranış Tespiti"]

    # Çok fazla "BLOCK" alan IP'leri tespit et
    blocked_ips = [log["src_ip"] for log in logs if log["action"] == "BLOCK"]
    most_blocked_ips = Counter(blocked_ips).most_common()
    suspicious_blocked_ips = [ip for ip, count in most_blocked_ips if count >= threshold_block]

    report.append("\nÇok Fazla 'BLOCK' Alan Şüpheli IP Adresleri:")
    if suspicious_blocked_ips:
        for ip in suspicious_blocked_ips:
            count = dict(most_blocked_ips)[ip]
            report.append(f"{ip}: {count} kez BLOCK almış.")
    else:
        report.append("Hiçbir IP belirtilen eşik değerini aşmadı.")

    # Tekrarlayan bağlantı denemelerini tespit et
    src_dst_pairs = [(log["src_ip"], log["dst_ip"]) for log in logs]
    repeated_attempts = Counter(src_dst_pairs).most_common()
    suspicious_attempts = [pair for pair, count in repeated_attempts if count >= threshold_attempts]

    report.append("\nTekrarlayan Bağlantı Denemeleri:")
    if suspicious_attempts:
        for pair in suspicious_attempts:
            count = dict(repeated_attempts)[pair]
            report.append(f"{pair[0]} -> {pair[1]}: {count} kez bağlantı denemesi.")
    else:
        report.append("Hiçbir bağlantı çifti belirtilen eşik değerini aşmadı.")

    # Analiz sonuçlarını ekrana yazdır
    print("\n".join(report))

    # Analiz sonuçlarını bir dosyaya kaydet
    with open(output_file, "w") as file:
        file.write("\n".join(report))
    
    print(f"\nTehdit raporu '{output_file}' dosyasına kaydedildi.")

if __name__ == "__main__":
    # Şüpheli davranışları tespit et ve raporu kaydet
    detect_threats("firewall_logs.json", threshold_block=5, threshold_attempts=10, output_file="threat_report.txt")
