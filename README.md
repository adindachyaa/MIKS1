# DEMO TASK 1
https://drive.google.com/file/d/1SzXcnRJ3SAWnS7uhOoQQGWb-_FgQqyha/view?usp=drivesdk

# 🛡️ Manajemen Insiden Keamanan Siber
## Implementasi SIEM dengan Wazuh di Azure Cloud

![Wazuh](https://img.shields.io/badge/Wazuh-4.7.5-blue)
![Azure](https://img.shields.io/badge/Platform-Microsoft%20Azure-0078D4)
![Ubuntu](https://img.shields.io/badge/OS-Ubuntu%2022.04%20LTS-orange)
![Status](https://img.shields.io/badge/Status-Completed-success)

---

## 📋 Daftar Isi

- [Deskripsi Proyek](#-deskripsi-proyek)
- [Anggota Kelompok & Pembagian Tugas](#-anggota-kelompok--pembagian-tugas)
- [Arsitektur Sistem](#-arsitektur-sistem)
- [Tugas 1 — Infrastruktur SIEM](#tugas-1---infrastruktur-siem)
- [Tugas 2 — Simulasi Serangan DDoS](#tugas-2---simulasi-serangan-ddos)
- [Tugas 3 — PoC Deteksi Insiden](#tugas-3---poc-deteksi-insiden)
- [Tugas 4 — Validasi Modul Malware (EICAR)](#tugas-4---validasi-modul-malware-eicar)
- [Tugas 5 — Analisis Log Density](#tugas-5---analisis-log-density)
- [Hasil & Kesimpulan](#-hasil--kesimpulan)

---

## 📌 Deskripsi Proyek

Proyek ini merupakan implementasi **Security Information and Event Management (SIEM)** menggunakan platform **Wazuh** yang di-deploy di **Microsoft Azure Cloud** (Student Free Tier). Sistem ini digunakan untuk mendeteksi dan merespons insiden keamanan siber, menguji kapabilitas sensor terhadap anomali jaringan, serta memvalidasi pendeteksian berkas berbahaya.

**Lingkup proyek:**
1. Deployment infrastruktur Wazuh (1 Manager + 2 Agents) di Azure.
2. Simulasi serangan DDoS (ICMP/Ping Flood) untuk menguji sistem.
3. Demonstrasi kemampuan deteksi Wazuh (*Critical Alerts*).
4. Validasi deteksi ancaman menggunakan berkas *malware dummy* EICAR.
5. Analisis kepadatan log (*Logging Density*) dan mitigasinya.

---

## 👥 Anggota Kelompok & Pembagian Tugas

| Peran | Nama | NRP | Tanggung Jawab |
|---|---|---|---|
| **Manager (Project Leader & SOC)** | Maritza Adelia | 5027241111 | Koordinasi, Tugas 3 (PoC Deteksi), Tugas 5 (Analisis Log), Laporan |
| **Manager (Project Leader & SOC)** | Oryza Qiara | 5027241084 | Setup Modul Malware (Tugas 4), FIM Monitoring, Dokumentasi GitHub |
| **Agent 1 (Red Team / Attacker)** | Nadia Kirana | 5027241007 | Tugas 2 (DDoS Scenario), Eksekusi Serangan ICMP/hping3 |
| **Agent 2 (SIEM Engineer)** | Adinda Cahya | 5027241117 | Tugas 1 (Infrastruktur), Deploy Wazuh VM, Azure NSG Routing |

---

## 🏗️ Arsitektur Sistem

```
┌─────────────────────────────────────────────────────┐
│              Microsoft Azure Cloud                  │
│                                                     │
│  ┌─────────────────┐     ┌──────────────────────┐   │
│  │  Wazuh Manager  │◄────│    wazuh-agent1      │   │
│  │ (70.153.25.20)  │     │    (Target/SOC)      │   │
│  │                 │◄────│    IP: 10.0.0.6      │   │
│  │  Dashboard ✅   │     └──────────────────────┘   │
│  │  Indexer   ✅   │                                │
│  │  Manager   ✅   │     ┌──────────────────────┐   │
│  └─────────────────┘◄────│    wazuh-agent2      │   │
│         │                │    (Attacker)        │   │
│         │                │    IP: 10.0.0.7      │   │
│         │                └──────────────────────┘   │
│    VNet: wazuh-manager-vnet                         │
└─────────────────────────────────────────────────────┘
```

**Spesifikasi VM:**

| VM | Nama | Private IP | Public IP | Fungsi |
|---|---|---|---|---|
| Manager | `wazuh-manager` | — | 70.153.25.20 | Pusat Kontrol, Pengumpul Log, & Dashboard |
| Agent 1 | `wazuh-agent1` | 10.0.0.6 | 70.153.25.28 | Target Serangan DDoS & Injeksi Malware |
| Agent 2 | `wazuh-agent2` | 10.0.0.7 | — | Mesin Penyerang (Attacker) |

---

## Tugas 1 - Infrastruktur SIEM (Agen 3)

### 1.1 Persiapan Azure & Kredensial

| Item | Nilai |
|---|---|
| Azure Portal Password | `azureMIKS2025` |
| Wazuh Dashboard URL | `https://70.153.25.20` |
| Wazuh Credentials | `admin` / `S9uWsCUXMx54?d?.+9HZM*+hTcXrq4ex` |

### 1.2 Verifikasi Infrastruktur

Memastikan seluruh agen berhasil terkoneksi ke Wazuh Manager dan berstatus **Active** sebelum pengujian keamanan dimulai.

![> 📸 Screenshot Referensi: `docum/WAZUH-DASHBOARD-AGENTS.jpeg`](docum/WAZUH-DASHBOARD-AGENTS.jpeg)

### 1.3 Konfigurasi Network Security Group (NSG)

Rules yang ditambahkan pada NSG Wazuh Manager:

| Priority | Nama | Port | Protocol | Fungsi |
|---|---|---|---|---|
| 100 | Allow-SSH | 22 | TCP | Akses SSH |
| 110 | Allow-Agent-Communication | 1514 | TCP | Komunikasi Agent |
| 120 | Allow-Agent-Enrollment | 1515 | TCP | Pendaftaran Agent |
| 130 | Allow-Wazuh-Dashboard | 443 | TCP | Akses Dashboard Web |
| 140 | Allow-Wazuh-API | 55000 | TCP | Wazuh REST API |

### 1.4 Instalasi Wazuh Manager

```bash
# Download installer
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
curl -sO https://packages.wazuh.com/4.7/config.yml

# Edit konfigurasi
nano config.yml

# Jalankan installer (dengan flag -i untuk skip OS check)
sudo bash wazuh-install.sh -a -i
```

**config.yml:**
```yaml
nodes:
  indexer:
    - name: node-1
      ip: "127.0.0.1"
  server:
    - name: wazuh-1
      ip: "127.0.0.1"
  dashboard:
    - name: dashboard
      ip: "127.0.0.1"
```

### 1.4 Instalasi Wazuh Agent

Dijalankan di setiap VM Agent:

```bash
# Tambah repository Wazuh
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --no-default-keyring \
--keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import

sudo chmod 644 /usr/share/keyrings/wazuh.gpg

echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] \
https://packages.wazuh.com/4.x/apt/ stable main" | \
sudo tee -a /etc/apt/sources.list.d/wazuh.list

sudo apt-get update

# Install Wazuh Agent versi 4.7.5
sudo WAZUH_MANAGER='10.0.0.5' \
     WAZUH_AGENT_NAME='agent1' \
     apt-get install wazuh-agent=4.7.5-1 -y

# Enable dan start service
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
```

### 1.5 Verifikasi Infrastruktur

```bash
# Cek status di Manager
sudo /var/ossec/bin/agent_control -l


> 📸 **[Tambahkan screenshot berikut di folder `screenshots/`]**
> - `azure-vm-list.png` → Daftar 4 VM status Running di Azure Portal
> - `wazuh-dashboard-agents.png` → Dashboard Wazuh menampilkan semua agent Active
> - `nsg-rules.png` → Konfigurasi NSG Manager
> - `terminal-service-running.png` → Status service Wazuh di terminal

**Hasil Dashboard Wazuh:**
```
Total agents  : 2 (akan menjadi 3 setelah Agent 3 terhubung)
Active agents : 2 ✅
Disconnected  : 0
```

---

## Tugas 2 - Simulasi Serangan DDoS (Agen 2)

### 2.1 Tools yang Digunakan

| Tool | Jenis Serangan | Keterangan |
|---|---|---|
| `hping3` | SYN Flood | Mengirim paket TCP SYN masif |
| `GoldenEye` | HTTP Flood | Membanjiri request HTTP |
| Python Script | Custom DDoS | Script serangan custom |

### 2.2 Persiapan Mesin Penyerang (Agent 2)

```bash
# Install hping3
sudo apt-get install hping3 -y

# Install tools pendukung
sudo apt-get install nmap netcat -y
```

### 2.3 Eksekusi Serangan SYN Flood

```bash
# SYN Flood ke Agent 1 (Target)
sudo hping3 -S --flood -V -p 80 <IP_TARGET>

# Dengan IP Spoofing (simulasi Distributed)
sudo hping3 -S --flood -V -p 80 --rand-source <IP_TARGET>
```

### 2.4 Eksekusi Serangan HTTP Flood

```bash
# Install GoldenEye
git clone https://github.com/jseidl/GoldenEye.git
cd GoldenEye
python3 goldeneye.py http://<IP_TARGET> -w 50 -s 500
```

### 2.5 Hasil (Screenshot)

> 📸 **[Tambahkan screenshot berikut di folder `screenshots/`]**
> - `attack-terminal.png` → Terminal saat serangan berjalan
> - `target-unreachable.png` → Bukti server target tidak dapat diakses (RTO)

---

## Tugas 3 - PoC Deteksi Insiden (Agen 1)

### 3.1 Monitoring Dashboard

Langkah monitoring saat serangan berlangsung:
1. Login ke dashboard: `https://70.153.25.20`
2. Buka menu **Wazuh → Security Events**
3. Filter by Agent 1 (target)
4. Pantau alert yang muncul secara real-time

### 3.2 Rule ID yang Relevan untuk DDoS

| Rule ID | Deskripsi | Level |
|---|---|---|
| 40101 | DoS attack detected | Critical |
| 40111 | SYN Flood detected | Critical |
| 31151 | Web server 400 error (anomali) | High |
| 5501 | Login brute force attempt | High |

### 3.3 Analisis Traffic Anomali

```bash
# Cek log di Agent 1 saat serangan
sudo tail -f /var/log/syslog | grep -i "flood\|ddos\|attack"

# Cek koneksi aktif
sudo ss -s
sudo netstat -an | grep SYN_RECV | wc -l
```

### 3.4 Hasil (Screenshot)

> 📸 **[Tambahkan screenshot berikut di folder `screenshots/`]**
> - `wazuh-critical-alerts.png` → Alert merah Critical di dashboard saat serangan
> - `traffic-anomaly.png` → Grafik traffic anomali di Wazuh
> - `rule-triggered.png` → Detail rule yang ter-trigger

---

## Tugas 4 - Analisis Log (Manajer)

### 4.1 Permasalahan Logging Density

Saat serangan DDoS terjadi, sistem menghasilkan log dalam jumlah sangat besar dalam waktu singkat. Hal ini menimbulkan beberapa masalah:

- **Overload Storage** → log memenuhi disk server
- **Performance Degradation** → proses analisis log menjadi lambat
- **Alert Fatigue** → terlalu banyak alert sehingga sulit menemukan yang kritis
- **Log Loss** → log bisa hilang jika buffer penuh

### 4.2 Solusi Log Rotation

```bash
# Konfigurasi logrotate untuk Wazuh
sudo nano /etc/logrotate.d/wazuh

# Isi konfigurasi:
/var/ossec/logs/ossec.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    postrotate
        /var/ossec/bin/ossec-control restart > /dev/null 2>&1
    endscript
}
```

### 4.3 Solusi Log Level Filtering

```bash
# Edit konfigurasi Wazuh Manager
sudo nano /var/ossec/etc/ossec.conf
```

```xml
<!-- Hanya catat log dengan level 7 ke atas (High & Critical) -->
<ossec_config>
  <alerts>
    <log_alert_level>7</log_alert_level>
    <email_alert_level>12</email_alert_level>
  </alerts>
</ossec_config>
```

### 4.4 Solusi Arsitektur — Log Aggregation

```
Agent 1 ──┐
Agent 2 ──┤──► Wazuh Manager ──► Wazuh Indexer ──► Dashboard
Agent 3 ──┘         │
                     └──► Log Archive (Cold Storage)
                              (Retensi 30 hari)
```

### 4.5 Rekomendasi Best Practice

| Masalah | Solusi | Implementasi |
|---|---|---|
| Log terlalu banyak | Log Level Filtering | Set minimum level 7 |
| Disk penuh | Log Rotation | Rotasi harian, simpan 7 hari |
| Alert fatigue | Alert Tuning | Whitelist traffic normal |
| Performance lambat | Log Compression | Kompres log > 1 hari |
| Kehilangan log | Log Forwarding | Kirim ke external storage |

---

## 📊 Hasil & Kesimpulan

### Hasil Keseluruhan

| Tugas | Status | Keterangan |
|---|---|---|
| Deploy Infrastruktur Wazuh | ✅ Selesai | Manager + 2 Agent Active |
| Simulasi Serangan DDoS | ✅ Selesai | SYN Flood & HTTP Flood berhasil |
| PoC Deteksi Insiden | ✅ Selesai | Critical alert terdeteksi Wazuh |
| Analisis Logging Density | ✅ Selesai | Solusi Log Rotation & Filtering |

### Kesimpulan

Wazuh terbukti mampu:
1. **Mendeteksi** traffic anomali saat serangan DDoS berlangsung
2. **Menghasilkan** critical alerts secara real-time
3. **Memonitor** seluruh infrastruktur dari satu dashboard terpusat
4. **Mencatat** semua aktivitas mencurigakan dalam bentuk log terstruktur

### Rekomendasi

- Implementasikan **auto-blocking** menggunakan Wazuh Active Response
- Tambahkan **rate limiting** di level NSG Azure
- Gunakan **Azure DDoS Protection** untuk proteksi tambahan
- Lakukan **log archiving** ke Azure Blob Storage untuk penyimpanan jangka panjang

---

## 📁 Struktur Repository

```
📁 wazuh-siem-project/
├── 📄 README.md
├── 📁 infrastructure/          (Agen 3)
│   ├── config.yml
│   └── nsg-rules.md
├── 📁 attack/                  (Agen 2)
│   ├── syn-flood.sh
│   └── http-flood.py
├── 📁 detection/               (Agen 1)
│   └── alert-rules.md
├── 📁 analysis/                (Manajer)
│   └── logging-density.md
└── 📁 screenshots/
    ├── azure-vm-list.png
    ├── wazuh-dashboard-agents.png
    ├── attack-terminal.png
    └── wazuh-critical-alerts.png
```

---

## 🔗 Referensi

- [Wazuh Official Documentation](https://documentation.wazuh.com)
- [Wazuh Installation Guide](https://documentation.wazuh.com/current/installation-guide/index.html)
- [Azure Virtual Machines Documentation](https://docs.microsoft.com/en-us/azure/virtual-machines/)
- [hping3 Manual](https://linux.die.net/man/8/hping3)

---

*Dibuat untuk memenuhi tugas mata kuliah Manajemen Insiden Keamanan Siber*  
*Institut Teknologi Sepuluh Nopember (ITS) Surabaya*
