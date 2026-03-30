#!/usr/bin/env python3
"""
╔══════════════════════════════════╗
║         P O R T   S C A N        ║
║   Ağ Port Tarayıcı - v2.0        ║
╚══════════════════════════════════╝
Kullanım:
  python3 scan.py <hedef> <portlar> [seçenekler]

Örnekler:
  python3 scan.py 192.168.1.1 80
  python3 scan.py 192.168.1.1 1-1024 --proto tcp --is 100
  python3 scan.py 192.168.1.1-192.168.1.5 22,80,443 --proto all
  python3 scan.py 192.168.1.1 1-65535 --proto tcp --is 200 --rapor sonuc.html
"""

import socket
import threading
import ipaddress
import json
import time
import queue
import sys
import argparse
import os
from datetime import datetime

# ─── Renkler ──────────────────────────────────────────────────────────────────
class R:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    GREEN   = "\033[92m"
    RED     = "\033[91m"
    YELLOW  = "\033[93m"
    CYAN    = "\033[96m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    WHITE   = "\033[97m"
    GRAY    = "\033[90m"

def renkli(metin, *kodlar):
    return "".join(kodlar) + metin + R.RESET

# ─── Sabitler ─────────────────────────────────────────────────────────────────
ZAMAN_ASIMI     = 0.5
BANNER_BOYUTU   = 1024

# Yaygın port → servis adı eşlemesi
SERVISLER = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 465: "SMTPS",
    587: "SMTP/TLS", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
    1900: "UPnP", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    27017: "MongoDB",
}

# ─── Sonuç Sınıfı ─────────────────────────────────────────────────────────────
class Sonuc:
    def __init__(self, ip, port, proto, durum, banner=""):
        self.ip     = str(ip)
        self.port   = port
        self.proto  = proto
        self.durum  = durum
        self.banner = banner
        self.servis = SERVISLER.get(port, "")

    @property
    def acik(self):
        return "açık" in self.durum.lower()

    def sozluk(self):
        d = {
            "ip": self.ip,
            "port": self.port,
            "protokol": self.proto,
            "durum": self.durum,
            "servis": self.servis,
        }
        if self.banner:
            d["banner"] = self.banner
        return d

# ─── Port Tarama Fonksiyonları ────────────────────────────────────────────────
def tcp_tara(ip, port):
    s = Sonuc(ip, port, "TCP", "kapalı")
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(ZAMAN_ASIMI)
        sock.connect((str(ip), port))
        s.durum = "açık"
        # Banner grabbing
        try:
            if port == 80:
                sock.sendall(b"GET / HTTP/1.0\r\nHost: " + str(ip).encode() + b"\r\n\r\n")
            banner_ham = sock.recv(BANNER_BOYUTU).decode("utf-8", errors="ignore")
            s.banner = banner_ham.strip()
        except Exception:
            pass
    except socket.timeout:
        s.durum = "filtrelenmiş"
    except ConnectionRefusedError:
        s.durum = "kapalı"
    except socket.error:
        s.durum = "kapalı"
    finally:
        if sock:
            sock.close()
    return s

def udp_tara(ip, port):
    s = Sonuc(ip, port, "UDP", "belirsiz")
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(ZAMAN_ASIMI)
        sock.sendto(b"\x00", (str(ip), port))
        data, _ = sock.recvfrom(BANNER_BOYUTU)
        s.durum = "açık"
        s.banner = data.decode("utf-8", errors="ignore").strip()
    except socket.timeout:
        s.durum = "filtrelenmiş/açık"
    except socket.error:
        s.durum = "kapalı"
    finally:
        if sock:
            sock.close()
    return s

# ─── İş Parçacığı Yönetimi ───────────────────────────────────────────────────
kilit       = threading.Lock()
gorev_kuyrugu = queue.Queue()
tum_sonuclar  = []
acik_sayac    = 0
taranan_sayac = 0
toplam_gorev  = 0

def isci():
    global acik_sayac, taranan_sayac
    while True:
        try:
            ip, port, proto = gorev_kuyrugu.get(timeout=1)
        except queue.Empty:
            break

        if proto == "TCP":
            s = tcp_tara(ip, port)
        else:
            s = udp_tara(ip, port)

        with kilit:
            tum_sonuclar.append(s)
            taranan_sayac += 1
            if s.acik:
                acik_sayac += 1
                # Canlı çıktı
                servis_adi = f" {renkli(s.servis, R.CYAN)}" if s.servis else ""
                banner_ozet = ""
                if s.banner:
                    ilk_satir = s.banner.split("\n")[0][:60]
                    banner_ozet = f"  {renkli('↳ ' + ilk_satir, R.GRAY)}"
                print(
                    f"  {renkli('●', R.GREEN)} "
                    f"{renkli(s.ip, R.WHITE)}:{renkli(str(s.port), R.BOLD + R.WHITE)} "
                    f"{renkli(f'[{s.proto}]', R.BLUE)}"
                    f"{servis_adi}"
                    f"{banner_ozet}"
                )

        gorev_kuyrugu.task_done()

# ─── Argüman Ayrıştırma ───────────────────────────────────────────────────────
def argumanlari_ayristir():
    p = argparse.ArgumentParser(
        description="Port Tarayıcı",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    p.add_argument("hedef",
        help="IP adresi veya aralığı (örn: 192.168.1.1 veya 192.168.1.1-192.168.1.10)")
    p.add_argument("portlar", nargs="?", default=None,
        help="Port, aralık veya liste (örn: 80 | 1-1024 | 22,80,443) — verilmezse 1-65535 taranır")
    p.add_argument("--proto", default="tcp", choices=["tcp","udp","all"],
        help="Protokol: tcp / udp / all  (varsayılan: tcp)")
    p.add_argument("--is", dest="is_parcacigi", type=int, default=50, metavar="SAYI",
        help="İş parçacığı sayısı  (varsayılan: 50)")
    p.add_argument("--rapor", metavar="DOSYA",
        help="HTML rapor çıktısı (örn: sonuc.html)")
    return p.parse_args()

# ─── Yardımcı: IP Listesi ─────────────────────────────────────────────────────
def ip_listesi(hedef):
    if "-" in hedef:
        bas, son = hedef.rsplit("-", 1)
        try:
            bas_ip = ipaddress.ip_address(bas)
            son_ip = ipaddress.ip_address(son)
        except ValueError:
            # 192.168.1.1-10 formatı
            parca = bas.rsplit(".", 1)
            son_ip = ipaddress.ip_address(parca[0] + "." + son)
            bas_ip = ipaddress.ip_address(bas)
        liste = []
        cur = bas_ip
        while cur <= son_ip:
            liste.append(cur)
            cur += 1
        return liste
    else:
        return [ipaddress.ip_address(hedef)]

# ─── Yardımcı: Port Listesi ───────────────────────────────────────────────────
def port_listesi(portlar_str):
    portlar = []
    for parca in portlar_str.split(","):
        parca = parca.strip()
        if "-" in parca:
            bas, son = parca.split("-", 1)
            portlar.extend(range(int(bas), int(son)+1))
        else:
            portlar.append(int(parca))
    return portlar

# ─── HTML Rapor ───────────────────────────────────────────────────────────────
def html_rapor_olustur(dosya, meta):
    acik_sonuclar = [s for s in tum_sonuclar if s.acik]
    acik_sonuclar.sort(key=lambda x: x.port)

    satirlar = ""
    for s in acik_sonuclar:
        banner_html = ""
        if s.banner:
            ilk_satir = s.banner.split("\n")[0][:120]
            banner_html = f'<span class="banner">{ilk_satir}</span>'
        satirlar += f"""
        <tr>
          <td class="ip">{s.ip}</td>
          <td class="port">{s.port}</td>
          <td class="proto {s.proto.lower()}">{s.proto}</td>
          <td class="servis">{s.servis or '—'}</td>
          <td class="durum acik">● Açık</td>
          <td class="banner-cell">{banner_html}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Port Tarama Raporu — {meta['hedef']}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@300;400;600&display=swap');

  :root {{
    --bg:      #0d1117;
    --surface: #161b22;
    --border:  #21262d;
    --accent:  #58a6ff;
    --green:   #3fb950;
    --yellow:  #d29922;
    --red:     #f85149;
    --purple:  #bc8cff;
    --text:    #e6edf3;
    --muted:   #8b949e;
  }}

  * {{ box-sizing: border-box; margin: 0; padding: 0; }}

  body {{
    background: var(--bg);
    color: var(--text);
    font-family: 'IBM Plex Sans', sans-serif;
    min-height: 100vh;
    padding: 2.5rem 2rem;
  }}

  header {{
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    margin-bottom: 2.5rem;
    padding-bottom: 1.5rem;
    border-bottom: 1px solid var(--border);
  }}

  .logo {{
    font-family: 'IBM Plex Mono', monospace;
    font-size: 1.6rem;
    font-weight: 600;
    letter-spacing: -0.5px;
    color: var(--accent);
  }}
  .logo span {{ color: var(--muted); font-weight: 400; }}

  .meta {{
    text-align: right;
    font-family: 'IBM Plex Mono', monospace;
    font-size: 0.78rem;
    color: var(--muted);
    line-height: 1.8;
  }}
  .meta strong {{ color: var(--text); }}

  .istatistikler {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 1rem;
    margin-bottom: 2rem;
  }}

  .kart {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1.2rem 1.5rem;
  }}
  .kart-baslik {{
    font-size: 0.72rem;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: var(--muted);
    margin-bottom: 0.5rem;
    font-family: 'IBM Plex Mono', monospace;
  }}
  .kart-deger {{
    font-family: 'IBM Plex Mono', monospace;
    font-size: 2rem;
    font-weight: 600;
    color: var(--accent);
  }}
  .kart-deger.yesil {{ color: var(--green); }}
  .kart-deger.sari  {{ color: var(--yellow); }}

  table {{
    width: 100%;
    border-collapse: collapse;
    font-family: 'IBM Plex Mono', monospace;
    font-size: 0.85rem;
  }}

  thead tr {{
    border-bottom: 2px solid var(--border);
  }}

  th {{
    text-align: left;
    padding: 0.75rem 1rem;
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: var(--muted);
    font-weight: 500;
  }}

  tbody tr {{
    border-bottom: 1px solid var(--border);
    transition: background 0.15s;
  }}
  tbody tr:hover {{ background: rgba(88,166,255,0.04); }}

  td {{ padding: 0.7rem 1rem; vertical-align: middle; }}

  .ip     {{ color: var(--text); }}
  .port   {{ color: var(--accent); font-weight: 600; }}
  .proto.tcp  {{ color: var(--purple); }}
  .proto.udp  {{ color: var(--yellow); }}
  .servis     {{ color: var(--muted); }}
  .durum.acik {{ color: var(--green); }}

  .banner-cell {{ max-width: 360px; }}
  .banner {{
    display: inline-block;
    background: rgba(255,255,255,0.04);
    border-radius: 4px;
    padding: 0.15rem 0.5rem;
    font-size: 0.75rem;
    color: var(--muted);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    max-width: 100%;
  }}

  .bos {{
    text-align: center;
    padding: 4rem;
    color: var(--muted);
    font-family: 'IBM Plex Mono', monospace;
  }}

  footer {{
    margin-top: 3rem;
    padding-top: 1rem;
    border-top: 1px solid var(--border);
    font-size: 0.75rem;
    color: var(--muted);
    font-family: 'IBM Plex Mono', monospace;
    text-align: center;
  }}
</style>
</head>
<body>

<header>
  <div>
    <div class="logo">PORT<span>SCAN</span></div>
    <div style="font-size:0.8rem;color:var(--muted);margin-top:0.3rem;">Ağ Port Tarama Raporu</div>
  </div>
  <div class="meta">
    <div><strong>Hedef</strong> &nbsp; {meta['hedef']}</div>
    <div><strong>Portlar</strong> &nbsp; {meta['portlar']}</div>
    <div><strong>Protokol</strong> &nbsp; {meta['proto'].upper()}</div>
    <div><strong>Tarih</strong> &nbsp; {meta['tarih']}</div>
    <div><strong>Süre</strong> &nbsp; {meta['sure']:.2f}s</div>
  </div>
</header>

<div class="istatistikler">
  <div class="kart">
    <div class="kart-baslik">Taranan Port</div>
    <div class="kart-deger">{meta['toplam_port']}</div>
  </div>
  <div class="kart">
    <div class="kart-baslik">Açık Port</div>
    <div class="kart-deger yesil">{len(acik_sonuclar)}</div>
  </div>
  <div class="kart">
    <div class="kart-baslik">Taranan IP</div>
    <div class="kart-deger">{meta['ip_sayisi']}</div>
  </div>
  <div class="kart">
    <div class="kart-baslik">Tamamlanma</div>
    <div class="kart-deger sari">{meta['sure']:.1f}s</div>
  </div>
</div>

<table>
  <thead>
    <tr>
      <th>IP Adresi</th>
      <th>Port</th>
      <th>Proto</th>
      <th>Servis</th>
      <th>Durum</th>
      <th>Banner</th>
    </tr>
  </thead>
  <tbody>
    {"<tr><td colspan='6' class='bos'>Açık port bulunamadı.</td></tr>" if not acik_sonuclar else satirlar}
  </tbody>
</table>

<footer>PORTSCAN v2.0 · {meta['tarih']} · {meta['toplam_port']} port tarandı</footer>

</body>
</html>"""

    with open(dosya, "w", encoding="utf-8") as f:
        f.write(html)

# ─── Ana Fonksiyon ────────────────────────────────────────────────────────────
def main():
    args = argumanlari_ayristir()

    # Port belirtilmemişse tüm portları tara
    tam_tarama = args.portlar is None
    portlar_str = args.portlar if args.portlar else "1-65535"

    # IP ve port listelerini oluştur
    try:
        ipler   = ip_listesi(args.hedef)
        portlar = port_listesi(portlar_str)
    except ValueError as e:
        print(renkli(f"✗ Hata: {e}", R.RED))
        sys.exit(1)

    if not all(1 <= p <= 65535 for p in portlar):
        print(renkli("✗ Port numaraları 1-65535 arasında olmalıdır.", R.RED))
        sys.exit(1)

    protokoller = []
    if args.proto in ("tcp", "all"):
        protokoller.append("TCP")
    if args.proto in ("udp", "all"):
        protokoller.append("UDP")

    toplam = len(ipler) * len(portlar) * len(protokoller)

    # ─── Başlık ───────────────────────────────────────────────────────────────
    print()
    print(renkli("╔══════════════════════════════════╗", R.CYAN + R.DIM))
    print(renkli("║  ", R.CYAN + R.DIM) + renkli("P O R T  S C A N  v2.0", R.BOLD + R.WHITE) + renkli("        ║", R.CYAN + R.DIM))
    print(renkli("╚══════════════════════════════════╝", R.CYAN + R.DIM))
    print()
    print(f"  {renkli('Hedef   ', R.GRAY)}  {renkli(args.hedef, R.WHITE + R.BOLD)}")

    if tam_tarama:
        portlar_goster = "1-65535  " + renkli("← port belirtilmedi, tüm portlar taranıyor", R.YELLOW)
    else:
        portlar_goster = portlar_str
    print(f"  {renkli('Portlar ', R.GRAY)}  {portlar_goster}")

    print(f"  {renkli('Protokol', R.GRAY)}  {renkli(args.proto.upper(), R.WHITE)}")
    print(f"  {renkli('İş Par. ', R.GRAY)}  {renkli(str(args.is_parcacigi), R.WHITE)}")
    print(f"  {renkli('Toplam  ', R.GRAY)}  {renkli(str(toplam) + ' görev', R.WHITE)}")
    print()
    print(renkli("  ─" * 20, R.GRAY + R.DIM))
    print(renkli("  Açık portlar:", R.GRAY))
    print()

    baslangic = time.time()

    # Görevleri kuyruğa ekle
    for ip in ipler:
        for port in portlar:
            for proto in protokoller:
                gorev_kuyrugu.put((ip, port, proto))

    # İş parçacıklarını başlat
    parcaciklar = []
    for _ in range(min(args.is_parcacigi, toplam)):
        t = threading.Thread(target=isci, daemon=True)
        parcaciklar.append(t)
        t.start()

    gorev_kuyrugu.join()

    sure = time.time() - baslangic

    # ─── Özet ─────────────────────────────────────────────────────────────────
    print()
    print(renkli("  ─" * 20, R.GRAY + R.DIM))
    print()
    print(f"  {renkli('✓', R.GREEN + R.BOLD)} Tarama tamamlandı  "
          f"{renkli(f'{sure:.2f}s', R.CYAN)}  ·  "
          f"{renkli(str(acik_sayac) + ' açık port', R.GREEN + R.BOLD)}  /  "
          f"{renkli(str(toplam) + ' taranan', R.GRAY)}")
    print()

    # ─── HTML Rapor ───────────────────────────────────────────────────────────
    if args.rapor:
        meta = {
            "hedef":       args.hedef,
            "portlar":     portlar_str,
            "proto":       args.proto,
            "tarih":       datetime.now().strftime("%d.%m.%Y %H:%M"),
            "sure":        sure,
            "toplam_port": toplam,
            "ip_sayisi":   len(ipler),
        }
        html_rapor_olustur(args.rapor, meta)
        print(f"  {renkli('↳', R.CYAN)} HTML rapor kaydedildi: {renkli(args.rapor, R.WHITE + R.BOLD)}")
        print()

if __name__ == "__main__":
    main()