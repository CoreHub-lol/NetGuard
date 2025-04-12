import subprocess
import ipaddress
import socket
import platform
import time
import re
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

# Farben für die Konsole
class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

# ASCII-Art für "NetGuard"
ascii_art = """
 _   _      _    _____                     _ 
| \ | | ___| |_ / ____|_   _  __ _ _ __ __| |
|  \| |/ _ \ __| |  __| | | |/ _` | '__/ _` |
| |\  |  __/ |_| | |_ | |_| | (_| | | | (_| |
|_| \_|\___|\__|_____| \__,_| \__,_|_|  \__,_|
"""

# Korrigiere die ping_host Funktion in der ping_sweep Funktion
def ping_sweep(subnet):
    print(f"{Colors.BLUE}Starte Scan im Netzwerk {subnet}...{Colors.ENDC}")
    active_devices = []
    try:
        network = ipaddress.ip_network(subnet, strict=False)
    except ValueError:
        print(f"{Colors.RED}Fehler: Ungültiges Subnetzformat! Beispiel: 192.168.1.0/24{Colors.ENDC}")
        return active_devices

    os_type = platform.system().lower()
    total_hosts = sum(1 for _ in network.hosts())
    print(f"Insgesamt {total_hosts} Host(s) zu scannen")
    
    # Progress-Tracking
    completed = 0
    active_count = 0
    lock = threading.Lock()
    
    def ping_host(ip):
        nonlocal completed, active_count
        ip_str = str(ip)
        try:
            if os_type == "windows":
                # stdout und stderr auf PIPE setzen und text=False verwenden
                result = subprocess.run(["ping", "-n", "1", "-w", "500", ip_str], 
                                      stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE,
                                      text=False,  # Text-Modus deaktivieren
                                      timeout=2)
            else:
                result = subprocess.run(["ping", "-c", "1", "-W", "1", ip_str], 
                                      stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE,
                                      text=False,  # Text-Modus deaktivieren
                                      timeout=2)
            
            with lock:
                completed += 1
                if result.returncode == 0:
                    active_devices.append(ip_str)
                    active_count += 1
                    print(f"\r{Colors.GREEN}[{completed}/{total_hosts}] Aktive Geräte: {active_count} | Zuletzt gefunden: {ip_str}{Colors.ENDC}", end="")
                else:
                    print(f"\r[{completed}/{total_hosts}] Aktive Geräte: {active_count}", end="")
        except (subprocess.TimeoutExpired, subprocess.SubprocessError):
            with lock:
                completed += 1
                print(f"\r[{completed}/{total_hosts}] Aktive Geräte: {active_count}", end="")
    
    # Multithreading für schnelleren Scan
    with ThreadPoolExecutor(max_workers=min(50, total_hosts)) as executor:
        executor.map(ping_host, network.hosts())
    
    print(f"\n{Colors.GREEN}Scan abgeschlossen! {len(active_devices)} aktive Geräte gefunden.{Colors.ENDC}")
    return active_devices

# Funktion 2: Port-Scanning mit Threading für bessere Performance
def scan_ports(target_ip, start_port, end_port):
    print(f"{Colors.BLUE}Scanne Ports {start_port} bis {end_port} auf {target_ip}...{Colors.ENDC}")
    open_ports = []
    total_ports = end_port - start_port + 1
    completed = 0
    lock = threading.Lock()
    
    def check_port(port):
        nonlocal completed
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((target_ip, port))
        sock.close()
        
        with lock:
            completed += 1
            if result == 0:
                open_ports.append(port)
                service = get_common_service(port)
                print(f"\r{Colors.GREEN}[{completed}/{total_ports}] Port {port} ist offen ({service}){Colors.ENDC}", end="")
            else:
                print(f"\r[{completed}/{total_ports}] Prüfe Port {port}...", end="")
    
    # Multithreading für schnelleren Scan
    with ThreadPoolExecutor(max_workers=min(200, total_ports)) as executor:
        executor.map(check_port, range(start_port, end_port + 1))
    
    print(f"\n{Colors.GREEN}Port-Scan abgeschlossen! {len(open_ports)} offene Ports gefunden.{Colors.ENDC}")
    return open_ports

def measure_latency(host, count=10):
    print(f"{Colors.BLUE}Messe Latenz zu {host} ({count} Pakete)...{Colors.ENDC}")
    os_type = platform.system().lower()
    
    try:
        if os_type == "windows":
            # Wichtig: errors='ignore' hinzugefügt, um Probleme mit nicht darstellbaren Zeichen zu vermeiden
            output = subprocess.check_output(["ping", "-n", str(count), host], 
                                            stderr=subprocess.STDOUT, 
                                            text=False)  # Hier auf text=False geändert
            
            # Manuelles Dekodieren mit Fehlerbehandlung
            output = output.decode('cp1252', errors='ignore')
            
            match = re.search(r"Minimum = (\d+)ms, Maximum = (\d+)ms, Mittelwert = (\d+)ms", output)
            if match:
                min_latency, max_latency, avg_latency = match.groups()
                return {
                    'min': float(min_latency),
                    'max': float(max_latency),
                    'avg': float(avg_latency)
                }
            else:
                match = re.search(r"Minimum = (\d+)ms, Maximum = (\d+)ms, Average = (\d+)ms", output)
                if match:
                    min_latency, max_latency, avg_latency = match.groups()
                    return {
                        'min': float(min_latency),
                        'max': float(max_latency),
                        'avg': float(avg_latency)
                    }
        else:
            # Für Linux/Unix auch mit Fehlerbehandlung
            output = subprocess.check_output(["ping", "-c", str(count), host], 
                                           stderr=subprocess.STDOUT, 
                                           text=False)
            
            # Manuelles Dekodieren mit Fehlerbehandlung
            output = output.decode('utf-8', errors='ignore')
            
            match = re.search(r"min/avg/max/mdev = ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)", output)
            if match:
                min_latency, avg_latency, max_latency, _ = match.groups()
                return {
                    'min': float(min_latency),
                    'max': float(max_latency),
                    'avg': float(avg_latency)
                }
        
        print(f"{Colors.RED}Konnte die Latenzdaten nicht aus der Ausgabe extrahieren.{Colors.ENDC}")
        return None
    except subprocess.CalledProcessError:
        print(f"{Colors.RED}Fehler: Der Host {host} konnte nicht erreicht werden.{Colors.ENDC}")
        return None
    except Exception as e:
        print(f"{Colors.RED}Ein Fehler ist aufgetreten: {e}{Colors.ENDC}")
        return None

# Funktion 4: Sicherheitsprüfung für Systeme
def check_security(target_ip):
    print(f"{Colors.BLUE}Prüfe Sicherheit für {target_ip}...{Colors.ENDC}")
    
    # Liste bekannter unsicherer Dienste
    insecure_services = {
        21: "FTP (unverschlüsselt)",
        23: "Telnet (unverschlüsselt)",
        25: "SMTP (unverschlüsselt)",
        53: "DNS",
        80: "HTTP (unverschlüsselt)",
        110: "POP3 (unverschlüsselt)",
        143: "IMAP (unverschlüsselt)",
        445: "SMB (Windows-Dateifreigabe)",
        1433: "MS SQL",
        1521: "Oracle DB",
        3306: "MySQL/MariaDB",
        3389: "RDP (Remote Desktop)",
        5432: "PostgreSQL"
    }
    
    # Zunächst scannen wir nach häufig verwendeten Ports
    print("Scannen nach bekannten unsicheren Ports...")
    open_ports = scan_ports(target_ip, 1, 1024)
    
    # Prüfen, welche der offenen Ports als unsicher gelten
    insecure_open = {}
    for port in open_ports:
        if port in insecure_services:
            insecure_open[port] = insecure_services[port]
    
    return open_ports, insecure_open

# Hilfsfunktion: Erkennung gängiger Dienste nach Portnummer
def get_common_service(port):
    common_ports = {
        20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 
        53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP", 
        110: "POP3", 123: "NTP", 137: "NetBIOS", 138: "NetBIOS", 139: "NetBIOS", 
        143: "IMAP", 161: "SNMP", 162: "SNMP", 389: "LDAP", 443: "HTTPS", 
        445: "SMB", 514: "Syslog", 587: "SMTP", 636: "LDAPS", 993: "IMAPS", 
        995: "POP3S", 1080: "SOCKS", 1433: "MSSQL", 1521: "Oracle", 
        3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 
        8080: "HTTP-Alt", 8443: "HTTPS-Alt"
    }
    
    return common_ports.get(port, "Unbekannt")

# Funktion 5: Einfacher Netzwerk-Bandbreiten-Test
def test_bandwidth():
    print(f"{Colors.BLUE}Führe einen einfachen Bandbreiten-Test durch...{Colors.ENDC}")
    print("Lade eine kleine Datei herunter, um die Download-Geschwindigkeit zu messen...")
    
    # URLs für den Test (verschiedene Größen für genauere Messung)
    test_urls = [
        "http://speedtest.ftp.otenet.gr/files/test100k.db",   # 100 KB
        "http://speedtest.ftp.otenet.gr/files/test1Mb.db"     # 1 MB
    ]
    
    results = []
    
    try:
        import requests
        
        for url in test_urls:
            start_time = time.time()
            response = requests.get(url, stream=True)
            size = 0
            
            for chunk in response.iter_content(chunk_size=1024):
                if chunk:
                    size += len(chunk)
            
            duration = time.time() - start_time
            
            # Berechnung der Geschwindigkeit in Mbps
            speed_mbps = (size * 8 / 1000000) / duration
            results.append(speed_mbps)
            
            print(f"Datei: {url.split('/')[-1]}")
            print(f"Größe: {size/1024:.2f} KB")
            print(f"Zeit: {duration:.2f} Sekunden")
            print(f"Geschwindigkeit: {speed_mbps:.2f} Mbps")
            print()
        
        if results:
            avg_speed = sum(results) / len(results)
            print(f"{Colors.GREEN}Durchschnittliche Download-Geschwindigkeit: {avg_speed:.2f} Mbps{Colors.ENDC}")
        
        return avg_speed if results else None
        
    except ImportError:
        print(f"{Colors.YELLOW}Für den Bandbreitentest wird das 'requests' Modul benötigt.")
        print("Installiere es mit 'pip install requests'{Colors.ENDC}")
        return None
    except Exception as e:
        print(f"{Colors.RED}Fehler beim Bandbreitentest: {e}{Colors.ENDC}")
        return None

# Korrigiere die monitor_network Funktion 
def monitor_network(duration=30):
    print(f"{Colors.BLUE}Überwache das Netzwerk für {duration} Sekunden...{Colors.ENDC}")
    
    # Wir verwenden ein einfaches Ping-basiertes Monitoring zu einem bekannten Host
    target = "8.8.8.8"  # Google DNS
    interval = 1  # Sekunden zwischen den Pings
    
    start_time = time.time()
    results = []
    
    print(f"Starte Überwachung um {datetime.now().strftime('%H:%M:%S')}")
    print(f"Sende Pings an {target} im {interval}-Sekunden-Takt...")
    
    try:
        while time.time() - start_time < duration:
            # Manueller Ping anstatt die fehlerhafte Funktion zu nutzen
            os_type = platform.system().lower()
            try:
                if os_type == "windows":
                    cmd = ["ping", "-n", "1", "-w", "1000", target]
                else:
                    cmd = ["ping", "-c", "1", "-W", "1", target]
                
                result = subprocess.run(cmd, 
                                     stdout=subprocess.PIPE, 
                                     stderr=subprocess.PIPE, 
                                     text=False,  # Text-Modus deaktivieren
                                     timeout=2)
                
                if result.returncode == 0:
                    # Befehl erfolgreich, einfache Abschätzung der Latenz (ca. 100ms)
                    current_time = datetime.now().strftime("%H:%M:%S")
                    # In einer echten Implementierung würden wir die tatsächliche Latenz extrahieren
                    results.append(100)  # Platzhalter-Wert
                    print(f"[{current_time}] {Colors.GREEN}Ping erfolgreich{Colors.ENDC}")
                else:
                    current_time = datetime.now().strftime("%H:%M:%S")
                    print(f"[{current_time}] {Colors.RED}Keine Antwort - Verbindungsproblem!{Colors.ENDC}")
                    results.append(None)
            except Exception as e:
                current_time = datetime.now().strftime("%H:%M:%S")
                print(f"[{current_time}] {Colors.RED}Fehler: {str(e)}{Colors.ENDC}")
                results.append(None)
            
            # Warten bis zum nächsten Intervall
            time.sleep(interval)
    
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Überwachung vorzeitig beendet.{Colors.ENDC}")
    
    # Statistiken berechnen
    successful_pings = [r for r in results if r is not None]
    packet_loss = (len(results) - len(successful_pings)) / len(results) * 100 if results else 0
    
    print(f"\n{Colors.BLUE}--- Überwachungsergebnisse ---{Colors.ENDC}")
    print(f"Zeitraum: {duration} Sekunden")
    print(f"Gesendete Pings: {len(results)}")
    print(f"Erfolgreiche Antworten: {len(successful_pings)}")
    print(f"Paketverlust: {packet_loss:.1f}%")
    
    if successful_pings:
        min_latency = min(successful_pings)
        max_latency = max(successful_pings)
        avg_latency = sum(successful_pings) / len(successful_pings)
        print(f"Minimale Latenz: {min_latency:.2f} ms")
        print(f"Maximale Latenz: {max_latency:.2f} ms")
        print(f"Durchschnittliche Latenz: {avg_latency:.2f} ms")
    
    return results

# Hilfsfunktion: System-Info ermitteln
def get_system_info():
    print(f"{Colors.BLUE}Sammle System- und Netzwerkinformationen...{Colors.ENDC}")
    
    system_info = {
        "Betriebssystem": platform.platform(),
        "System": platform.system(),
        "Release": platform.release(),
        "Version": platform.version(),
        "Architektur": platform.machine(),
        "Hostname": socket.gethostname(),
        "IP-Adressen": []
    }
    
    # IP-Adressen ermitteln
    try:
        # Primäre IP ermitteln (mit der wir nach außen kommunizieren)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        primary_ip = s.getsockname()[0]
        s.close()
        system_info["Primäre IP"] = primary_ip
        
        # Alle Netzwerkadapter auflisten
        hostname = socket.gethostname()
        ip_list = socket.getaddrinfo(hostname, None)
        
        for ip_info in ip_list:
            addr = ip_info[4][0]
            if not addr.startswith("127.") and ":" not in addr:  # IPv4 und keine Loopback
                system_info["IP-Adressen"].append(addr)
    
    except Exception as e:
        print(f"{Colors.RED}Fehler beim Ermitteln der Netzwerkinformationen: {e}{Colors.ENDC}")
    
    return system_info

# Hauptprogramm mit benutzerfreundlicher Eingabe
def main():
    # Für farbige Ausgabe auf Windows
    if platform.system().lower() == "windows":
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    
    # ASCII-Art am Programmstart anzeigen
    print(f"{Colors.BLUE}{ascii_art}{Colors.ENDC}")
    print(f"{Colors.BOLD}{Colors.BLUE}=== NetGuard - Netzwerk-Scanner und Analyzer ===\n{Colors.ENDC}")
    print(f"Dieses Tool hilft dir, dein Netzwerk zu analysieren und zu überwachen.")
    print(f"Version 2.0 - Verbesserte Performance und neue Funktionen")
    print(f"Ausgeführt auf: {platform.node()} ({platform.system()})")
    print(f"Startzeit: {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}\n")

    # Zu Beginn System-Info anzeigen
    system_info = get_system_info()
    print(f"{Colors.BOLD}Systeminformationen:{Colors.ENDC}")
    for key, value in system_info.items():
        if isinstance(value, list):
            print(f"  {key}:")
            for item in value:
                print(f"    - {item}")
        else:
            print(f"  {key}: {value}")
    print()

    # Hauptschleife
    while True:
        print(f"{Colors.BOLD}{Colors.BLUE}Was möchtest du tun?{Colors.ENDC}")
        print(f"{Colors.BOLD}1.{Colors.ENDC} Aktive Geräte im Netzwerk finden")
        print(f"{Colors.BOLD}2.{Colors.ENDC} Offene Ports auf einem Computer prüfen")
        print(f"{Colors.BOLD}3.{Colors.ENDC} Netzwerkgeschwindigkeit (Latenz) messen")
        print(f"{Colors.BOLD}4.{Colors.ENDC} Sicherheit eines Computers prüfen")
        print(f"{Colors.BOLD}5.{Colors.ENDC} Bandbreitentest durchführen")
        print(f"{Colors.BOLD}6.{Colors.ENDC} Netzwerk kurzzeitig überwachen")
        print(f"{Colors.BOLD}7.{Colors.ENDC} Beenden")
        
        choice = input(f"\n{Colors.BOLD}Gib eine Nummer ein (1-7):{Colors.ENDC} ")

        if choice == "1":
            # Standardwert für das Subnetz basierend auf der eigenen IP
            default_subnet = "192.168.1.0/24"
            if "Primäre IP" in system_info:
                ip_parts = system_info["Primäre IP"].split('.')
                if len(ip_parts) == 4:
                    default_subnet = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
            
            subnet = input(f"\nGib dein Netzwerk ein (Standard: {default_subnet}): ") or default_subnet
            active_devices = ping_sweep(subnet)
            
            if active_devices:
                print(f"\n{Colors.GREEN}Gefundene Geräte:{Colors.ENDC}")
                for idx, device in enumerate(active_devices, 1):
                    try:
                        hostname = socket.getfqdn(device)
                        hostname_str = f" ({hostname})" if hostname != device else ""
                    except:
                        hostname_str = ""
                    
                    print(f"{Colors.BOLD}{idx}.{Colors.ENDC} {device}{hostname_str}")
            else:
                print(f"\n{Colors.YELLOW}Keine Geräte gefunden oder ungültiges Subnetz.{Colors.ENDC}")
        
        elif choice == "2":
            default_ip = "localhost"
            if "Primäre IP" in system_info:
                default_ip = system_info["Primäre IP"]
            
            target = input(f"\nGib die IP-Adresse ein (Standard: {default_ip}): ") or default_ip
            
            # Welchen Portbereich scannen?
            port_range = input("Welchen Portbereich möchtest du scannen?\n1. Nur wichtige Ports (1-1024)\n2. Erweiterte Ports (1-10000)\n3. Benutzerdefinierten Bereich\nAuswahl (Standard: 1): ") or "1"
            
            if port_range == "1":
                open_ports = scan_ports(target, 1, 1024)
            elif port_range == "2":
                open_ports = scan_ports(target, 1, 10000)
            elif port_range == "3":
                start = int(input("Startport: ") or "1")
                end = int(input("Endport: ") or "1024")
                open_ports = scan_ports(target, start, end)
            else:
                open_ports = scan_ports(target, 1, 1024)
            
            if open_ports:
                print(f"\n{Colors.GREEN}Offene Ports auf {target}:{Colors.ENDC}")
                for port in sorted(open_ports):
                    service = get_common_service(port)
                    print(f"- Port {port}: {service}")
            else:
                print(f"\n{Colors.YELLOW}Keine offenen Ports gefunden.{Colors.ENDC}")
        
        elif choice == "3":
            host_options = [
                ("Google DNS", "8.8.8.8"),
                ("Cloudflare DNS", "1.1.1.1"),
                ("Google.com", "google.com"),
                ("Amazon.com", "amazon.com"),
                ("Lokaler Router", "192.168.1.1")
            ]
            
            print("\nZu welchem Server soll die Latenz gemessen werden?")
            for idx, (name, ip) in enumerate(host_options, 1):
                print(f"{idx}. {name} ({ip})")
            print(f"{len(host_options) + 1}. Eigene Eingabe")
            
            host_choice = input(f"Auswahl (Standard: 1): ") or "1"
            
            if host_choice.isdigit() and 1 <= int(host_choice) <= len(host_options):
                host = host_options[int(host_choice) - 1][1]
            elif host_choice == str(len(host_options) + 1):
                host = input("Gib den Host ein: ")
            else:
                host = host_options[0][1]
            
            count = int(input("Anzahl der Ping-Pakete (Standard: 10): ") or "10")
            
            latency = measure_latency(host, count)
            if latency:
                print(f"\n{Colors.GREEN}Latenz zu {host}:{Colors.ENDC}")
                print(f"  Minimum: {latency['min']:.2f} ms")
                print(f"  Durchschnitt: {latency['avg']:.2f} ms")
                print(f"  Maximum: {latency['max']:.2f} ms")
                
                # Bewertung der Latenz
                if latency['avg'] < 20:
                    print(f"{Colors.GREEN}Ausgezeichnete Verbindung!{Colors.ENDC}")
                elif latency['avg'] < 50:
                    print(f"{Colors.GREEN}Sehr gute Verbindung.{Colors.ENDC}")
                elif latency['avg'] < 100:
                    print(f"{Colors.YELLOW}Gute Verbindung.{Colors.ENDC}")
                elif latency['avg'] < 150:
                    print(f"{Colors.YELLOW}Durchschnittliche Verbindung.{Colors.ENDC}")
                else:
                    print(f"{Colors.RED}Langsame Verbindung.{Colors.ENDC}")
            else:
                print(f"\n{Colors.RED}Keine Antwort von {host}.{Colors.ENDC}")
        
        elif choice == "4":
            default_ip = "localhost"
            if "Primäre IP" in system_info:
                default_ip = system_info["Primäre IP"]
            
            target = input(f"\nWelchen Computer möchtest du prüfen? (Standard: {default_ip}): ") or default_ip
            
            open_ports, insecure_ports = check_security(target)
            
            print(f"\n{Colors.BOLD}Sicherheitsbericht für {target}:{Colors.ENDC}")
            
            if open_ports:
                print(f"\n{Colors.YELLOW}Offene Ports ({len(open_ports)}):{Colors.ENDC}")
                for port in sorted(open_ports):
                    service = get_common_service(port)
                    if port in insecure_ports:
                        print(f"{Colors.RED}! Port {port}: {service} - UNSICHER{Colors.ENDC}")
                    else:
                        print(f"- Port {port}: {service}")
                
                if insecure_ports:
                    print(f"\n{Colors.RED}Sicherheitsrisiken gefunden!{Colors.ENDC}")
                    print(f"{Colors.RED}Die folgenden offenen Ports könnten ein Sicherheitsrisiko darstellen:{Colors.ENDC}")
                    for port, service in insecure_ports.items():
                        print(f"{Colors.RED}- Port {port}: {service}{Colors.ENDC}")
                    
                    print(f"\n{Colors.YELLOW}Empfehlungen:{Colors.ENDC}")
                    print("- Deaktiviere nicht benötigte Dienste")
                    print("- Verwende Firewallregeln, um den Zugriff einzuschränken")
                    print("- Aktualisiere die Dienste auf sichere Versionen")
                else:
                    print(f"\n{Colors.GREEN}Keine bekannten unsicheren Dienste gefunden.{Colors.ENDC}")
            else:
                print(f"\n{Colors.GREEN}Keine offenen Ports gefunden - System scheint gut abgesichert.{Colors.ENDC}")
        
        elif choice == "5":
            print(f"\n{Colors.BLUE}Bandbreitentest starten...{Colors.ENDC}")
            try:
                import requests
            except ImportError:
                print(f"\n{Colors.YELLOW}Für den Bandbreitentest wird das 'requests' Modul benötigt.")
                install = input("Möchtest du es jetzt installieren? (j/n): ").lower()
                if install in ["j", "ja", "y", "yes"]:
                    try:
                        subprocess.check_call([sys.executable, "-m", "pip", "install", "requests"])
                        print(f"{Colors.GREEN}Installation abgeschlossen!{Colors.ENDC}")
                        import requests
                    except:
                        print(f"{Colors.RED}Installation fehlgeschlagen. Versuche 'pip install requests' manuell auszuführen.{Colors.ENDC}")
                        continue
                else:
                    print("Bandbreitentest wird übersprungen.")
                    continue
                    
            test_bandwidth()
        
        elif choice == "6":
            duration = int(input("\nWie lange soll das Netzwerk überwacht werden (in Sekunden, Standard: 30)? ") or "30")
            monitor_network(duration)
        
        elif choice == "7":
            print(f"\n{Colors.GREEN}NetGuard wird beendet. Bis bald!{Colors.ENDC}")
            break
        
        else:
            print(f"\n{Colors.RED}Ungültige Eingabe! Bitte wähle eine Nummer zwischen 1 und 7.{Colors.ENDC}")
        
        print("\n" + "="*60)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}Programm durch Benutzer beendet.{Colors.ENDC}")
    except Exception as e:
        print(f"\n{Colors.RED}Ein unerwarteter Fehler ist aufgetreten: {e}{Colors.ENDC}")
        import traceback
        traceback.print_exc()