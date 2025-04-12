
# NetGuard – Network Scanner & Analyzer

[![MIT License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)  
[![Python Version](https://img.shields.io/badge/python-3.6%2B-blue.svg)](https://www.python.org/downloads/)  
[![OS Support](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)](#)  
[![Made with Python](https://img.shields.io/badge/made%20with-Python-3776AB.svg)](#)  
[![Contributions Welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg)](#)

---

**NetGuard** ist ein leistungsstarkes Netzwerk-Analysetool zur Überwachung, Analyse und Bewertung von Netzwerken. Es vereint eine Vielzahl an Funktionen zur Netzwerkerkennung, Sicherheit und Performance-Analyse – ideal für Systemadministratoren, IT-Enthusiasten und Sicherheitsexperten.

---

## 🚀 Features

- 🔍 **Netzwerkerkennung (Ping Sweep)** – Scannt dein lokales Netzwerk nach aktiven Geräten  
- 🔐 **Portscanner** – Erkennt offene Ports und identifiziert Dienste  
- ⚡ **Latenzmessung** – Misst Antwortzeiten und bewertet die Verbindungsqualität  
- 🛡️ **Sicherheitsanalyse** – Erkennt Schwachstellen und gibt Sicherheitsempfehlungen  
- 📊 **Bandbreitentest** – Misst die Downloadgeschwindigkeit über verschiedene Testquellen  
- 📡 **Netzwerküberwachung** – Echtzeit-Monitoring mit Ausfall- und Paketverlust-Erkennung  
- 💻 **Systeminformationen** – Zeigt nützliche Informationen über das eigene System  

---

## 📋 Systemanforderungen

- Python 3.6 oder höher  
- Betriebssystem: Windows, Linux oder macOS  
- Optional: `requests`-Modul für Bandbreitentests  

---

## 🛠️ Installation

### Abhängigkeiten installieren

Stelle sicher, dass du Python 3.6 oder höher installiert hast. Du kannst die erforderlichen Abhängigkeiten installieren, indem du folgendes ausführst:

```bash
pip install -r requirements.txt
```

Falls du die `requests`-Bibliothek für den Bandbreitentest benötigst:

```bash
pip install requests
```

### Repository klonen

```bash
git clone https://github.com/yourusername/netguard.git
cd netguard
```

---

## 💻 Verwendung

```bash
python netguard.py
```

### Hauptfunktionen im Menü

- Aktive Geräte im Netzwerk entdecken  
- Offene Ports auf einem Zielsystem scannen  
- Netzwerk-Latenz messen  
- Sicherheitsbewertung eines Computers durchführen  
- Bandbreitentest durchführen  
- Netzwerkverbindung überwachen  

---

## 🔒 Sicherheitshinweise

- Verwende das Tool **nur in Netzwerken**, für die du **ausdrücklich berechtigt** bist  
- Portscans können von Sicherheitssystemen als verdächtiges Verhalten erkannt werden  
- Einige Funktionen erfordern Administrator- oder Root-Rechte  

---

## 🤝 Contributing

Beiträge sind willkommen! Bitte lies vorher die [Contribution Guidelines](CONTRIBUTING.md).  

---

## 📝 Lizenz

Dieses Projekt steht unter der [MIT-Lizenz](LICENSE).

---

## ✨ Feature-Details

<details>
<summary><strong>Netzwerkerkennung</strong></summary>

- Erkennt aktive Geräte im lokalen IPv4-Netz  
- Multi-Threading für hohe Geschwindigkeit  

</details>

<details>
<summary><strong>Portscanner</strong></summary>

- Konfigurierbare Portbereiche  
- Erkennt gängige Dienste  

</details>

<details>
<summary><strong>Latenzmessung</strong></summary>

- Misst min./max./durchschn. Ping  
- Verbindungsqualität wird analysiert  

</details>

<details>
<summary><strong>Sicherheitsanalyse</strong></summary>

- Erkennt unsichere Dienste  
- Gibt Empfehlungen zur Absicherung  

</details>

<details>
<summary><strong>Bandbreitentest</strong></summary>

- Testet Downloadgeschwindigkeit mit verschiedenen Quellen  
- Durchschnittsbandbreite wird berechnet  

</details>

<details>
<summary><strong>Netzwerküberwachung</strong></summary>

- Echtzeitverbindungsüberwachung  
- Erkennung von Ausfällen und Paketverlusten  

</details>

---

## 🔧 Technische Details

- Geschrieben in Python 3  
- Verwendung von nativen Sockets  
- Plattformunabhängig (Windows, Linux, macOS)  
- Multi-Threading für bessere Performance  
- Fehlertolerante Ausführung  
- Farbige Konsolenausgabe  

---

## 📊 Performance

- Schnelle Netzwerkscans durch parallele Threads  
- Optimierte Portscans  
- Geringe CPU-Auslastung  

---

## 🎨 Benutzeroberfläche

- Farbige Ausgabe für bessere Lesbarkeit  
- Übersichtlich gestaltetes Hauptmenü  
- Fortschrittsanzeigen  
- Klare Benutzerführung  

---

## 📈 Zukunftspläne

- 🖥️ GUI-Version (grafische Oberfläche)  
- 🔍 Erweiterte Sicherheitsprüfungen  
- 📡 Netzwerkverkehrsanalyse  
- 📄 Automatische Berichte  
- 🔄 Kontinuierliches Monitoring  
- 🔌 API-Integration  

---

## 💡 Tipps für den Einsatz

- Regelmäßige Netzwerkscans durchführen  
- Sicherheitsergebnisse dokumentieren  
- Bandbreitentests zu verschiedenen Tageszeiten ausführen  
- Ergebnisse speichern und vergleichen
