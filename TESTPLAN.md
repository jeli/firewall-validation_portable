# Testplan mit realen Konfigurationen (Katalog 1.2.0)

Dieser Plan prüft die umgebaute Fassung (Anzeige `index.html`, Logik `engine.js`, Datenmodell `rules.js` mit Prüfdefinitionen) mit echten Exporten deiner Firewalls.

## Worum es geht – und worum nicht

Die Umbau-Sicherheit ist bereits automatisch belegt: `tests/selbsttest.html` vergleicht 340 Einzelergebnisse aus zehn synthetischen Configs mit einer Referenz. Diese synthetischen Configs beruhen aber auf **Annahmen**, wie OPNsense und pfSense ihre Einstellungen in der `config.xml` ablegen. Ob diese Annahmen für **deine Versionen** stimmen, kann nur ein Export zeigen, den die Firewall selbst geschrieben hat. Genau das prüft dieser Plan.

Konkret beantwortet er drei Fragen:

1. **Regression:** Bewertet die neue Fassung deine bisherigen Exporte genauso wie die alte? (Phase 1)
2. **Erkennung:** Erkennt jede Regel die Einstellung, für die sie gedacht ist, wenn du sie auf der Firewall tatsächlich setzt? (Phase 2)
3. **Konfigurierbarkeit:** Wirken Änderungen aus dem Regel-Editor wie beschrieben, und lassen sich eigene Prüfungen schreiben? (Phase 3)

## Kennzeichnung in diesem Plan

Die Spalte **Wo** nennt das System, auf dem ein Schritt ausgeführt wird:

- **OPN-GUI** – Weboberfläche der OPNsense
- **PF-GUI** – Weboberfläche der pfSense
- **PC** – dein Arbeitsrechner mit Browser und dem Tool-Ordner

Die Spalte **Methode** sagt, wie sicher sich der Test auf einer produktiven Firewall durchführen lässt (siehe nächster Abschnitt).

---

## Vorbereitung

### Zwei Test-Methoden

**Methode S – Speichern ohne Anwenden.** Nur für Firewall-Regeln, NAT, Aliase und Interface-Einstellungen. Diese Seiten schreiben eine Änderung beim Klick auf „Speichern“ bereits in die `config.xml`, aktiv wird sie aber erst mit „Änderungen anwenden“. Du kannst also speichern, exportieren und die Änderung wieder entfernen, ohne dass sie je gewirkt hat.

- Nie auf „Anwenden“ klicken, solange die Teständerung besteht.
- Die Teständerung direkt nach dem Export wieder löschen bzw. zurücksetzen.
- Arbeitet eine zweite Person an derselben Firewall, vorher absprechen: Ihr „Anwenden“ würde deine Testregel aktivieren.

**Methode L – Labor.** Für alles, was beim Speichern sofort wirkt: SSH, WebGUI, Benutzer, Dienste (SNMP, UPnP, IDS, Unbound, Syslog) und VPN. Diese Tests gehören auf eine Test-Instanz, zum Beispiel eine OPNsense- und eine pfSense-VM in einem isolierten Netz. Eine Kopie deiner Produktiv-Config in die VM einzuspielen ist möglich, dann aber nur ohne Anschluss an das echte Netz, weil sonst IP-Adressen doppelt vorkommen.

> Nicht empfohlen: die exportierte `config.xml` von Hand im Texteditor verändern. Das prüft wieder nur meine Annahmen über die XML-Struktur, nicht das, was die Firewall wirklich schreibt – und genau darum geht es hier.

### Einen Export erstellen

| Wo | Schritt | Erklärung |
|---|---|---|
| OPN-GUI | *System → Konfiguration → Sicherungen* (engl. *System → Configuration → Backups*), Bereich „Download“, Häkchen bei „Verschlüsseln“ **nicht** setzen, „Konfiguration herunterladen“ | Erzeugt die `config.xml`. Eine verschlüsselte Datei kann das Tool nicht lesen. |
| PF-GUI | *Diagnostics → Backup & Restore*, „Backup area: All“, „Skip RRD data“ **ankreuzen**, „Download configuration as XML“ | Ohne RRD-Daten ist die Datei deutlich kleiner (bei deinem Export sonst rund 1,2 MB), der Inhalt für das Audit ist derselbe. |
| PC | Datei eindeutig benennen, z. B. `T2-07_opn_ntp-wan.xml` | Test-ID im Namen, damit Export und Protokollzeile zusammenpassen. |

### Werkzeug bereitstellen

| Wo | Schritt | Erklärung |
|---|---|---|
| PC | Den **alten** Tool-Ordner (Stand vor dem Umbau: `index.html` + `rules.js` 1.0.0) als `fvp-alt` aufbewahren | Wird in Phase 1 als Vergleich gebraucht. |
| PC | Den **neuen** Ordner als `fvp-neu` entpacken | Enthält `index.html`, `engine.js`, `rules.js` 1.2.0, `rules-editor.html`, `tests/`. |
| PC | `fvp-neu/tests/selbsttest.html` im Browser öffnen | Erwartet: „Alle 340 Ergebnisse stimmen mit der Referenz überein“. Erst dann weitermachen – sonst ist die Engine-Datei beschädigt oder unvollständig. |

### Protokoll

Für jeden Testfall eine Zeile:

| Test-ID | Plattform/Version | Erwartet | Tatsächlich | OK? | Bemerkung |
|---|---|---|---|---|---|
| T2-07 | OPNsense 25.x | SVC-NTP-OPEN = WARN | | | |

Die Firmware-Version gehört mit ins Protokoll, weil sich Ablageorte zwischen Versionen ändern können.

### So liest du das Ergebnis ab

Im Einzelbericht (`index.html`) den Filter **„Alle“** wählen. Jede Regel steht dort mit Status (FAIL / WARN / OK / N/A / MANUELL / FEHLER) und ihren Befunden. Für jeden Testfall zählt der Status der genannten Regel und, wo angegeben, der Befundtext.

**Wie du eine Abweichung einordnest:**

- Status **FEHLER**: Die Prüfung ist abgestürzt. Immer ein Programmfehler – Befundtext notieren.
- Status **N/A**, obwohl die Einstellung gesetzt ist: Die Engine findet die Einstellung nicht an der Stelle, an der sie sucht. Meist ein anderer Ablageort in deiner Version. Diesen Export aufheben (nach Bereinigung, siehe unten) – er ist die Grundlage für die Korrektur.
- **Anderer Status** als erwartet (z. B. OK statt FAIL): Die Einstellung wird gefunden, aber anders bewertet als gedacht. Befundtext und Einstellung notieren.

> Exporte mit Abweichungen vor dem Weitergeben mit `sanitize-opnsense.sed` bereinigen (Passwörter, Schlüssel, Zertifikate werden durch `REDACTED` ersetzt; das Ergebnis des Audits ändert sich dadurch nicht).

---

## Phase 1 – Regression mit unveränderten Exporten

Ziel: Die neue Fassung bewertet deine realen Configs genau wie die alte. Keine Änderung an der Firewall nötig.

| ID | Wo | Schritt | Erwartet |
|---|---|---|---|
| T1-01 | OPN-GUI, PF-GUI | Von jeder Firewall einen aktuellen Export ziehen | – |
| T1-02 | PC | Jeden Export einzeln in `fvp-alt/index.html` laden, Score, Note und die Zähler (FAIL, WARN, OK, Manuell, N/A, Fehler) notieren | – |
| T1-03 | PC | Denselben Export in `fvp-neu/index.html` laden, dieselben Werte notieren | Score und Note identisch |
| T1-04 | PC | In beiden Tabs Filter „Alle“ wählen und die Status aller 32 Regeln vergleichen | Identisch – mit **einer** erlaubten Ausnahme, siehe unten |
| T1-05 | PC | Alle Exporte gleichzeitig in beide Fassungen laden (Fleet-Dashboard) | Ø-Score, Median und Notenverteilung identisch |

**Erlaubte Abweichungen** – alles andere ist ein Fehler im Umbau:

1. **WireGuard:** Die alte Fassung zeigte bei konfiguriertem WireGuard für `VPN-WG-PRESENT` den Status **FEHLER** (Programmfehler), die neue **WARN** mit „WireGuard konfiguriert (Tunnels: n, Peers: m)“. Bei deiner OPNsense-Test-Config erwartet: Tunnels 1, Peers 3.
2. **Zwei zusätzliche Regeln:** `FW-SHADOWED-BLOCK` und `FW-SHADOWED-PASS` gibt es nur in der neuen Fassung. Ihre Befunde prüft Phase 2.7.
3. **Score:** Durch die zwei zusätzlichen Regeln verschiebt sich der Score leicht, und zwar auch nach oben, weil sie die maximal mögliche Strafpunktzahl mit erhöhen. Bei deinen Test-Configs: OPNsense 32,5 → 33,9, pfSense 83,3 → 83,6. Zum Vergleich der übrigen 32 Regeln zählen nur deren Status und Befunde.
4. **pfSense DNS-Resolver:** Stehen unter „Network Interfaces“ mindestens drei Interfaces einschließlich WAN (z. B. `lan,opt2,wan`), meldet `SVC-DNS-OPENRESOLVER` jetzt korrekt WARN statt OK.

---

## Phase 2 – Erkennung einzelner Einstellungen

Grundablauf je Testfall:

1. **Ausgangslage** – Status der Regel im aktuellen Export notieren (Phase 1 liefert ihn bereits).
2. **Ändern** – Einstellung laut Tabelle setzen (Wo / Methode beachten).
3. **Exportieren** – wie oben beschrieben, Datei nach Test-ID benennen.
4. **Prüfen** – Export in `fvp-neu/index.html` laden, Status mit „Erwartet“ vergleichen, protokollieren.
5. **Zurücksetzen** – Änderung rückgängig machen (bei Methode S ohne „Anwenden“).

Für viele Regeln gibt es zwei Testfälle: einmal „auslösen“ (Befund erwartet), einmal „beheben“ (OK erwartet). Beides zu prüfen zeigt, dass die Regel nicht einfach immer dasselbe meldet.

Die Menüpfade gelten für aktuelle Versionen (OPNsense 24.x/25.x, pfSense CE 2.7). Weichen sie bei dir ab, bitte im Protokoll vermerken.

### 2.1 Management-Ebene

| ID | Plattform | Wo | Methode | Einstellung | Erwartet |
|---|---|---|---|---|---|
| T2-01 | OPN | OPN-GUI | L | *System → Settings → Administration*, Web GUI: „Listen Interfaces“ = **All** (leer) | `MGMT-WEBGUI-WAN` = FAIL, Befund „WebGUI an KEIN Interface gebunden“ |
| T2-02 | OPN | OPN-GUI | L | „Listen Interfaces“ = nur **LAN**, keine WAN-Regel auf den GUI-Port | `MGMT-WEBGUI-WAN` = OK |
| T2-03 | beide | OPN-GUI / PF-GUI | S | *Firewall → Rules → WAN*: Pass, TCP, Ziel **This Firewall** bzw. **WAN address**, Port = GUI-Port (443 oder dein eigener) | `MGMT-WEBGUI-WAN` = FAIL, Befund „WAN-Regel #n erlaubt GUI-Port …“ |
| T2-04 | beide | OPN-GUI / PF-GUI | L | Web GUI Protokoll auf **HTTP** stellen (OPN: *System → Settings → Administration*; PF: *System → Advanced → Admin Access*) | `MGMT-WEBGUI-HTTP` = FAIL |
| T2-05 | beide | OPN-GUI / PF-GUI | L | SSH aktivieren, OPN zusätzlich „Listen Interfaces“ = All | `MGMT-SSH-WAN` = FAIL (OPN: „SSH an KEIN Interface gebunden“) |
| T2-06 | beide | OPN-GUI / PF-GUI | S | WAN-Regel Pass TCP Ziel This Firewall Port **22** (oder dein SSH-Port) | `MGMT-SSH-WAN` = FAIL mit Regelnummer |
| T2-07 | beide | OPN-GUI / PF-GUI | L | SSH **deaktivieren** | `MGMT-SSH-WAN`, `MGMT-SSH-ROOT`, `MGMT-SSH-PWAUTH` = N/A |
| T2-08 | OPN | OPN-GUI | L | *Administration → Secure Shell*: „Permit root user login“ an | `MGMT-SSH-ROOT` = FAIL; aus → OK |
| T2-09 | PF | PF-GUI | – | (kein Schalter vorhanden) | `MGMT-SSH-ROOT` = N/A „pfSense ohne permitRootLogin-Schalter“ |
| T2-10 | OPN | OPN-GUI | L | „Permit password login“ an | `MGMT-SSH-PWAUTH` = FAIL; aus → OK |
| T2-11 | PF | PF-GUI | L | *System → Advanced → Admin Access*, „SSHd Key Only“ = **Password or Public Key** | `MGMT-SSH-PWAUTH` = WARN; „Public Key Only“ → OK |
| T2-12 | OPN | OPN-GUI | L | *System → Access → Users*: Admin-Konto (Gruppe „admins“) **ohne** OTP-Seed | `MGMT-MFA` = FAIL, Befund nennt das Konto. Hinweis: auch ein aktives `root` zählt als Admin |
| T2-13 | OPN | OPN-GUI | L | Allen aktiven Admin-Konten einen OTP-Seed geben (bzw. `root` deaktivieren) | `MGMT-MFA` = OK |
| T2-14 | PF | PF-GUI | – | – | `MGMT-MFA` = N/A „pfSense CE ohne native GUI-MFA“ |
| T2-15 | beide | OPN-GUI / PF-GUI | L | `root` (pfSense: `admin`) aktiv lassen | `MGMT-ROOT-ACCOUNT` = WARN |
| T2-16 | beide | OPN-GUI / PF-GUI | L | Benanntes Admin-Konto anlegen, `root`/`admin` deaktivieren (**vorher** Login mit dem neuen Konto testen!) | `MGMT-ROOT-ACCOUNT` = OK |
| T2-17 | beide | OPN-GUI / PF-GUI | L | Konsolenmenü-Passwortschutz aus (OPN: *Administration → Console*; PF: *System → Advanced → Admin Access → Console Options*) | `MGMT-CONSOLE` = WARN; an → OK |

### 2.2 Firewall-Regeln

| ID | Plattform | Wo | Methode | Einstellung | Erwartet |
|---|---|---|---|---|---|
| T2-18 | beide | OPN-GUI / PF-GUI | S | *Firewall → Rules → LAN*: Pass, Protokoll **any**, Quelle **any**, Ziel **any** | `FW-ANY-ANY` = WARN (Schweregrad mittel), Befund mit `[lan]` |
| T2-19 | beide | OPN-GUI / PF-GUI | S | Dieselbe Regel auf **WAN** (niemals anwenden!) | `FW-ANY-ANY` = FAIL, Schweregrad **hoch**; zusätzlich `FW-WAN-EXPOSURE` = FAIL |
| T2-20 | beide | OPN-GUI / PF-GUI | S | WAN-Regel Pass TCP, Quelle eine einzelne IP, Ziel ein LAN-Host Port 443 | `FW-WAN-EXPOSURE` = FAIL, Befund nennt Quelle und Ziel |
| T2-21 | beide | OPN-GUI / PF-GUI | S | *Interfaces → WAN*: „Block private networks“ aus | `FW-BLOCKPRIV` = FAIL „fehlt auf: wan“; an → OK |
| T2-22 | beide | OPN-GUI / PF-GUI | S | „Block bogon networks“ aus | `FW-BLOCKBOGON` = FAIL; an → OK |
| T2-23 | beide | OPN-GUI / PF-GUI | S | LAN-Regel mit Quelle „Single host or Network“ **192.168.1.38/24** (Host-IP mit Netzmaske) | `FW-HOST-CIDR` = FAIL, Befund nennt `192.168.1.38/24` |
| T2-24 | beide | OPN-GUI / PF-GUI | S | Host-Alias mit Eintrag **192.168.1.38/24** anlegen (*Firewall → Aliases*) | `FW-HOST-CIDR` = FAIL, Befund „Alias '…'“ |
| T2-25 | beide | OPN-GUI / PF-GUI | S | Eine beliebige Regel **deaktivieren** | `FW-DISABLED-RULES` = WARN |
| T2-26 | beide | OPN-GUI / PF-GUI | S | Block-Regel **ohne** „Log packets“ anlegen | `FW-BLOCK-NOLOG` = WARN; alle Block-Regeln mit Logging → OK |
| T2-27 | OPN | OPN-GUI | S | **Wichtiger Prüfpunkt:** Regel über *Firewall → Automation → Filter* anlegen (neue Regelverwaltung), z. B. WAN any-any | Erwartet laut Katalog: `FW-ANY-ANY` = FAIL. **Vermutlich** zeigt das Tool keinen Befund, weil die Engine nur die klassischen Regeln unter *Firewall → Rules* liest. Ergebnis unbedingt protokollieren |

### 2.3 NAT / Port-Forwarding

| ID | Plattform | Wo | Methode | Einstellung | Erwartet |
|---|---|---|---|---|---|
| T2-28 | beide | OPN-GUI / PF-GUI | S | *Firewall → NAT → Port Forward*: WAN, Quelle **any**, Zielport **3389**, Ziel ein LAN-Host | `NAT-MGMT-EXPOSED` = FAIL, Schweregrad **kritisch**; `NAT-WAN-ANY-SRC` = WARN |
| T2-29 | beide | OPN-GUI / PF-GUI | S | Wie T2-28, aber Quelle eine einzelne IP | `NAT-MGMT-EXPOSED` = FAIL, Schweregrad **hoch**; `NAT-WAN-ANY-SRC` = OK |
| T2-30 | beide | OPN-GUI / PF-GUI | S | Port-Alias `Mgmt` mit `22 3389` anlegen, Port-Forward mit Zielport `Mgmt` | `NAT-MGMT-EXPOSED` = FAIL, Befund nennt Ports 22 und 3389 (Alias-Auflösung) |
| T2-31 | beide | OPN-GUI / PF-GUI | S | Port-Forward auf Port **443** (nicht sensibel), Quelle any | `NAT-MGMT-EXPOSED` = OK; `NAT-WAN-ANY-SRC` = WARN |
| T2-32 | OPN | OPN-GUI | S | **Prüfpunkt:** Falls deine Version Port-Forwards unter einem neuen Menüpunkt (z. B. „Destination NAT“) verwaltet, dort einen Forward auf 3389 anlegen | Erwartet wie T2-28. Zeigt das Tool OK, liegen die Forwards an einem Ort, den die Engine nicht liest – protokollieren |
| T2-33 | PF | PF-GUI | S | *Firewall → NAT → 1:1*: Eintrag anlegen | `NAT-1TO1` = WARN, Befund „extern <-> intern“; keiner → OK |
| T2-33a | OPN | OPN-GUI | S | **Prüfpunkt:** *Firewall → NAT → One-to-One*: Eintrag anlegen | Erwartet: WARN. **Sehr wahrscheinlich** OK, weil deine OPNsense-Version 1:1-NAT unter `OPNsense/Firewall/Filter/onetoone` ablegt, die Engine aber nur `<nat><onetoone>` liest. Protokollieren |
| T2-34 | beide | OPN-GUI / PF-GUI | L | UPnP aktivieren (OPN: Plugin `os-upnp`, *Services → Universal Plug and Play*; PF: *Services → UPnP & NAT-PMP*) | `NAT-UPNP` = FAIL; deaktiviert → OK „vorhanden, deaktiviert“ |

### 2.4 Dienst-Exposition

| ID | Plattform | Wo | Methode | Einstellung | Erwartet |
|---|---|---|---|---|---|
| T2-35 | PF | PF-GUI | L | *Services → SNMP*: aktivieren, Read Community **public** | `SVC-SNMP-PUBLIC` = FAIL, Schweregrad hoch |
| T2-36 | PF | PF-GUI | L | Aktiviert, eigene Community | `SVC-SNMP-PUBLIC` = WARN „SNMP aktiv. SNMPv3 prüfen.“ |
| T2-37 | PF | PF-GUI | L | Deaktiviert, Community weiterhin `public` | `SVC-SNMP-PUBLIC` = WARN |
| T2-38 | OPN | OPN-GUI | L | **Prüfpunkt:** Plugin `os-net-snmp`, *Services → Net-SNMP*: aktivieren, Community **public** | Erwartet: FAIL. **Vermutlich** meldet das Tool N/A oder einen veralteten Wert, weil die Engine SNMP nur unter `<snmpd>` sucht. Protokollieren |
| T2-39 | OPN | OPN-GUI | L | *Services → Unbound DNS → Access Lists*: Default Action **Allow** | `SVC-DNS-OPENRESOLVER` = WARN; Deny → OK; Unbound aus → N/A |
| T2-40 | PF | PF-GUI | L | *Services → DNS Resolver*, Network Interfaces = **All** | `SVC-DNS-OPENRESOLVER` = WARN; nur LAN → OK |
| T2-41 | beide | OPN-GUI / PF-GUI | S | WAN-Regel Pass **UDP**, Ziel This Firewall, Port **123** | `SVC-NTP-OPEN` = WARN |
| T2-42 | beide | OPN-GUI / PF-GUI | S | Wie T2-41, Port über Port-Alias mit `123` | `SVC-NTP-OPEN` = WARN (Alias-Auflösung) |
| T2-43 | beide | OPN-GUI / PF-GUI | S | WAN-Regel Pass UDP Ziel This Firewall **ohne Port** (alle Ports) | Bekannte Lücke: `SVC-NTP-OPEN` = OK, obwohl NTP erreichbar wäre (erfasst wird die Regel von `FW-WAN-EXPOSURE`). Bestätigen |
| T2-44 | OPN | OPN-GUI | L | *Services → Intrusion Detection → Administration*: „Enabled“ aus (IDS aber eingerichtet) | `SVC-IDS-DISABLED` = FAIL; `SVC-IDS-NOIPS` = N/A |
| T2-45 | OPN | OPN-GUI | L | Enabled an, „IPS mode“ aus | `SVC-IDS-DISABLED` = OK; `SVC-IDS-NOIPS` = WARN |
| T2-46 | OPN | OPN-GUI | L | Enabled an, IPS mode an | beide OK |
| T2-47 | PF | PF-GUI | L | Suricata (oder Snort) installiert, Interface **deaktiviert** | `SVC-IDS-DISABLED` = FAIL |
| T2-48 | PF | PF-GUI | L | Interface aktiv, „Block Offenders“ aus bzw. kein Inline-Modus | `SVC-IDS-NOIPS` = WARN; Block Offenders an → OK |
| T2-49 | PF | PF-GUI | L | Kein IDS-Paket installiert | `SVC-IDS-DISABLED` und `SVC-IDS-NOIPS` = N/A |

### 2.5 VPN

| ID | Plattform | Wo | Methode | Einstellung | Erwartet |
|---|---|---|---|---|---|
| T2-50 | OPN | OPN-GUI | L | *VPN → IPsec → Connections*: Verbindung mit Version **IKEv1** | `VPN-IKEV1` = FAIL, Befund „Swanctl '…' nutzt IKEv1“ |
| T2-51 | OPN | OPN-GUI | L | Legacy-Tunnel (*VPN → IPsec → Tunnel Settings*) Phase 1 Key Exchange **V1** oder Modus „Aggressive“ | `VPN-IKEV1` = FAIL |
| T2-52 | PF | PF-GUI | L | *VPN → IPsec → Tunnels*: Phase 1 **IKEv1**, Negotiation mode **Aggressive** | `VPN-IKEV1` = FAIL |
| T2-53 | beide | OPN-GUI / PF-GUI | L | Nur IKEv2-Verbindungen | `VPN-IKEV1` = OK; kein IPsec → N/A |
| T2-54 | OPN | OPN-GUI | L | *VPN → OpenVPN → Instances*: Data Ciphers nur **AES-256-CBC** | `VPN-OVPN-CIPHER` = WARN; mit AES-256-GCM → OK |
| T2-55 | OPN | OPN-GUI | L | **Prüfpunkt:** OpenVPN-Server über die **Legacy**-Seite (*VPN → OpenVPN → Servers [legacy]*) mit CBC-Cipher | Erwartet: WARN. **Vermutlich** N/A, weil die Engine auf OPNsense nur „Instances“ liest. Protokollieren |
| T2-56 | PF | PF-GUI | L | *VPN → OpenVPN → Servers*: Data Encryption Algorithms nur **AES-128-CBC** | `VPN-OVPN-CIPHER` = WARN; mit GCM → OK |
| T2-57 | beide | OPN-GUI / PF-GUI | S | VPN-Interface zuweisen (*Interfaces → Assignments*, z. B. `wg0`/`ovpns1`, Beschreibung enthält „VPN“, „WireGuard“ o. ä.), darauf Pass-Regel Ziel **any** | `VPN-FULL-ACCESS` = WARN, Befund mit Regelnummer |
| T2-58 | beide | OPN-GUI / PF-GUI | S | **Prüfpunkt:** Keine VPN-Interfaces zugewiesen, Pass-Regel Ziel any nur auf dem Gruppen-Reiter („WireGuard“ bzw. „OpenVPN“) | Bekannte Lücke: `VPN-FULL-ACCESS` = N/A „Keine VPN-Interfaces erkannt“. Bestätigen |
| T2-59 | OPN | OPN-GUI | L | *VPN → WireGuard*: Instanz mit n Peers | `VPN-WG-PRESENT` = WARN „Tunnels: 1, Peers: n“. **Zahl mit der GUI vergleichen** – das ist die korrigierte Prüfung |
| T2-60 | PF | PF-GUI | L | WireGuard-Paket: Tunnel mit n Peers | `VPN-WG-PRESENT` = WARN mit korrekten Zahlen |
| T2-61 | beide | OPN-GUI / PF-GUI | L | Kein WireGuard | `VPN-WG-PRESENT` = N/A |

### 2.6 System-Härtung

| ID | Plattform | Wo | Methode | Einstellung | Erwartet |
|---|---|---|---|---|---|
| T2-62 | beide | – | – | (keine Änderung) | `SYS-FIRMWARE` und `SYS-BACKUP-SECRETS` = immer MANUELL. OPN: Befund listet installierte Plugins; PF: Config-Version |
| T2-63 | OPN | OPN-GUI | L | *System → Settings → Logging → Remote*: Ziel anlegen | `SYS-SYSLOG-REMOTE` = OK „1 Ziel(e)“; ohne Ziel → WARN |
| T2-64 | PF | PF-GUI | L | *Status → System Logs → Settings*: „Enable Remote Logging“ + Server | `SYS-SYSLOG-REMOTE` = OK mit Servername |
| T2-65 | OPN | OPN-GUI | L | *System → Access → Users*: API-Schlüssel für ein Konto erzeugen | `SYS-API-KEYS` = WARN, Befund nennt das Konto; gelöscht → OK |

### 2.7 Regel-Reihenfolge

Eine **Auffang-Regel** erfasst jeden Verkehr: aktiv, Quelle any, Ziel any ohne Port, Protokoll any, weder Zeitplan noch Tag noch Negation, keine Floating-Regel. Jede spätere aktive Regel auf demselben Interface in derselben Richtung wird nie erreicht. Alle Tests arbeiten mit Methode S (speichern, exportieren, entfernen, **nie anwenden**).

| ID | Plattform | Wo | Methode | Einstellung (auf einem Interface, Reihenfolge von oben nach unten) | Erwartet |
|---|---|---|---|---|---|
| T2-66 | beide | OPN-GUI / PF-GUI | S | 1. Block, Quelle any, Ziel any, Protokoll any – 2. Pass TCP Ziel any Port 443 | `FW-SHADOWED-PASS` = WARN: „#… 'Pass …' wird nie erreicht – verdeckt durch #… block …“ |
| T2-67 | beide | OPN-GUI / PF-GUI | S | Wie T2-66, dann die Block-Regel per Ziehen **ans Ende** verschieben | `FW-SHADOWED-PASS` = OK |
| T2-68 | beide | OPN-GUI / PF-GUI | S | 1. Pass any→any – 2. Block, Ziel ein einzelner Host | `FW-SHADOWED-BLOCK` = WARN (Schweregrad mittel) |
| T2-69 | OPN | OPN-GUI | S | Wie T2-68, aber die Block-Regel mit Richtung **out** | Kein Befund: andere Richtung |
| T2-70 | OPN | OPN-GUI | S | 1. Pass any→any nur **IPv6** – 2. Block nur **IPv4** | Kein Befund: IPv6 verdeckt IPv4 nicht |
| T2-71 | OPN | OPN-GUI | S | 1. Pass any→any **IPv4+IPv6** – 2. Block nur IPv4 | `FW-SHADOWED-BLOCK` = WARN |
| T2-72 | beide | OPN-GUI / PF-GUI | S | Wie T2-68, die Pass-Regel bekommt einen **Zeitplan** (Schedule) | Kein Befund: mit Zeitplan keine Auffang-Regel |
| T2-73 | beide | OPN-GUI / PF-GUI | S | Wie T2-68, die Pass-Regel ist **deaktiviert** | Kein Befund |
| T2-74 | beide | OPN-GUI / PF-GUI | S | Wie T2-68, die Pass-Regel hat Ziel any mit **Port 443** | Kein Befund: keine Auffang-Regel |
| T2-75 | beide | OPN-GUI / PF-GUI | S | Floating-Regel Pass any→any, danach auf einem Interface eine Block-Regel | Kein Befund: Floating-Regeln werden nicht einbezogen (bekannte Grenze) |
| T2-76 | OPN | OPN-GUI | S | **Prüfpunkt:** Pass any→any auf dem Reiter einer **Interface-Gruppe**, danach Block auf einem Mitglieds-Interface | Kein Befund erwartet (Gruppenregeln werden nicht mit Interface-Regeln verglichen). Ergebnis protokollieren |

---

## Phase 3 – Einstellungen aus dem Regel-Editor

Diese Tests brauchen **keine** Änderung an der Firewall. Grundlage ist ein Export aus Phase 1 bzw. ein Export mit der Testregel aus Phase 2.

Vor Phase 3: `fvp-neu/rules.js` als `rules.js.orig` sichern. Nach jedem Testfall die Sicherung zurückkopieren.

Grundablauf: Im Editor ändern → „Als neue Version speichern …“ → heruntergeladene Datei als `rules.js` in `fvp-neu` legen (alte ersetzen, ggf. aus „rules (1).js“ umbenennen) → `index.html` neu laden → Export laden → vergleichen.

| ID | Wo | Änderung im Editor | Export | Erwartet |
|---|---|---|---|---|
| T3-01 | PC | *Katalog-Einstellungen*: WAN-Interfaces = `wan, opt2` (Name deines zweiten Providers bzw. irgendeines weiteren Interfaces) | Phase 1 | `FW-BLOCKPRIV`/`FW-BLOCKBOGON` prüfen jetzt beide Interfaces; Regeln auf `opt2` zählen bei `FW-WAN-EXPOSURE` mit |
| T3-02 | PC | Regel `NAT-MGMT-EXPOSED`, Parameter `sensitive_ports` ohne `3389` | T2-28 | `NAT-MGMT-EXPOSED` = OK statt FAIL |
| T3-03 | PC | Wie T3-02, aber Wert `["abc"]` eintragen | – | Editor lehnt ab: „Liste ganzer Zahlen zwischen 1 und 65535 erwartet“ |
| T3-04 | PC | Regel `SVC-SNMP-PUBLIC`, Parameter `default_communities` um deine eigene Community erweitern | T2-36 | `SVC-SNMP-PUBLIC` = FAIL statt WARN |
| T3-05 | PC | Regel `FW-ANY-ANY`, Parameter `wan_zone_severity` = `critical` | T2-19 | `FW-ANY-ANY` = FAIL mit Schweregrad kritisch; Score sinkt |
| T3-06 | PC | *Katalog-Einstellungen*: Strafpunktfaktor WARN = `1` | Phase 1 | Score sinkt bei jeder Config mit WARN-Befunden; ohne WARN unverändert |
| T3-07 | PC | Beliebige Regel mit FAIL-Befund **deaktivieren** | Phase 1 | Regel fehlt im Bericht (auch unter „Alle“), Score steigt |
| T3-08 | PC | Schweregrad einer FAIL-Regel von „mittel“ auf „kritisch“ | Phase 1 | Score sinkt; Regel steht weiter oben in der Liste |
| T3-09 | PC | Neue Regel anlegen, z. B. `SVC-TEST-NEU` | Phase 1 | Regel erscheint mit Status MANUELL „Keine automatische Prüfung implementiert“; Score unverändert |
| T3-10 | PC | Nach dem Speichern `rules.js` im Editor erneut öffnen, *Katalog-Einstellungen* ansehen | – | Neue Version, Changelog-Eintrag mit deiner Notiz und den geänderten Regel-IDs |
| T3-11 | PC | `tests/selbsttest.html` öffnen, während die geänderte `rules.js` aktiv ist | – | Weiterhin 340/340 – der Selbsttest nutzt seinen eigenen Katalog und bleibt unbeeinflusst |

### Eigene Prüfungen schreiben

Für diese Tests im Editor oben „rules.js öffnen …“ nicht nötig; der Katalog lädt automatisch. Im Bereich **Prüfung** einer Regel gibt es „Test-Config laden …“ und „Probelauf“.

| ID | Wo | Schritt | Export | Erwartet |
|---|---|---|---|---|
| T3-12 | PC | Regel `SVC-NTP-OPEN` öffnen, „Test-Config laden …“ mit dem Export aus T2-41, dann „Probelauf“ | T2-41 | WARN „NTP (UDP/123) per WAN erreichbar.“, 1 Treffer – ohne zu speichern |
| T3-13 | PC | In derselben Prüfung `"123"` durch `"124"` ersetzen, „Probelauf“ | T2-41 | OK, 0 Treffer. Danach „Änderungen verwerfen“ |
| T3-14 | PC | Prüfung verfälschen: einen Schlüssel falsch schreiben (z. B. `"ergebnis"` → `"ergebniss"`), „Aufbau prüfen“, dann „Übernehmen“ | – | Aufbauprüfung nennt den unbekannten Schlüssel; „Übernehmen“ wird mit derselben Meldung abgelehnt |
| T3-15 | PC | Neue Regel `FW-WAN-SSH-EIGEN` anlegen: Vorlage „Firewall-Regeln filtern“, darin `"25"` durch `"@param:ports"` ersetzen, unter Parameter `{"ports": ["22"]}` eintragen, „Probelauf“ | T2-06 | WARN mit der SSH-Regel aus T2-06 als Befund |
| T3-16 | PC | T3-15 anlegen, als neue Version speichern, `rules.js` ersetzen, Export in `index.html` laden | T2-06 | Die eigene Regel steht im Bericht mit Status WARN und dem gewählten Schweregrad |
| T3-17 | PC | **Prüfpunkt nachbessern:** Zeigte T2-38 (OPNsense SNMP-Plugin) N/A, in `SVC-SNMP-PUBLIC` den Pfad unter `werte → community → pfad` um den Ablageort deiner Version ergänzen (im Export nachsehen), „Probelauf“ | T2-38 | Erwartetes Ergebnis aus T2-38. Gelingt es, ist die Lücke ohne Programmierung behoben |
| T3-18 | PC | Bei einer beliebigen Regel das Prüfungsfeld leeren, „Übernehmen“ | Phase 1 | In der Liste erscheint „ohne Prüfung“; im Bericht steht die Regel als MANUELL. Danach „Auf geladenen Stand zurücksetzen“ |

---

## Phase 4 – Anzeige und Robustheit

| ID | Wo | Schritt | Erwartet |
|---|---|---|---|
| T4-01 | PC | Mehrere Exporte gleichzeitig laden | Fleet-Dashboard, Klick auf ein Gerät öffnet dessen Bericht, Rückweg zum Dashboard funktioniert |
| T4-02 | PC | Eine beliebige andere XML-Datei laden (z. B. eine RSS- oder Office-XML) | Fehlermeldung „Wurzelelement ist <…>, erwartet <opnsense> oder <pfsense>“, kein Absturz |
| T4-03 | PC | `engine.js` testweise aus dem Ordner entfernen und `index.html` neu laden | Rote Meldung „engine.js konnte nicht geladen werden …“ direkt beim Öffnen. Danach `engine.js` zurücklegen |
| T4-04 | PC | Bericht drucken (Strg+P) | Druckbild wie bisher, Filter ausgeblendet |
| T4-05 | PC | `fvp-neu` in einem zweiten Browser öffnen (Firefox und Chrome/Edge) und T1-03 wiederholen | Gleiche Ergebnisse |

---

## Auswertung

- **Phase 1** muss vollständig passen (bis auf die vier erlaubten Abweichungen). Sonst ist der Umbau fehlerhaft.
- **Phase 2** zeigt, welche Regeln auf deinen Versionen zuverlässig arbeiten. Die als **Prüfpunkt** markierten Fälle (T2-27, T2-32, T2-33a, T2-38, T2-55, T2-76) und die **bekannten Lücken** (T2-43, T2-58) sind die wahrscheinlichsten Abweichungen. Liegt nur eine Einstellung an einem anderen Ort, lässt sich das oft selbst im Editor beheben (siehe T3-17). Betrifft es Firewall- oder NAT-Regeln (T2-27, T2-32, T2-33a), muss die Fakten-Schicht in `engine.js` erweitert werden; dafür wird der bereinigte Export gebraucht.
- **Phase 3** muss vollständig passen. Sonst wirkt eine Katalog-Einstellung nicht wie dokumentiert. T3-17 ist die Ausnahme: Es zeigt, ob sich eine Prüfpunkt-Lücke per Pfad-Ergänzung schließen lässt oder ob die Engine erweitert werden muss.

Die gesammelten Exporte mit gesetzten Einstellungen sind zusätzlich wertvoll: Bereinigt ergänzen sie die synthetischen Test-Configs in `tests/configs/` um echte Beispiele deiner Versionen und machen den Selbsttest für künftige Änderungen deutlich aussagekräftiger.
