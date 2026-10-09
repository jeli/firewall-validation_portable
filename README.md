# Firewall-Validation Portable

Ein portabler Security-Auditor für **OPNsense**- und **pfSense**-Firewalls — vollständig clientseitig, ohne Server, ohne Installation, ohne Datenübertragung.

Das Tool prüft eine vom Nutzer selbst exportierte Firewall-Konfiguration (`config.xml`) gegen einen quantifizierten Regelkatalog (34 Regeln, 6 Kategorien), berechnet daraus einen **Posture-Score (0–100)** und eine **Note (A–F)** und erstellt einen lesbaren Auditbericht mit Begründung, Maßnahme und Referenzen für jeden Befund. Beim Laden mehrerer Konfigurationen erscheint zusätzlich ein **Fleet-Dashboard** zur Flottenanalyse.

## Features

### Audit (Einzelkonfiguration)
- **Automatische Plattform-Erkennung** — OPNsense und pfSense (CE) anhand des XML-Wurzelelements; plattformspezifische Prüfpfade (z. B. OPNsense-Nested-Config, pfSense-IDS-Pakete Suricata/Snort).
- **34 Regeln in 6 Kategorien:**

  | Kategorie | Regeln (Beispiele) |
  |---|---|
  | Management-Ebene (8) | WebGUI/SSH vom WAN erreichbar, HTTP statt HTTPS, Root-Login, SSH-Passwort-Auth, MFA/OTP für Admins, root-Konto, Konsolenmenü |
  | Firewall-Regeln (9) | Verdeckte Regeln durch falsche Reihenfolge (Block- und Freigaberegeln hinter einer Auffang-Regel), any→any-Pass-Regeln, WAN-Exposition, „Block private/bogon networks", Tippfehler-Netzmasken (Host-IP mit /24), deaktivierte Regeln, Block ohne Logging |
  | NAT / Port-Forwarding (4) | Weiterleitung sensibler Ports (SSH, RDP, SMB, DBs, VNC, Redis, ES, MongoDB …), Quelle ANY, UPnP/NAT-PMP, 1:1-NAT |
  | Dienst-Exposition (5) | SNMP-Standard-Community, Unbound Open-Resolver-Risiko, offenes NTP, IDS/IPS deaktiviert, IDS ohne Blockmodus |
  | VPN (4) | IPsec IKEv1/Aggressive Mode, OpenVPN ohne AEAD-Cipher, uneingeschränkter VPN-Zugriff (ANY), WireGuard Allowed-IPs-Review |
  | System-Härtung (4) | Firmware-Stand (Live-Check-Hinweis), Remote-Syslog, API-Schlüssel, Secrets in config.xml |

- **Status je Regel:** `FAIL` (Schwachstelle), `WARN` (bedingtes Risiko), `OK` (erfüllt), `N/A` (nicht zutreffend), `MANUELL` (Live-Prüfung nötig), `FEHLER` (Prüfungsfehler).
- **Detailbericht** je Regel mit Findings (konkrete Regelnummern, Ports, Konten), Begründung, empfohlener Maßnahme und Referenzen.
- **Filter** im Bericht: Offen (FAIL+WARN), nur FAIL, nur WARN, Bestanden, Manuell, N/A, Alle.
- **Alias-Auflösung:** Host- und Port-Aliase (inkl. verschachtelter Aliase) werden aufgelöst und in Port- und Zielprüfungen einbezogen.

### Fleet-Dashboard (mehrere Konfigurationen)
- **KPIs:** Ø- und Median-Posture-Score, Geräteanzahl, Geräte mit Handlungsbedarf (Note < B), Geräte mit kritischen/hohen Befunden, offene Befunde gesamt.
- **Verteilungen:** Notenverteilung (A–F) und Score-Histogramm (10-Punkte-Buckets).
- **Systemische Befunde:** Häufigste FAIL/WARN-Regeln flottenweit, mit Drill-down („welche Standorte haben diesen Befund?").
- **Kategorie-Ansicht:** Standorte mit FAIL je Kategorie.
- **Standort-Tabelle:** sortier- und durchsuchbar, filterbar nach Note, Plattform, „nur kritische", „Handlungsbedarf", mit Pagination; Klick auf ein Gerät öffnet dessen Einzelbericht mit Rückkehr zum Dashboard.

### Bedienung & Technik
- **Drag & Drop** oder Dateiauswahl; mehrere Dateien = Fleet-Modus.
- **100 % clientseitig:** XML wird per `DOMParser` im Browser geparst — keine Uploads, kein Backend, offline nutzbar (auch via `file://`).
- **Druck-optimiert** (Print-Stylesheet; Filter ausgeblendet, Abschnitte nicht umgebrochen).
- **Responsive** Layout (Desktop + Mobile).

## Scoring-Modell

Jede Regel hat einen Schweregrad mit Gewicht:

| Schweregrad | Gewicht |
|---|---|
| kritisch | 10 |
| hoch | 6 |
| mittel | 3 |
| niedrig | 1 |
| info | 0 |

Berechnung:

```
Penalty  = Σ (Gewicht × Faktor)   mit FAIL = 1.0, WARN = 0.5, OK = 0.0
Posture  = 100 × (1 − Penalty / max. mögliche Penalty)
Note     = A ≥ 90, B ≥ 80, C ≥ 70, D ≥ 60, sonst F
```

`N/A` und `MANUELL` fließen **nicht** in den Nenner ein — der Score wird also nur nach tatsächlich bewertbaren Regeln normiert.

## Voraussetzungen

- **Ein moderner Webbrowser** mit aktiviertem JavaScript (ES2017+: `async/await`, `DOMParser`, `Set`, `Object.assign`). Firefox, Chrome/Chromium, Edge und Safari (aktuell) werden unterstützt.
- **Diese Dateien müssen zusammen im selben Verzeichnis liegen:**
  - `index.html` — Anzeige: Upload, Einzelbericht, Fleet-Dashboard
  - `engine.js` — Prüf-Logik: XML einlesen, Regelsprache ausführen, Scoring
  - `rules.js` — Regelkatalog und Einstellungen (wird per `<script>`-Tag als `window.RULES_DATA` eingebunden)
  - `rules-editor.html` — optionaler Editor für den Regelkatalog (siehe unten)
  - `tests/` — optional: Selbsttest der Prüf-Engine und Referenz-Configs (siehe unten)
  - `LICENSE` — Lizenztext (GNU GPL Version 3); `NOTICE` — Urheberhinweis und Zusatzbedingung nach Abschnitt 7(b) (siehe [Lizenz](#lizenz))
  - `site/` und `.github/workflows/pages.yml` — Projektseite für GitHub Pages (siehe [Projektseite](#projektseite-auf-github-pages)); für den Betrieb des Werkzeugs nicht nötig
  - `HANDBUCH.html` / `HANDBUCH.pdf` — ausführliches Benutzerhandbuch zu `index.html` und Regel-Editor mit annotierten Screenshots (die HTML-Fassung ist eigenständig, Bilder eingebettet; das PDF ist dieselbe Fassung zum Drucken)
- **Kein Webserver, kein Build, keine weiteren Abhängigkeiten** — das direkte Öffnen der `index.html` vom Dateisystem (`file://`) funktioniert ebenso wie das Hosting auf einem beliebigen statischen Server oder Forge (GitHub Pages, Codeberg Pages).
- **Die zu prüfende `config.xml` ist NICHT Teil dieses Repositories.** Sie wird vom Nutzer selbst von seiner Firewall exportiert (beliebig viele Geräte):
  - OPNsense: *System → Configuration → Backups → Download*
  - pfSense: *Diagnostics → Backup & Restore*

## Verwendung

1. `index.html` im Browser öffnen (Doppelklick genügt).
2. Die von der Firewall exportierte `config.xml` per Drag & Drop ablegen oder über „Datei auswählen" laden. Die Datei wird ausschließlich lokal im Browser gelesen.
   - Eine Datei → Einzelbericht mit Scorecard, Übersichts-Tabelle und Detailbefunden.
   - Mehrere Dateien → Fleet-Dashboard mit Aggregation; Klick auf ein Gerät zeigt dessen Einzelbericht.
3. Bericht bei Bedarf drucken (Strg+P) oder filtern.

## Aufbau: Datenmodell, Logik und Anzeige

Seit Katalog 1.2.0 steht auch **was** geprüft wird im Datenmodell:

| Datei | Rolle | Enthält |
|---|---|---|
| `rules.js` | Datenmodell | Regeln mit Texten, Schweregrad, aktiv/inaktiv, Parametern **und Prüfdefinition** (Feld `check`), dazu globale Einstellungen (Gewichte, Strafpunktfaktoren, WAN-Interfaces) |
| `engine.js` | Logik | Fakten-Schicht (übersetzt die `config.xml` je Plattform in einheitliche Objekte), Interpreter der Regelsprache, 4 Bausteine in Programmcode, Scoring. Keine Anzeige. |
| `index.html` | Anzeige | Datei-Upload, Einzelbericht, Fleet-Dashboard. Keine Prüflogik. |
| `rules-editor.html` | Pflege | Bearbeitet `rules.js` einschließlich der Prüfungen; Aufbauprüfung und Probelauf über `engine.js` |

Pro Audit läuft die Engine jede aktive Regel des Katalogs durch und führt deren Prüfdefinition aus. Das Ergebnis (Status, Befunde, ggf. abweichender Schweregrad) wird mit Gewicht und Strafpunktfaktor aus `rules.js` verrechnet. 30 der 34 Regeln bestehen nur aus Daten; 4 rufen einen **Baustein** auf, weil ihre Logik (Port aus der Config ableiten, verschränkte Benutzerlisten, Netzmasken-Arithmetik) den Rahmen der Regelsprache sprengen würde: `MGMT-WEBGUI-WAN`, `MGMT-SSH-WAN`, `MGMT-ROOT-ACCOUNT`, `FW-HOST-CIDR`.

**Wirksame Einstellungen aus `rules.js`** (fehlt ein Wert oder ist er ungültig, gilt der Standard):

| Einstellung | Wirkung | Standard |
|---|---|---|
| `meta.severity_weights` | Gewicht je Schweregrad | 10 / 6 / 3 / 1 / 0 |
| `meta.scoring.penalty_fail/warn/pass` | Anteil des Gewichts, der als Strafpunkte zählt | 1.0 / 0.5 / 0.0 |
| `meta.wan_interfaces` | Interfaces, die als Internetseite gelten (alle WAN-Prüfungen) | `["wan"]` |
| `NAT-MGMT-EXPOSED` → `params.sensitive_ports` | Ports, deren WAN-Weiterleitung als sensibel gilt | 22, 23, 135, 139, 445, 1433, 3306, 3389, 5432, 5900, 5901, 6379, 9200, 11211, 27017 |
| `SVC-SNMP-PUBLIC` → `params.default_communities` | Als unsicher geltende SNMP-Communities | public, private |
| `FW-ANY-ANY` → `params.wan_zone_severity` | Schweregrad einer any-any-Regel auf WAN | high |

Weitere Prüfwerte (z. B. NTP-Port 123, Cipher-Listen, XML-Pfade) stehen direkt in der jeweiligen Prüfdefinition und sind damit ebenfalls im Editor änderbar. Eigene Regeln können eigene Parameter anlegen und in der Prüfung mit `"@param:name"` verwenden.

## Regelkatalog bearbeiten (`rules-editor.html`)

Der Editor ist wie `index.html` vollständig offline nutzbar (`file://`, keine Abhängigkeiten) und lädt die `rules.js` aus demselben Ordner automatisch. Alternativ lässt sich über „rules.js öffnen …" jede andere Katalogdatei laden (auch eine reine `rules.json`).

- **Anzeigen & suchen:** Regeln nach Kategorie gruppiert, Farbbalken = Schweregrad, deaktivierte Regeln durchgestrichen; Suche über ID, Titel und Kategorie.
- **Bearbeiten:** Titel, Kategorie, Schweregrad, aktiv/inaktiv, Begründung, Maßnahme, Referenzen (eine pro Zeile) und optionale Parameter (JSON). „Übernehmen" schreibt die Änderung in den Katalog; geänderte und neue Regeln sind in der Liste markiert.
- **Neue Regeln / Löschen:** Neue Regeln werden am Ende ihrer Kategorie eingefügt. IDs werden auf Format und Eindeutigkeit geprüft.
- **Katalog-Einstellungen:** Name, Beschreibung, Gewichte je Schweregrad, Strafpunktfaktoren und die WAN-Interfaces (z. B. `wan, opt2` bei zwei Providern).
- **Parameter:** Zu jeder Regel zeigt der Editor, welche Parameter die Engine tatsächlich liest (fest verdrahtete sowie per `@param:` in der Prüfung verwendete). Die fest verdrahteten werden vor dem Übernehmen auf gültige Werte geprüft.
- **Prüfung:** Die Prüfdefinition jeder Regel als JSON. Über „Vorlage einfügen …“ gibt es Ausgangspunkte für jeden Prüftyp, „Aufbau prüfen“ meldet Tipp- und Strukturfehler mit genauer Stelle, die aufklappbare **Sprachreferenz** listet alle Quellen, Felder und Operatoren (direkt aus `engine.js` erzeugt). **„Probelauf“** führt die Prüfung – auch ungespeichert – gegen eine geladene `config.xml` aus und zeigt Status, Treffer und Befunde.
- **Regeln ohne Prüfung** sind in der Liste mit „ohne Prüfung“ gekennzeichnet; sie erscheinen im Bericht als `MANUELL`.
- **Als neue Version speichern:** Der Dialog zeigt, was sich gegenüber dem geladenen Stand geändert hat, schlägt eine Versionsnummer vor (Minor bei neuen/entfernten Regeln, geänderter Gewichtung oder geänderter Prüfung, sonst Patch) und schreibt einen Eintrag in `meta.changelog`. Heruntergeladen wird eine neue `rules.js` — diese neben `index.html` ablegen und die alte ersetzen. Optional lässt sich derselbe Stand als `rules.json` für das Python-Audit-Tool exportieren. Das Python-Tool wertet das Feld `check` derzeit nicht aus; neue Regeln erscheinen dort als `MANUAL`.

> **Hinweis zu älteren Katalogen:** Kataloge vor 1.2.0 enthalten keine Prüfdefinitionen. Mit der aktuellen `engine.js` werden dort nur die 4 Bausteine ausgewertet, alle übrigen Regeln erscheinen als `MANUELL`. Deshalb immer die mitgelieferte `rules.js` 1.2.0 (oder neuer) verwenden.

## Eigene Prüfungen schreiben (Regelsprache)

Eine Prüfung ist ein JSON-Objekt im Feld `check` einer Regel. Die vollständige Liste aller Quellen, Felder und Operatoren zeigt der Editor unter „Sprachreferenz“; hier das Prinzip.

**Drei Typen:**

| `typ` | Zweck |
|---|---|
| `abfrage` (Standard, darf fehlen) | Werte aus der Config lesen und/oder Einträge filtern, dann Ergebnis-Fälle auswerten |
| `reihenfolge` | Paare finden, bei denen eine Regel A vor einer Regel B steht (gleiche Gruppe, z. B. Interface und Richtung) |
| `baustein` | Prüfung in Programmcode aufrufen: `{"typ": "baustein", "name": "MGMT-WEBGUI-WAN"}` |

**Bausteine einer Abfrage:**

- `werte` – benannte Angaben aus der Config: `{"pfad": "system/webgui/protocol", "standard": "https", "klein": true}`, `{"anzahl": "OPNsense/Syslog/destinations/destination"}` oder `{"verbinde": ["syslog/remoteserver", "syslog/remoteserver2"]}`. Pfade dürfen je Plattform verschieden sein: `{"opnsense": "…", "pfsense": "…"}`.
- `quelle` + `wo` + `vorlage` – Einträge einer Faktenquelle filtern (`filterregeln`, `nat`, `benutzer`, `interfaces`, `wan_interfaces`, `ids_instanzen`) und je Treffer einen Text bilden. Statt `quelle` geht auch `xml` mit einem XML-Pfad (`a/b/c`, `a/*` für alle Kinder, `//name` für das erste Vorkommen irgendwo). Mehrere Abfragen: `abfragen: [ … ]`, jede optional mit `plattform`.
- `ergebnis` – Liste von Fällen, **der erste passende gilt**; der letzte Fall ohne `wenn` ist der Standard. Ein Fall hat `status` (FAIL, WARN, PASS, NA, MANUAL), optional `schweregrad`, `befund` (ein Text) oder `befunde: "je_treffer"` (ein Befund pro Treffer) und `notiz`.

**Bedingungen** (in `wo` und `wenn`): Kurzform `{"aktiv": true, "aktion": ["block", "reject"]}` (alle Felder müssen passen, eine Liste heißt „einer davon“), Operatoren über `{"feld": "ziel_port", "port_ist": ["123"]}`, Verknüpfungen `und`, `oder`, `nicht`, Schalter und Pfade `eingeschaltet`, `existiert`, Mengen `eine` / `keine` (eine Unterabfrage), `treffer_mit`, sowie als Wert von `wenn` die Wörter `"treffer"`, `"keine_treffer"` und `"quellen_leer"`. Texte werden ohne Groß-/Kleinschreibung verglichen.

**Textvorlagen:** `{feld}`, `{feld|Ersatz wenn leer}`, `{feld:klein}`, `{?feld=Text nur wenn Feld wahr}`, `{liste}` (alle Treffertexte, durch Komma getrennt), bei Reihenfolge-Prüfungen `{vorher.nr}` und `{nachher.descr}`.

**Beispiel 1 – eigene Regel:** SSH-Freigabe auf WAN (Ports als Parameter der Regel, `"params": {"ports": ["22", "2222"]}`):

```json
{
  "quelle": "filterregeln",
  "wo": {"und": [{"aktiv": true, "aktion": "pass", "ist_wan": true},
                 {"feld": "ziel_port", "port_ist": ["@param:ports"]}]},
  "vorlage": "#{nr} [{interface}] {quelle_anzeige} -> {ziel_text} - '{descr}'",
  "ergebnis": [
    {"wenn": "treffer", "status": "WARN", "befunde": "je_treffer"},
    {"status": "PASS"}
  ]
}
```

**Beispiel 2 – Ablageort nachtragen:** Zeigt der Testplan, dass eine Einstellung in deiner Version woanders liegt, genügt es, den Pfad zu ergänzen – z. B. bei SNMP `"community": {"pfad": ["snmpd/rocommunity", "OPNsense/netsnmp/general/community"]}`. Mit „Probelauf“ gegen den betreffenden Export sofort prüfbar.

**Grenzen:** Neue Faktenquellen (z. B. Regeln aus *Firewall → Automation*), neue Operatoren oder neue Bausteine erfordern eine Erweiterung von `engine.js`. Die Sprache ist bewusst klein gehalten: keine Variablen, keine Schleifen.

### Korrekturen gegenüber Katalog 1.1.0

- `SVC-DNS-OPENRESOLVER` (pfSense): Eine Interface-Liste wie `lan,opt2,wan` wird vollständig ausgewertet. Bisher wurde nur das erste Komma berücksichtigt und `wan` in solchen Listen übersehen.
- Textvergleiche sind durchgängig unabhängig von Groß-/Kleinschreibung. Das ändert nur Ergebnisse für ungewöhnliche Schreibweisen (z. B. `IKEv1` statt `ikev1`).
- Neue Regeln `FW-SHADOWED-BLOCK` und `FW-SHADOWED-PASS`. Da sie auch die maximal mögliche Strafpunktzahl erhöhen, können sich Scores leicht verschieben – in beide Richtungen.

## Selbsttest (`tests/selbsttest.html`)

`tests/selbsttest.html` im Browser öffnen. Die Seite wertet zehn synthetische Test-Configs (OPNsense und pfSense, jeweils „schwach“, „gehärtet“, „minimal“, Varianten und Fälle zur Regel-Reihenfolge) mit `engine.js` aus und vergleicht alle 340 Einzelergebnisse mit einer gespeicherten Referenz. Sie nutzt eine eigene, festgeschriebene Kopie des Katalogs (`tests/katalog-referenz.js`), sodass Änderungen an `rules.js` den Test nicht beeinflussen.

- **Nach jeder Änderung an `engine.js` ausführen.** Erwartet: „Alle 340 Ergebnisse stimmen mit der Referenz überein“.
- Eine Abweichung ist nicht zwingend ein Fehler: Wurde die Prüflogik bewusst geändert, muss die Referenz neu erzeugt werden.
- Die Test-Configs liegen zusätzlich als `tests/configs/*.xml` bei und lassen sich auch direkt in `index.html` laden.

Einen Testplan für die Prüfung mit realen Firewall-Konfigurationen enthält `TESTPLAN.md`.

## Sicherheitshinweis

Die `config.xml` enthält **Passwort-Hashes, VPN-Schlüssel und ggf. PSKs**. `rules.js` und `engine.js` werden per `<script>` geladen und damit als Programmcode ausgeführt – Katalogdateien aus unbekannten Quellen vor dem Einsatz prüfen. Da das Tool ausschließlich clientseitig arbeitet, verlässt die Konfiguration den Rechner nicht — trotzdem gilt: Audits möglichst offline durchführen, Ausgaben und Backups verschlüsselt aufbewahren und den Zugriff begrenzen.

Ein automatisiertes Audit ersetzt keine manuelle Prüfung (Regeln mit Status `MANUELL` erfordern zwingend einen Live-Check auf der Appliance).

## Projektseite auf GitHub Pages

Der Ordner `site/` enthält eine Projektseite, die das Werkzeug vorstellt. Der Workflow `.github/workflows/pages.yml` veröffentlicht bei jedem Push auf `main`:

| Adresse | Inhalt |
|---|---|
| `https://<benutzer>.github.io/<repository>/` | Projektseite |
| `…/app/` | das Werkzeug selbst als Demo, mit den Beispiel-Configs unter `app/tests/configs/` |
| `…/HANDBUCH.html`, `…/HANDBUCH.pdf` | Benutzerhandbuch |

Einmalig einrichten: im Repository unter *Settings › Pages* bei *Source* „GitHub Actions“ wählen. Links zum Repository und zum ZIP-Download setzt der Workflow selbst ein; die Seite übernimmt Regelanzahl und Kategorien aus der mitveröffentlichten `rules.js`.

Die Demo arbeitet wie die lokale Fassung vollständig im Browser. Für echte Konfigurationen empfiehlt sich trotzdem die heruntergeladene Fassung auf einem Rechner ohne Netzverbindung.

## Lizenz

Copyright (C) 2026 Christian Jelitte

Firewall-Validation Portable ist freie Software unter der **GNU General Public License, Version 3 oder später** (`GPL-3.0-or-later`). Der vollständige Lizenztext steht in [`LICENSE`](LICENSE).

**Zusätzliche Bedingung (Urhebernennung).** Nach Abschnitt 7(b) der GPLv3 gilt zusätzlich: Der Hinweis „Firewall-Validation Portable - Copyright (C) 2026 Christian Jelitte“ muss in allen Kopien und veränderten Fassungen erhalten bleiben, und zwar in den Dateiköpfen und im sichtbaren Lizenzhinweis am unteren Rand von `index.html` und `rules-editor.html`. Der verbindliche Wortlaut steht in [`NOTICE`](NOTICE).

Was das praktisch heißt:

- Du darfst das Werkzeug nutzen, weitergeben und verändern, auch gewerblich.
- Weitergaben und veränderte Fassungen bleiben unter der GPL-3.0-or-later und werden mit Quelltext weitergegeben.
- Der Urheberhinweis bleibt erhalten; veränderte Fassungen werden als verändert gekennzeichnet (Abschnitt 5(a) der GPL).
- Der Regel-Editor schreibt den Lizenzkopf beim Speichern einer neuen `rules.js` automatisch mit, und `meta.copyright` bleibt auch im JSON-Export erhalten.

Die Projektseite verwendet die Schrift Atkinson Hyperlegible unter der SIL Open Font License 1.1 (`site/fonts/OFL-*.txt`).

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version. This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details. Additional term under section 7(b): see [`NOTICE`](NOTICE).
