// Firewall-Validation Portable - Regelkatalog
// Copyright (C) 2026 Christian Jelitte <christian.jelitte@gmx-topmail.de>
// SPDX-License-Identifier: GPL-3.0-or-later
// Zusaetzliche Bedingung nach GPLv3 Abschnitt 7(b) (Urhebernennung): siehe Datei NOTICE.
window.RULES_DATA = {
  "meta": {
    "catalog": "OPNsense Security Baseline",
    "version": "1.2.0",
    "description": "Quantifiziertes Pruefschema fuer OPNsense-Konfigurationen (config.xml). Jede Regel besitzt einen Schweregrad und ein Gewicht; daraus berechnet die Engine einen normierten Posture-Score (0-100) und eine Note (A-F).",
    "copyright": "Copyright (C) 2026 Christian Jelitte",
    "license": "GPL-3.0-or-later, zusaetzliche Bedingung nach GPLv3 Abschnitt 7(b): Urhebernennung erhalten (siehe NOTICE)",
    "severity_weights": {
      "critical": 10,
      "high": 6,
      "medium": 3,
      "low": 1,
      "info": 0
    },
    "wan_interfaces": [
      "wan"
    ],
    "scoring": {
      "penalty_fail": 1.0,
      "penalty_warn": 0.5,
      "penalty_pass": 0.0,
      "note": "Penalty = Gewicht * Faktor. NA und MANUAL gehen NICHT in den Nenner ein. posture = round(100 * (1 - penalty_summe / max_moegliche_penalty)). Grade: A>=90, B>=80, C>=70, D>=60, sonst F."
    },
    "status_legend": {
      "PASS": "Kontrolle erfuellt",
      "FAIL": "Schwachstelle vorhanden",
      "WARN": "Bedingtes Risiko / Pruefung empfohlen",
      "NA": "Funktion nicht vorhanden / nicht zutreffend",
      "MANUAL": "Erfordert manuelle oder Live-Pruefung (nicht aus der Config bewertbar)"
    },
    "changelog": [
      {
        "version": "1.1.0",
        "date": "2026-09-29",
        "note": "Parameter werden von engine.js ausgewertet: meta.wan_interfaces (neu), meta.scoring (Strafpunktfaktoren), params von NAT-MGMT-EXPOSED, SVC-SNMP-PUBLIC und FW-ANY-ANY. Werte unveraendert, Bewertung identisch zu 1.0.0."
      },
      {
        "version": "1.2.0",
        "date": "2026-09-29",
        "note": "Pruefungen als Daten: 28 Regeln mit Pruefdefinition im Feld 'check', 4 als Baustein. Neu: FW-SHADOWED-BLOCK, FW-SHADOWED-PASS (Regel-Reihenfolge). Korrektur SVC-DNS-OPENRESOLVER: Interface-Liste mit mehreren Kommas wird vollstaendig ausgewertet.",
        "added": [
          "FW-SHADOWED-BLOCK",
          "FW-SHADOWED-PASS"
        ]
      }
    ]
  },
  "rules": [
    {
      "id": "MGMT-WEBGUI-WAN",
      "title": "WebGUI vom WAN-Interface erreichbar",
      "category": "Management-Ebene",
      "severity": "critical",
      "rationale": "Ist das Web-Interface direkt aus dem Internet erreichbar, wird das gesamte Geraet zur exponierten Angriffsflaeche (Brute-Force, CVE-Ausnutzung). Management gehoert ins LAN/Management-VLAN oder hinter ein VPN.",
      "remediation": "WebGUI nur an interne Interfaces binden (System > Settings > Administration > Listen Interfaces) und keine WAN-Pass-Regel auf den GUI-Port anlegen. Zugriff ueber VPN statt direkter WAN-Freigabe.",
      "references": [
        "OPNsense Hardening Guide: Secure access"
      ],
      "check": {
        "typ": "baustein",
        "name": "MGMT-WEBGUI-WAN"
      }
    },
    {
      "id": "MGMT-WEBGUI-HTTP",
      "title": "WebGUI ohne HTTPS (Klartext)",
      "category": "Management-Ebene",
      "severity": "high",
      "rationale": "HTTP uebertraegt Anmeldedaten und Sessions im Klartext und ermoeglicht Session-Hijacking sowie MITM.",
      "remediation": "Protokoll auf HTTPS umstellen und ein gueltiges Zertifikat hinterlegen.",
      "check": {
        "werte": {
          "protokoll": {
            "pfad": "system/webgui/protocol",
            "standard": "https",
            "klein": true
          }
        },
        "ergebnis": [
          {
            "wenn": {
              "protokoll": "http"
            },
            "status": "FAIL",
            "befund": "WebGUI-Protokoll ist HTTP (Klartext)."
          },
          {
            "status": "PASS",
            "notiz": "WebGUI nutzt {protokoll}."
          }
        ]
      }
    },
    {
      "id": "MGMT-SSH-WAN",
      "title": "SSH-Dienst auf WAN-Interface gebunden oder per WAN-Regel erreichbar",
      "category": "Management-Ebene",
      "severity": "high",
      "rationale": "Offenes SSH aus dem Internet ist Dauerziel von Brute-Force- und Credential-Stuffing-Angriffen.",
      "remediation": "SSH ausschliesslich an interne Interfaces binden, Zugriff ueber VPN. Falls unvermeidbar: Quelle hart einschraenken, Key-only, Port-Knocking/IDS.",
      "check": {
        "typ": "baustein",
        "name": "MGMT-SSH-WAN"
      }
    },
    {
      "id": "MGMT-SSH-ROOT",
      "title": "SSH Root-Login erlaubt",
      "category": "Management-Ebene",
      "severity": "medium",
      "rationale": "Direkter Root-Login entfernt die Nachvollziehbarkeit (kein Benutzerkontext) und macht das hoechstprivilegierte Konto direkt angreifbar.",
      "remediation": "permitRootLogin deaktivieren; benannte Admin-Konten mit sudo/Privilegien verwenden.",
      "check": {
        "werte": {
          "root_login": {
            "pfad": "system/ssh/permitrootlogin",
            "standard": "0"
          }
        },
        "ergebnis": [
          {
            "wenn": {
              "ssh_aktiv": false
            },
            "status": "NA",
            "notiz": "SSH nicht aktiviert."
          },
          {
            "wenn": {
              "plattform": "pfsense"
            },
            "status": "NA",
            "notiz": "pfSense ohne permitRootLogin-Schalter."
          },
          {
            "wenn": {
              "root_login": "1"
            },
            "status": "FAIL",
            "befund": "SSH permitRootLogin aktiviert."
          },
          {
            "status": "PASS"
          }
        ]
      }
    },
    {
      "id": "MGMT-SSH-PWAUTH",
      "title": "SSH Passwort-Authentifizierung aktiv",
      "category": "Management-Ebene",
      "severity": "medium",
      "rationale": "Passwort-Login ermoeglicht Brute-Force. Public-Key-Authentifizierung ist deutlich robuster.",
      "remediation": "Auf 'Public Key Only' umstellen und allen Admins SSH-Keys hinterlegen.",
      "check": {
        "werte": {
          "passwort_login": {
            "pfad": "system/ssh/passwordauth",
            "standard": "0"
          }
        },
        "ergebnis": [
          {
            "wenn": {
              "ssh_aktiv": false
            },
            "status": "NA",
            "notiz": "SSH nicht aktiviert."
          },
          {
            "wenn": {
              "plattform": "pfsense",
              "eingeschaltet": "system/ssh/sshdkeyonly"
            },
            "status": "PASS",
            "notiz": "pfSense: Public-Key-only aktiv."
          },
          {
            "wenn": {
              "plattform": "pfsense"
            },
            "status": "WARN",
            "befund": "pfSense: SSH-Passwort-Login erlaubt. Public-Key-only empfohlen."
          },
          {
            "wenn": {
              "passwort_login": "1"
            },
            "status": "FAIL",
            "befund": "SSH Passwort-Authentifizierung aktiviert."
          },
          {
            "status": "PASS"
          }
        ]
      }
    },
    {
      "id": "MGMT-MFA",
      "title": "Keine MFA/OTP fuer privilegierte Benutzer",
      "category": "Management-Ebene",
      "severity": "medium",
      "rationale": "Ohne zweiten Faktor genuegt ein kompromittiertes Passwort fuer vollen Admin-Zugriff.",
      "remediation": "TOTP-Seed je Admin setzen und MFA fuer GUI-Login erzwingen (System > Access > Servers / Local + TOTP).",
      "check": {
        "quelle": "benutzer",
        "wo": {
          "admin": true,
          "aktiv": true,
          "otp": false
        },
        "vorlage": "{name} (uid={uid})",
        "ergebnis": [
          {
            "wenn": {
              "plattform": "pfsense"
            },
            "status": "NA",
            "notiz": "pfSense CE ohne native GUI-MFA."
          },
          {
            "wenn": "treffer",
            "status": "FAIL",
            "befund": "Privilegierte Konten ohne OTP/MFA: {liste}."
          },
          {
            "status": "PASS"
          }
        ]
      }
    },
    {
      "id": "MGMT-ROOT-ACCOUNT",
      "title": "root-Konto aktiv als primaerer Admin-Zugang",
      "category": "Management-Ebene",
      "severity": "low",
      "rationale": "Geteilte Nutzung des root-Kontos verhindert individuelle Zurechenbarkeit und erschwert Rotation.",
      "remediation": "Benannte Admin-Konten anlegen, root nur als Notfallzugang fuehren, Standardpasswort sicher aendern.",
      "check": {
        "typ": "baustein",
        "name": "MGMT-ROOT-ACCOUNT"
      }
    },
    {
      "id": "MGMT-CONSOLE",
      "title": "Konsolenmenue nicht geschuetzt",
      "category": "Management-Ebene",
      "severity": "low",
      "rationale": "Ein ungeschuetztes serielles/physisches Konsolenmenue erlaubt Reset und Re-Konfiguration bei physischem Zugriff.",
      "remediation": "Konsolenmenue passwortschuetzen oder deaktivieren (System > Settings > Administration).",
      "check": {
        "ergebnis": [
          {
            "wenn": {
              "oder": [
                {
                  "eingeschaltet": "system/disableconsolemenu"
                },
                {
                  "eingeschaltet": "system/passwordprotect"
                }
              ]
            },
            "status": "PASS",
            "notiz": "Konsolenmenue geschuetzt/deaktiviert."
          },
          {
            "status": "WARN",
            "befund": "Konsolenmenue ungeschuetzt."
          }
        ]
      }
    },
    {
      "id": "FW-ANY-ANY",
      "title": "Pass-Regel mit Quelle ANY und Ziel ANY",
      "category": "Firewall-Regeln",
      "severity": "medium",
      "rationale": "Allow-any/any-Regeln heben das Least-Privilege-Prinzip auf. Auf WAN katastrophal; intern erlauben sie ungehinderte laterale Bewegung und C2/Exfiltration kompromittierter Hosts.",
      "remediation": "Regeln auf benoetigte Quellen/Ziele/Ports einschraenken. Troubleshooting-'allow any' nach Gebrauch entfernen.",
      "params": {
        "wan_zone_severity": "high"
      },
      "check": {
        "quelle": "filterregeln",
        "wo": {
          "aktiv": true,
          "aktion": "pass",
          "quelle_any": true,
          "ziel_any": true,
          "protokoll": [
            "any",
            "ip"
          ]
        },
        "vorlage": "#{nr} [{interface}] any->any - '{descr}'",
        "sortierung": {
          "zuerst": {
            "ist_wan": true
          }
        },
        "ergebnis": [
          {
            "wenn": {
              "treffer_mit": {
                "ist_wan": true
              }
            },
            "status": "FAIL",
            "schweregrad": "@param:wan_zone_severity",
            "befunde": "je_treffer"
          },
          {
            "wenn": "treffer",
            "status": "WARN",
            "befunde": "je_treffer",
            "notiz": "Interne any->any-Regeln. Bewusst pruefen."
          },
          {
            "status": "PASS"
          }
        ]
      }
    },
    {
      "id": "FW-WAN-EXPOSURE",
      "title": "WAN-Pass-Regel exponiert internen Dienst oder die Firewall selbst",
      "category": "Firewall-Regeln",
      "severity": "high",
      "rationale": "Jede eingehende Pass-Regel auf WAN oeffnet einen Dienst zum Internet. Mit Quelle ANY ist die Exposition vollstaendig.",
      "remediation": "Eingehende WAN-Regeln auf das Notwendige reduzieren, Quelle so eng wie moeglich fassen, sensible Dienste nicht exponieren.",
      "check": {
        "quelle": "filterregeln",
        "wo": {
          "aktiv": true,
          "aktion": "pass",
          "ist_wan": true,
          "richtung": "in"
        },
        "vorlage": "#{nr} WAN pass {protokoll} {quelle_anzeige} -> {ziel_text}{?quelle_any= [Quelle ANY]} - '{descr}'",
        "ergebnis": [
          {
            "wenn": "treffer",
            "status": "FAIL",
            "schweregrad": "high",
            "befunde": "je_treffer",
            "notiz": "Vom Internet erreichbarer Dienst."
          },
          {
            "status": "PASS",
            "notiz": "Keine WAN-Pass-Regeln."
          }
        ]
      }
    },
    {
      "id": "FW-BLOCKPRIV",
      "title": "'Block private networks' auf WAN deaktiviert",
      "category": "Firewall-Regeln",
      "severity": "medium",
      "rationale": "Ohne diesen Schutz werden gespoofte Pakete mit RFC1918-Quelladressen am WAN nicht verworfen.",
      "remediation": "Interfaces > [WAN] > 'Block private networks' aktivieren (sofern WAN nicht in einem privaten Upstream-Netz liegt).",
      "check": {
        "quelle": "wan_interfaces",
        "wo": {
          "block_private": false
        },
        "vorlage": "{name}",
        "ergebnis": [
          {
            "wenn": "treffer",
            "status": "FAIL",
            "befund": "'Block private networks' fehlt auf: {liste}."
          },
          {
            "status": "PASS"
          }
        ]
      }
    },
    {
      "id": "FW-BLOCKBOGON",
      "title": "'Block bogon networks' auf WAN deaktiviert",
      "category": "Firewall-Regeln",
      "severity": "low",
      "rationale": "Bogon-Filter verwirft Pakete aus nicht zugewiesenen/reservierten Adressbereichen.",
      "remediation": "Interfaces > [WAN] > 'Block bogon networks' aktivieren.",
      "check": {
        "quelle": "wan_interfaces",
        "wo": {
          "block_bogons": false
        },
        "vorlage": "{name}",
        "ergebnis": [
          {
            "wenn": "treffer",
            "status": "FAIL",
            "befund": "'Block bogon networks' fehlt auf: {liste}."
          },
          {
            "status": "PASS"
          }
        ]
      }
    },
    {
      "id": "FW-HOST-CIDR",
      "title": "Regel mit unplausibler Netzmaske (Einzelhost mit Subnetz-Maske)",
      "category": "Firewall-Regeln",
      "severity": "low",
      "rationale": "Eine Host-IP mit /24 (z.B. 192.168.0.38/24) oeffnet ungewollt das ganze Subnetz statt nur des Hosts - haeufiger Tippfehler mit Sicherheitsfolge.",
      "remediation": "Beabsichtigte Maske pruefen: Einzelhost als /32 angeben.",
      "check": {
        "typ": "baustein",
        "name": "FW-HOST-CIDR"
      }
    },
    {
      "id": "FW-DISABLED-RULES",
      "title": "Deaktivierte Firewall-Regeln vorhanden (Hygiene)",
      "category": "Firewall-Regeln",
      "severity": "info",
      "rationale": "Verwaiste deaktivierte Regeln erschweren das Review und koennen versehentlich reaktiviert werden.",
      "remediation": "Nicht mehr benoetigte Regeln entfernen oder dokumentieren.",
      "check": {
        "quelle": "filterregeln",
        "wo": {
          "aktiv": false
        },
        "vorlage": "#{nr} [{interface}] '{descr}'",
        "ergebnis": [
          {
            "wenn": "treffer",
            "status": "WARN",
            "befunde": "je_treffer",
            "notiz": "Deaktivierte Regeln - Hygiene."
          },
          {
            "status": "PASS"
          }
        ]
      }
    },
    {
      "id": "FW-BLOCK-NOLOG",
      "title": "Block/Reject-Regeln ohne Logging",
      "category": "Firewall-Regeln",
      "severity": "low",
      "rationale": "Ohne Logging auf Block-Regeln fehlt die Sichtbarkeit fuer Angriffsversuche und Fehlersuche.",
      "remediation": "Logging fuer relevante Block-/Default-Deny-Regeln aktivieren.",
      "check": {
        "quelle": "filterregeln",
        "wo": {
          "aktiv": true,
          "aktion": [
            "block",
            "reject"
          ],
          "log": false
        },
        "vorlage": "#{nr} [{interface}] '{descr}'",
        "ergebnis": [
          {
            "wenn": "treffer",
            "status": "WARN",
            "befunde": "je_treffer",
            "notiz": "Block/Reject ohne Logging."
          },
          {
            "status": "PASS"
          }
        ]
      }
    },
    {
      "id": "FW-SHADOWED-BLOCK",
      "title": "Block-Regel wird durch vorangehende Auffang-Regel nie erreicht",
      "category": "Firewall-Regeln",
      "severity": "medium",
      "rationale": "Regeln werden je Interface und Richtung von oben nach unten ausgewertet, die erste passende gewinnt. Steht vor einer Block-Regel eine Regel, die jeden Verkehr erfasst (Quelle any, Ziel any, Protokoll any, ohne Zeitplan oder Tag), greift die Block-Regel nie. Der Schutz besteht dann nur scheinbar.",
      "remediation": "Reihenfolge korrigieren: Block-Regeln vor die allgemeine Freigabe verschieben oder die Auffang-Regel auf die tatsaechlich benoetigten Quellen und Ziele einschraenken.",
      "references": [
        "OPNsense-Dokumentation: Firewall Rules - Processing order",
        "pfSense-Dokumentation: Rule Methodology - First match"
      ],
      "check": {
        "typ": "reihenfolge",
        "quelle": "filterregeln",
        "gleich": [
          "interface",
          "richtung"
        ],
        "umfasst": [
          "ip_version"
        ],
        "vorher": {
          "aktiv": true,
          "floating": false,
          "zusatzbedingung": false,
          "protokoll": "any",
          "quelle_any": true,
          "quelle_negiert": false,
          "ziel_any": true,
          "ziel_negiert": false,
          "ziel_port": ""
        },
        "nachher": {
          "aktiv": true,
          "floating": false,
          "aktion": [
            "block",
            "reject"
          ]
        },
        "vorlage": "#{nachher.nr} [{interface}/{richtung}] '{nachher.descr}' wird nie erreicht - verdeckt durch #{vorher.nr} {vorher.aktion} '{vorher.descr}'",
        "ergebnis": [
          {
            "wenn": "treffer",
            "status": "WARN",
            "befunde": "je_treffer",
            "notiz": "Block-Regel wirkt nicht: eine vorangehende Regel faengt den gesamten Verkehr ab."
          },
          {
            "status": "PASS"
          }
        ]
      }
    },
    {
      "id": "FW-SHADOWED-PASS",
      "title": "Freigabe-Regel wird durch vorangehende Auffang-Regel nie erreicht",
      "category": "Firewall-Regeln",
      "severity": "low",
      "rationale": "Steht eine Regel, die jeden Verkehr erfasst, vor einer Freigabe, wird die Freigabe nie ausgewertet. Typisch ist eine 'Block all'-Regel am Anfang statt am Ende. Das ist vor allem ein Funktionsfehler, macht das Regelwerk aber auch schwer nachvollziehbar.",
      "remediation": "Allgemeine Block-Regel ans Ende des Interfaces verschieben (oder ganz entfernen, da beide Systeme am Ende ohnehin implizit blockieren) und die Freigaben davor anordnen.",
      "references": [
        "OPNsense-Dokumentation: Firewall Rules - Processing order",
        "pfSense-Dokumentation: Rule Methodology - First match"
      ],
      "check": {
        "typ": "reihenfolge",
        "quelle": "filterregeln",
        "gleich": [
          "interface",
          "richtung"
        ],
        "umfasst": [
          "ip_version"
        ],
        "vorher": {
          "aktiv": true,
          "floating": false,
          "zusatzbedingung": false,
          "protokoll": "any",
          "quelle_any": true,
          "quelle_negiert": false,
          "ziel_any": true,
          "ziel_negiert": false,
          "ziel_port": ""
        },
        "nachher": {
          "aktiv": true,
          "floating": false,
          "aktion": "pass"
        },
        "vorlage": "#{nachher.nr} [{interface}/{richtung}] '{nachher.descr}' wird nie erreicht - verdeckt durch #{vorher.nr} {vorher.aktion} '{vorher.descr}'",
        "ergebnis": [
          {
            "wenn": "treffer",
            "status": "WARN",
            "befunde": "je_treffer",
            "notiz": "Freigabe wirkt nicht: eine vorangehende Regel faengt den gesamten Verkehr ab."
          },
          {
            "status": "PASS"
          }
        ]
      }
    },
    {
      "id": "NAT-MGMT-EXPOSED",
      "title": "Port-Weiterleitung exponiert sensiblen/Management-Port vom WAN",
      "category": "NAT / Port-Forwarding",
      "severity": "critical",
      "rationale": "Weiterleitungen von WAN auf Ports wie SSH(22), RDP(3389), SMB(445), DB(3306/5432/1433/27017/6379), VNC(5900) oder Admin-Panels stellen interne Verwaltungsdienste ins Internet.",
      "remediation": "Solche Weiterleitungen entfernen oder ausschliesslich ueber VPN bereitstellen; falls noetig, Quelle hart auf bekannte IPs begrenzen.",
      "params": {
        "sensitive_ports": [
          22,
          23,
          135,
          139,
          445,
          1433,
          3306,
          3389,
          5432,
          5900,
          5901,
          6379,
          9200,
          11211,
          27017
        ],
        "sensitive_port_aliases_hint": "Auch Port-Aliase werden aufgeloest und geprueft."
      },
      "check": {
        "quelle": "nat",
        "wo": {
          "und": [
            {
              "ist_wan": true
            },
            {
              "feld": "ports",
              "ports_schneiden": "@param:sensitive_ports"
            }
          ]
        },
        "vorlage": "WAN-Forward Port(s) {treffer_ports} -> {ziel} (Quelle: {quelle_anzeige}) - '{descr}'",
        "ergebnis": [
          {
            "wenn": {
              "treffer_mit": {
                "quelle_any": true
              }
            },
            "status": "FAIL",
            "schweregrad": "critical",
            "befunde": "je_treffer"
          },
          {
            "wenn": "treffer",
            "status": "FAIL",
            "schweregrad": "high",
            "befunde": "je_treffer"
          },
          {
            "status": "PASS"
          }
        ]
      }
    },
    {
      "id": "NAT-WAN-ANY-SRC",
      "title": "Port-Weiterleitung vom WAN mit Quelle ANY",
      "category": "NAT / Port-Forwarding",
      "severity": "medium",
      "rationale": "Eine ueber das Internet generell erreichbare Weiterleitung vergroessert die Angriffsflaeche; Quelle ANY erlaubt jedem den Zugriff.",
      "remediation": "Quelle einschraenken; nur bewusst oeffentliche Dienste (z.B. Web) generell erreichbar lassen.",
      "check": {
        "quelle": "nat",
        "wo": {
          "ist_wan": true,
          "quelle_any": true
        },
        "vorlage": "WAN-Forward Quelle ANY Port {ports|?} -> {ziel} - '{descr}'",
        "ergebnis": [
          {
            "wenn": "treffer",
            "status": "WARN",
            "befunde": "je_treffer",
            "notiz": "Quelle ANY bei oeffentlichen Diensten ok, sonst einschraenken."
          },
          {
            "status": "PASS"
          }
        ]
      }
    },
    {
      "id": "NAT-UPNP",
      "title": "UPnP / NAT-PMP aktiviert",
      "category": "NAT / Port-Forwarding",
      "severity": "high",
      "rationale": "UPnP erlaubt internen Geraeten (inkl. Malware/IoT), eigenstaendig WAN-Ports zu oeffnen und umgeht das Firewall-Regelwerk.",
      "remediation": "UPnP/NAT-PMP deaktivieren, sofern nicht zwingend erforderlich; sonst auf vertrauenswuerdige Geraete/ACLs begrenzen.",
      "check": {
        "ergebnis": [
          {
            "wenn": {
              "oder": [
                {
                  "eingeschaltet": "//miniupnpd/enable"
                },
                {
                  "eingeschaltet": "OPNsense/UPnP/upnp"
                },
                {
                  "eingeschaltet": "OPNsense/UPnP/enable"
                },
                {
                  "eingeschaltet": "installedpackages/miniupnpd/enable"
                },
                {
                  "eingeschaltet": "installedpackages/miniupnpd/iface_array"
                }
              ]
            },
            "status": "FAIL",
            "befund": "UPnP/NAT-PMP aktiviert."
          },
          {
            "wenn": {
              "nicht": {
                "oder": [
                  {
                    "existiert": "//miniupnpd"
                  },
                  {
                    "existiert": "OPNsense/UPnP"
                  },
                  {
                    "existiert": "installedpackages/miniupnpd"
                  }
                ]
              }
            },
            "status": "PASS",
            "notiz": "UPnP nicht konfiguriert."
          },
          {
            "status": "PASS",
            "notiz": "UPnP vorhanden, deaktiviert."
          }
        ]
      }
    },
    {
      "id": "NAT-1TO1",
      "title": "1:1-NAT konfiguriert (Review)",
      "category": "NAT / Port-Forwarding",
      "severity": "info",
      "rationale": "1:1-NAT bildet einen kompletten Host nach aussen ab; die Exposition haengt vollstaendig an den WAN-Regeln.",
      "remediation": "Zugehoerige WAN-Regeln auf Least-Privilege pruefen.",
      "check": {
        "xml": "nat/onetoone",
        "vorlage": "{external|?} <-> {source/address|?}",
        "ergebnis": [
          {
            "wenn": {
              "nicht": {
                "existiert": "nat"
              }
            },
            "status": "NA"
          },
          {
            "wenn": "treffer",
            "status": "WARN",
            "befunde": "je_treffer",
            "notiz": "1:1-NAT - WAN-Regeln pruefen."
          },
          {
            "status": "PASS"
          }
        ]
      }
    },
    {
      "id": "SVC-SNMP-PUBLIC",
      "title": "SNMP mit Standard-Community 'public'",
      "category": "Dienst-Exposition",
      "severity": "high",
      "rationale": "Die Community 'public' ist oeffentlich bekannt und gibt lesenden Zugriff auf detaillierte Systeminformationen frei; SNMP v1/v2c uebertraegt zudem unverschluesselt.",
      "remediation": "SNMP deaktivieren, falls ungenutzt. Sonst Community aendern, auf SNMPv3 (Auth+Priv) wechseln und Zugriff auf Management-Netz begrenzen.",
      "params": {
        "default_communities": [
          "public",
          "private"
        ]
      },
      "check": {
        "werte": {
          "community": {
            "pfad": "snmpd/rocommunity"
          }
        },
        "ergebnis": [
          {
            "wenn": {
              "nicht": {
                "existiert": "snmpd"
              }
            },
            "status": "NA",
            "notiz": "SNMP nicht konfiguriert."
          },
          {
            "wenn": {
              "und": [
                {
                  "feld": "community",
                  "ist_eine_von": "@param:default_communities"
                },
                {
                  "eingeschaltet": "snmpd/enable"
                }
              ]
            },
            "status": "FAIL",
            "schweregrad": "high",
            "befund": "SNMP aktiv mit Standard-Community '{community}'."
          },
          {
            "wenn": {
              "feld": "community",
              "ist_eine_von": "@param:default_communities"
            },
            "status": "WARN",
            "befund": "SNMP-Standard-Community '{community}' konfiguriert."
          },
          {
            "wenn": {
              "eingeschaltet": "snmpd/enable"
            },
            "status": "WARN",
            "befund": "SNMP aktiv. SNMPv3 pruefen."
          },
          {
            "status": "PASS",
            "notiz": "Keine Standard-Community."
          }
        ]
      }
    },
    {
      "id": "SVC-DNS-OPENRESOLVER",
      "title": "Unbound: ACL-Default 'allow' (potenzieller Open Resolver)",
      "category": "Dienst-Exposition",
      "severity": "medium",
      "rationale": "Erlaubt der Resolver per Default jede Quelle und ist er vom WAN erreichbar, wird er zum Open Resolver und fuer DNS-Amplification-DDoS missbraucht.",
      "remediation": "ACL-Default auf 'deny' setzen und nur interne Netze freigeben; sicherstellen, dass Port 53 nicht vom WAN erreichbar ist.",
      "check": {
        "werte": {
          "pf_interfaces": {
            "pfad": "unbound/active_interface",
            "klein": true
          },
          "acl_standard": {
            "pfad": "OPNsense/unboundplus/acls/default_action",
            "klein": true
          }
        },
        "ergebnis": [
          {
            "wenn": {
              "plattform": "pfsense",
              "nicht": {
                "eingeschaltet": "unbound/enable"
              }
            },
            "status": "NA",
            "notiz": "Unbound nicht aktiviert."
          },
          {
            "wenn": {
              "plattform": "pfsense",
              "oder": [
                {
                  "pf_interfaces": ""
                },
                {
                  "feld": "pf_interfaces",
                  "liste_enthaelt": [
                    "all",
                    "wan"
                  ]
                }
              ]
            },
            "status": "WARN",
            "befund": "Unbound lauscht auf '{pf_interfaces|alle}' - Open-Resolver-Risiko."
          },
          {
            "wenn": {
              "plattform": "pfsense"
            },
            "status": "PASS",
            "notiz": "Unbound auf: {pf_interfaces}."
          },
          {
            "wenn": {
              "nicht": {
                "existiert": "OPNsense/unboundplus"
              }
            },
            "status": "NA",
            "notiz": "Unbound nicht konfiguriert."
          },
          {
            "wenn": {
              "nicht": {
                "eingeschaltet": "OPNsense/unboundplus/general/enabled"
              }
            },
            "status": "NA",
            "notiz": "Unbound nicht aktiviert."
          },
          {
            "wenn": {
              "acl_standard": "allow"
            },
            "status": "WARN",
            "befund": "Unbound ACL-Default='allow'. Open-Resolver-Risiko."
          },
          {
            "status": "PASS",
            "notiz": "Unbound ACL-Default='{acl_standard|deny}'."
          }
        ]
      }
    },
    {
      "id": "SVC-NTP-OPEN",
      "title": "NTP ohne Zugriffsbeschraenkung",
      "category": "Dienst-Exposition",
      "severity": "low",
      "rationale": "Ein vom WAN erreichbarer NTP-Dienst kann fuer Amplification-Angriffe missbraucht werden.",
      "remediation": "NTP-Zugriff auf interne Netze beschraenken bzw. am WAN blockieren.",
      "check": {
        "quelle": "filterregeln",
        "wo": {
          "und": [
            {
              "aktiv": true,
              "aktion": "pass",
              "ist_wan": true
            },
            {
              "feld": "ziel_port",
              "port_ist": [
                "123"
              ]
            }
          ]
        },
        "ergebnis": [
          {
            "wenn": {
              "nicht": {
                "existiert": "ntpd"
              }
            },
            "status": "NA",
            "notiz": "NTP nicht konfiguriert."
          },
          {
            "wenn": "treffer",
            "status": "WARN",
            "befund": "NTP (UDP/123) per WAN erreichbar."
          },
          {
            "status": "PASS",
            "notiz": "Kein WAN-Zugriff auf NTP."
          }
        ]
      }
    },
    {
      "id": "SVC-IDS-DISABLED",
      "title": "IDS/IPS (Suricata) deaktiviert",
      "category": "Dienst-Exposition",
      "severity": "medium",
      "rationale": "Ohne aktives IDS/IPS fehlt eine zentrale Erkennungs-/Abwehrschicht. Fehlende mitigierende Kontrolle erhoeht das Restrisiko exponierter Dienste.",
      "remediation": "Suricata aktivieren, Regelsaetze pflegen und auf relevanten Interfaces betreiben.",
      "check": {
        "ergebnis": [
          {
            "wenn": {
              "plattform": "pfsense",
              "ids_paket": ""
            },
            "status": "NA",
            "notiz": "Kein IDS-Paket installiert."
          },
          {
            "wenn": {
              "plattform": "pfsense",
              "keine": {
                "quelle": "ids_instanzen",
                "wo": {
                  "aktiv": true
                }
              }
            },
            "status": "FAIL",
            "befund": "{ids_paket} installiert, aber inaktiv."
          },
          {
            "wenn": {
              "plattform": "pfsense"
            },
            "status": "PASS"
          },
          {
            "wenn": {
              "nicht": {
                "existiert": "OPNsense/IDS/general"
              }
            },
            "status": "NA",
            "notiz": "IDS nicht konfiguriert."
          },
          {
            "wenn": {
              "nicht": {
                "eingeschaltet": "OPNsense/IDS/general/enabled"
              }
            },
            "status": "FAIL",
            "befund": "IDS/IPS deaktiviert."
          },
          {
            "status": "PASS"
          }
        ]
      }
    },
    {
      "id": "SVC-IDS-NOIPS",
      "title": "IDS aktiv, aber IPS-Blockmodus aus (nur Erkennung)",
      "category": "Dienst-Exposition",
      "severity": "low",
      "rationale": "Im reinen Detection-Modus werden Angriffe erkannt, aber nicht blockiert.",
      "remediation": "IPS-Modus aktivieren (erfordert kompatible Netzwerkkarte/Konfiguration).",
      "check": {
        "ergebnis": [
          {
            "wenn": {
              "plattform": "pfsense",
              "ids_paket": ""
            },
            "status": "NA",
            "notiz": "Kein IDS-Paket."
          },
          {
            "wenn": {
              "plattform": "pfsense",
              "keine": {
                "quelle": "ids_instanzen",
                "wo": {
                  "aktiv": true
                }
              }
            },
            "status": "NA",
            "notiz": "IDS inaktiv."
          },
          {
            "wenn": {
              "plattform": "pfsense",
              "keine": {
                "quelle": "ids_instanzen",
                "wo": {
                  "aktiv": true,
                  "blockiert": true
                }
              }
            },
            "status": "WARN",
            "befund": "{ids_paket} nur Detection-Modus."
          },
          {
            "wenn": {
              "plattform": "pfsense"
            },
            "status": "PASS"
          },
          {
            "wenn": {
              "nicht": {
                "existiert": "OPNsense/IDS/general"
              }
            },
            "status": "NA",
            "notiz": "IDS nicht konfiguriert."
          },
          {
            "wenn": {
              "nicht": {
                "eingeschaltet": "OPNsense/IDS/general/enabled"
              }
            },
            "status": "NA",
            "notiz": "IDS deaktiviert."
          },
          {
            "wenn": {
              "nicht": {
                "eingeschaltet": "OPNsense/IDS/general/ips"
              }
            },
            "status": "WARN",
            "befund": "IDS nur Detection-Modus."
          },
          {
            "status": "PASS"
          }
        ]
      }
    },
    {
      "id": "VPN-IKEV1",
      "title": "IPsec IKEv1 / Aggressive Mode aktiv",
      "category": "VPN",
      "severity": "high",
      "rationale": "IKEv1 (insb. Aggressive Mode mit PSK) ist anfaellig fuer Offline-Brute-Force des PSK.",
      "remediation": "Auf IKEv2 mit starken Cipher-Suiten umstellen; Aggressive Mode vermeiden.",
      "check": {
        "abfragen": [
          {
            "xml": "ipsec/phase1",
            "wo": {
              "oder": [
                {
                  "iketype": "ikev1"
                },
                {
                  "mode": "aggressive"
                }
              ]
            },
            "vorlage": "IPsec Phase1 '{descr}' nutzt {iketype:klein|ikev1}/mode={mode:klein}."
          },
          {
            "xml": "OPNsense/Swanctl/Connections/Connection",
            "wo": {
              "version": [
                "1",
                "ikev1"
              ]
            },
            "vorlage": "Swanctl '{description}' nutzt IKEv1."
          }
        ],
        "ergebnis": [
          {
            "wenn": "treffer",
            "status": "FAIL",
            "befunde": "je_treffer"
          },
          {
            "wenn": "quellen_leer",
            "status": "NA",
            "notiz": "Kein IPsec konfiguriert."
          },
          {
            "status": "PASS",
            "notiz": "IPsec nutzt IKEv2."
          }
        ]
      }
    },
    {
      "id": "VPN-OVPN-CIPHER",
      "title": "OpenVPN ohne AEAD-Cipher / schwache Verschluesselung",
      "category": "VPN",
      "severity": "medium",
      "rationale": "Veraltete Cipher (z.B. ohne AES-GCM/CHACHA20) bieten geringeren Schutz; fehlende TLS-Crypt/Auth schwaecht die Kontrollkanal-Sicherheit.",
      "remediation": "AEAD-Cipher (AES-256-GCM) erzwingen und TLS-Crypt/Auth aktivieren.",
      "check": {
        "abfragen": [
          {
            "plattform": "pfsense",
            "xml": "openvpn/openvpn-server",
            "wo": {
              "nicht": {
                "oder": [
                  {
                    "feld": "data_ciphers",
                    "enthaelt_eins_von": [
                      "GCM",
                      "CHACHA20"
                    ]
                  },
                  {
                    "feld": "data_ciphers_fallback",
                    "enthaelt_eins_von": [
                      "GCM",
                      "CHACHA20"
                    ]
                  }
                ]
              }
            },
            "vorlage": "OpenVPN-Server '{description}' ohne AEAD-Cipher."
          },
          {
            "plattform": "opnsense",
            "xml": "OPNsense/OpenVPN/Instances/*",
            "wo": {
              "und": [
                {
                  "feld": "data-ciphers",
                  "leer": false
                },
                {
                  "nicht": {
                    "feld": "data-ciphers",
                    "enthaelt_eins_von": [
                      "GCM",
                      "CHACHA20"
                    ]
                  }
                }
              ]
            },
            "vorlage": "OpenVPN-Instance '{description}' ohne AEAD-Cipher."
          }
        ],
        "ergebnis": [
          {
            "wenn": "quellen_leer",
            "status": "NA",
            "notiz": "Keine OpenVPN-Serverinstanz."
          },
          {
            "wenn": "treffer",
            "status": "WARN",
            "befunde": "je_treffer"
          },
          {
            "status": "PASS"
          }
        ]
      }
    },
    {
      "id": "VPN-FULL-ACCESS",
      "title": "VPN-Peer-Regel mit uneingeschraenktem Zugriff (ANY)",
      "category": "VPN",
      "severity": "medium",
      "rationale": "Pass-Regeln, die VPN-Peers ANY-Zugriff in interne Netze geben, heben die Segmentierung auf.",
      "remediation": "VPN-Zugriff auf benoetigte Zielsysteme/Ports einschraenken.",
      "check": {
        "quelle": "filterregeln",
        "wo": {
          "aktiv": true,
          "aktion": "pass",
          "ist_vpn": true,
          "ziel_any": true
        },
        "vorlage": "#{nr} [{interface}] {quelle_anzeige} -> ANY - '{descr}'",
        "ergebnis": [
          {
            "wenn": {
              "keine": {
                "quelle": "interfaces",
                "wo": {
                  "ist_vpn": true
                }
              }
            },
            "status": "NA",
            "notiz": "Keine VPN-Interfaces erkannt."
          },
          {
            "wenn": "treffer",
            "status": "WARN",
            "befunde": "je_treffer",
            "notiz": "Ziel ANY kann Full-Tunnel oder zu breiter Zugriff sein."
          },
          {
            "status": "PASS"
          }
        ]
      }
    },
    {
      "id": "VPN-WG-PRESENT",
      "title": "WireGuard aktiv (Allowed-IPs pruefen)",
      "category": "VPN",
      "severity": "info",
      "rationale": "WireGuard-Peers mit weiten Allowed-IPs koennen breiten internen Zugriff erhalten.",
      "remediation": "Allowed-IPs der Peers und zugehoerige Interface-Regeln auf Least-Privilege pruefen.",
      "check": {
        "ergebnis": [
          {
            "wenn": {
              "wg_vorhanden": false
            },
            "status": "NA"
          },
          {
            "wenn": {
              "feld": "wg_gesamt",
              "groesser": 0
            },
            "status": "WARN",
            "befund": "WireGuard konfiguriert (Tunnels: {wg_tunnel}, Peers: {wg_peers}). Allowed-IPs pruefen."
          },
          {
            "status": "NA",
            "notiz": "WireGuard ohne Tunnel/Peers."
          }
        ]
      }
    },
    {
      "id": "SYS-FIRMWARE",
      "title": "Firmware-Aktualitaet pruefen (Live-Check noetig)",
      "category": "System-Haertung",
      "severity": "info",
      "rationale": "Eine veraltete OPNsense kann bekannte CVEs aufweisen. Der Patch-Stand ist nicht zuverlaessig aus der config.xml ableitbar.",
      "remediation": "Auf der Appliance 'opnsense-update -c' bzw. Firmware-Status pruefen und Security-Announcements verfolgen.",
      "check": {
        "werte": {
          "version": {
            "pfad": [
              "version",
              "system/version"
            ]
          },
          "plugins": {
            "pfad": "system/firmware/plugins"
          }
        },
        "ergebnis": [
          {
            "wenn": {
              "plattform": "pfsense"
            },
            "status": "MANUAL",
            "befund": "pfSense Config-Version: {version|(unbekannt)}.",
            "notiz": "Firmware-Stand auf Appliance pruefen."
          },
          {
            "status": "MANUAL",
            "befund": "Installierte Plugins: {plugins|(keine)}.",
            "notiz": "Patch-Stand nicht aus config.xml ableitbar."
          }
        ]
      }
    },
    {
      "id": "SYS-SYSLOG-REMOTE",
      "title": "Kein Remote-Syslog / Log-Forwarding konfiguriert",
      "category": "System-Haertung",
      "severity": "low",
      "rationale": "Ohne externes Logging gehen Spuren bei Kompromittierung/Reset verloren; forensische Auswertung wird erschwert.",
      "remediation": "Remote-Syslog-Ziel (zentrales SIEM/Log-Host) konfigurieren.",
      "check": {
        "werte": {
          "ziele": {
            "anzahl": "OPNsense/Syslog/destinations/destination"
          },
          "server": {
            "verbinde": [
              "syslog/remoteserver",
              "syslog/remoteserver2",
              "syslog/remoteserver3"
            ],
            "trenner": ", "
          }
        },
        "ergebnis": [
          {
            "wenn": {
              "feld": "ziele",
              "groesser": 0
            },
            "status": "PASS",
            "notiz": "Remote-Syslog: {ziele} Ziel(e)."
          },
          {
            "wenn": {
              "feld": "server",
              "leer": false
            },
            "status": "PASS",
            "notiz": "Remote-Syslog: {server}."
          },
          {
            "wenn": {
              "eingeschaltet": "syslog/enableremotelogging"
            },
            "status": "PASS",
            "notiz": "Remote-Syslog: aktiv."
          },
          {
            "status": "WARN",
            "befund": "Kein Remote-Syslog konfiguriert."
          }
        ]
      }
    },
    {
      "id": "SYS-API-KEYS",
      "title": "API-Schluessel auf Benutzerkonten vorhanden",
      "category": "System-Haertung",
      "severity": "info",
      "rationale": "API-Keys mit weitreichenden Rechten sind ein attraktives Ziel; Speicherung und Rechteumfang sind zu pruefen.",
      "remediation": "API-Keys auf das Noetigste begrenzen, sicher speichern und rotieren.",
      "check": {
        "quelle": "benutzer",
        "wo": {
          "feld": "api_schluessel",
          "groesser": 0
        },
        "vorlage": "{name|?}",
        "ergebnis": [
          {
            "wenn": "treffer",
            "status": "WARN",
            "befund": "API-Schluessel auf Konten: {liste}."
          },
          {
            "status": "PASS",
            "notiz": "Keine API-Schluessel."
          }
        ]
      }
    },
    {
      "id": "SYS-BACKUP-SECRETS",
      "title": "config.xml enthaelt Secrets (Hinweis)",
      "category": "System-Haertung",
      "severity": "info",
      "rationale": "Die Konfiguration enthaelt Passwort-Hashes, VPN-Keys und PSKs. Unverschluesselte Backups sind ein Einfallstor.",
      "remediation": "Config-Backups verschluesseln und Zugriff streng begrenzen.",
      "check": {
        "ergebnis": [
          {
            "status": "MANUAL",
            "befund": "config.xml enthaelt Passwort-Hashes, Schluessel und ggf. PSKs.",
            "notiz": "Backups verschluesseln und Zugriff begrenzen."
          }
        ]
      }
    }
  ]
};
