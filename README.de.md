<!-- English source SHA-256: d0280e2c890d3f18780b8c0cd0965c2d6b1ebfe943eafba0ebdc2c69aa09e771 -->
<h1 align="center">sibuna</h1>
<p align="center">Webschutz mit Proof of Work im Browser und optionaler Konsole.</p>
<p align="center">
  <a href="#features">Funktionen</a> ·
  <a href="#quickstart">Schnellstart</a> ·
  <a href="#console">Konsole</a> ·
  <a href="#how-it-works">Funktionsweise</a> ·
  <a href="#documentation">Dokumentation</a>
</p>

<!-- language-navigation -->
<p align="center">
  <a href="README.md">English</a> · <a href="README.zh-CN.md">简体中文</a> ·
  <a href="README.ko.md">한국어</a> · <a href="README.ja.md">日本語</a> ·
  <a href="README.es.md">Español</a> · <a href="README.de.md">Deutsch</a> ·
  <a href="README.hi.md">हिन्दी</a> · <a href="README.ar.md">العربية</a>
</p>

**Sibuna hilft, Websites und APIs vor unerwünschtem Bot-Verkehr zu schützen.** Es kann
Anfragen zur Anwendung weiterleiten oder neben einem vorhandenen Proxy wie Caddy, nginx
oder Traefik arbeiten.

Anfragen zu senden ist oft billig. Ihre Verarbeitung kann die Anwendung mehr Arbeit
kosten. Sibuna verlangt vor dem Zugang ein gelöstes Rätsel. Es soll mehr Rechenarbeit
zum Erzeugen als zum Prüfen des Nachweises erfordern. Automatisierte Clients tragen
so einen größeren Anteil der Zugangskosten.

Rechnen braucht auch Energie. Die Menge hängt von Hardware und Einstellungen ab.
Proof of Work fügt Zulassungskosten hinzu. Es belegt keine Menschlichkeit und stoppt
nicht jeden Angriff. Eine signierte Sitzung erlaubt spätere Anfragen ohne neues Rätsel
pro Anfrage. Regeln und lokale Ratenlimits steuern, was diese Clients danach anfordern dürfen.

<a id="features"></a>

## Funktionen

- **Ein ausführbares Programm:** Engine, eingebetteter Speicher, Browser-Löser und Konsolen-Assets.
- **Native Pakete:** Linux, macOS und Windows. Der Browser-Löser nutzt WebAssembly.
- **Browser-Challenges:** einstellbares Hashcash oder sequenzielle Arbeit, danach signierte Sitzung.
- **Zugangsrichtlinien:** erlauben, herausfordern oder ablehnen nach Adresse, Pfad, Headern und User-Agent.
- **Anwendungsprüfung:** eingebaute Prüfungen für SQL-Injection, XSS und Pfadtraversierung.
- **Optionales OWASP CRS:** signierte Updates, Audit und Enforce, private Tests und Rücknahme.
- **Lokale Ratenlimits:** Bursts und Dauerverkehr begrenzen, optional auch je Regel.
- **Betreiberkonsole:** Verkehr, Länderstichproben, aufgezeichnete Vorfälle und Richtlinienbearbeitung.
- **Cluster:** ein gesonderter Quellbuild repliziert Richtlinien und Reputation über Zaxonlite.

<a id="quickstart"></a>

## Schnellstart

[Lade ein Release](https://github.com/insanai/sibuna/releases/tag/v0.3.5) für deine Plattform herunter. Das Standardpaket unterstützt
Speicher und Konsole. Die Konsole startet mit `--console`.

| Plattform | Paket | Voraussetzungen |
| --- | --- | --- |
| Linux x86-64 | `sibuna-linux-amd64.tar.gz` | Linux 5.10 oder neuer; statisch gebundenes musl |
| Linux ARM64 | `sibuna-linux-arm64.tar.gz` | Linux 5.10 oder neuer; statisch gebundenes musl |
| macOS Apple Silicon | `sibuna-macos-arm64.tar.gz` | macOS 15 oder neuer |
| macOS Intel | `sibuna-macos-amd64.tar.gz` | macOS 15 oder neuer |
| Windows x86-64 | `sibuna-windows-amd64.zip` | Windows 10 / Server 2019 oder neuer; natives `sibuna.exe` |
| FreeBSD x86-64 | `sibuna-0.3.5-freebsd-15.1-amd64.pkg` | FreeBSD 15.1; CLI-Paket |
| OpenBSD x86-64 | `sibuna-0.3.5-openbsd-7.9-amd64.tgz` | OpenBSD 7.9; CLI-Paket |

macOS-Builds sind unsigniert. Jedes Paket enthält Lizenzen, Quellverweise und ein
Build-Manifest. Prüfe das Archiv vor der Nutzung gegen `SHA256SUMS`.

Debian/RPM-Pakete unterstützen Linux x86-64 und ARM64; Arch `sibuna-bin` unterstützt x86-64. Pakete für FreeBSD 15.1 und OpenBSD 7.9 unterstützen x86-64 und installieren die CLI. Linux-Pakete enthalten einen optionalen, deaktivierten systemd-Dienst. BSD-Pakete erzeugen weder Dienst noch Konto oder Zustand. Dies sind Upstream-Downloads; die Aufnahme in Community-Archive ist ein separates Verfahren. Der Release enthält auch eine Homebrew-Quellformel und ein Helm-Chart. Die [Paket-Betriebsanleitung](https://insanai.github.io/sibuna/de/book/operations.html) beschreibt Installation, Verifikation, privaten Zustand, Updates und Kubernetes.

Für Linux x86-64 mit einer Anwendung auf Port 3000:

```sh
curl -fLO https://github.com/insanai/sibuna/releases/download/v0.3.5/sibuna-linux-amd64.tar.gz
curl -fLO https://github.com/insanai/sibuna/releases/download/v0.3.5/SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS
tar -xzf sibuna-linux-amd64.tar.gz
(umask 077; openssl rand -hex 32 > sibuna.seed)
./sibuna --host 127.0.0.1 --port 8080 --upstream-port 3000 --secret-file ./sibuna.seed
```

Öffne `http://127.0.0.1:8080` für einen lokalen Versuch. Terminiere bei einer öffentlichen Website HTTPS
an einem vertrauenswürdigen Eingangsproxy und halte Sibunas Listener privat. Die
[Einsatzanleitung](https://insanai.github.io/sibuna/de/book/operations.html) beschreibt Caddy und nginx.

Standardmodus ist `reverse_proxy`. Nutze `--mode forward_auth`, wenn der Eingangsproxy weiterleitet und Sibuna nach
Zulassung fragt. Die Anleitung enthält beide Konfigurationen. Shields eingebauter
Prüfer ist standardmäßig aktiv. `--gate` liefert Zulassung ohne diesen Prüfer. Wähle Regeln
mit `--policy-file <file>`, auch für API-Clients und Health-Checks ohne Browser-Challenge.

Entpacke unter Windows die ZIP und führe `.\sibuna.exe --help` in PowerShell aus. Ctrl+C stoppt es.
Beschränke Seed-, Zugangsdaten- und Datendateien mit Windows-ACLs.

<a id="build-from-source"></a>

### Aus Quellen bauen

Nutze **Zig 0.17.0**. Toolchain-Prüfsummen und festgelegte Abhängigkeitsquellen liegen im Repository.

```sh
git clone git@github.com:insanai/sibuna.git
cd sibuna
python3 tools/prepare_build.py
zig build -Doptimize=safe -j2
```

Das Programm liegt unter `zig-out/bin/sibuna`. Cluster-Builds nutzen `-Dcluster=true` und brauchen OpenSSL 3.
[CONTRIBUTING.md](CONTRIBUTING.md) beschreibt die Build-Prüfungen auf Englisch.

<a id="enable-owasp-crs"></a>

### OWASP CRS aktivieren

CRS ist standardmäßig aus. Lade und prüfe ein unterstütztes signiertes Release. Starte
mit Audit, um Funde ohne CRS-Ablehnungen zu prüfen:

```sh
./sibuna crs check --version 4.30.0 --output ./crs-candidate
./sibuna --host 127.0.0.1 --upstream-port 3000 --secret-file ./sibuna.seed \
  --crs-mode audit --crs-dir ./crs-candidate
```

Nutze ein neues Kandidatenverzeichnis. Die Prüfung ändert keinen laufenden Daemon.
CLI und Konsole können Updates vorbereiten, Änderungen prüfen und einen verifizierten
Kandidaten auswählen. Aktiviere Enforce nach Tests normalen Anwendungsverkehrs und Prüfung
der Ausschlüsse. Die [CRS-Anleitung](https://insanai.github.io/sibuna/de/book/operations.html) beschreibt Updates, Rücknahme, Body-Grenzen
und unvollständige Prüfung. Forward Auth verlangt `--crs-profile headers` und sieht keine vollständigen Bodies.

<a id="console"></a>

## Konsole

Die Konsole läuft im selben Programm. Initialisiere einen Administrator bei gestopptem Daemon:

```sh
./sibuna init-admin admin --data-dir ./data
./sibuna --host 127.0.0.1 --upstream-port 3000 --secret-file ./sibuna.seed \
  --data-dir ./data --console 127.0.0.1:19446
```

Öffne `http://127.0.0.1:19446/console/` und ändere das vorläufige Passwort. Die [Betriebsanleitung](https://insanai.github.io/sibuna/de/book/operations.html) beschreibt
HTTPS, GeoIP-Import und CRS-Updates. Ergänze die CRS-Optionen des vorherigen Beispiels,
um Prüfung neben der Konsole zu aktivieren.

![Sibuna-Konsole mit Globus, Anfragezeitachse und Abdeckung](docs/readme/images/console-globe.jpg)

Der Globus zeigt Länderstichproben der letzten Minute. Marker geben ungefähre
Länderpositionen an. Pfeile zeigen zum eingestellten Serverstandort, keine einzelnen
Live-Verbindungen. GeoIP benötigt einen getrennt importierten Datensatz. `--console-location <latitude,longitude>` platziert
 den Server auf dem Globus.

<details>
<summary>Verkehrsübersicht, Richtlinieneditor und Vorfallsuntersuchung</summary>

**Verkehrsübersicht** — Anfrageergebnisse, Beobachtungsfenster und Live-Updates.

![Sibuna-Verkehrsübersicht mit Zählern zugelassener, herausgeforderter und abgelehnter Anfragen](docs/readme/images/console-dashboard.jpg)

**Richtlinieneditor** — Beispiel einer Checkout-Challenge mit ausdrücklichen Kriterien und Einstellungen.

![Sibuna-Richtlinieneditor mit Entwurf einer Checkout-Challenge-Regel](docs/readme/images/console-policy-editor.jpg)

**Vorfallsuntersuchung** — gespeicherte Belege und begrenzte, redigierte Anfrageheader.

![Vorfallsbelege mit redigierten Headern und Antwortzustand](docs/readme/images/console-incident.jpg)

</details>

Dies sind Chrome-Aufnahmen von v0.2.0 auf einem Prüfknoten. Verkehr und GeoIP-Zuordnungen
sind Testdaten. Die angezeigten Zähler sind keine Benchmark-Ergebnisse.

<a id="how-it-works"></a>

## Funktionsweise

Eine Anfrage wird zugelassen, herausgefordert oder abgelehnt. Ein Besucher mit gelöstem
Rätsel erhält eine signierte Sitzung. Spätere Anfragen durchlaufen weiterhin die
anwendbaren Richtlinien- und Ratenprüfungen.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/readme/images/admission-session-dark.svg">
  <img src="docs/readme/images/admission-session.svg" alt="Rätsel lösen, signierte Sitzung erhalten und weitere Anfragen gegen Regeln prüfen">
</picture>

Gate prüft Zugangsregeln, Sitzungen und lokale Ratenlimits. Shield ergänzt den eingebauten
Angriffsprüfer. Natives CRS wird getrennt eingerichtet. Beginne mit Audit vor Enforce.

<details>
<summary>Gate, Shield und Sibunas Module</summary>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/readme/images/protection-surfaces-dark.svg">
  <img src="docs/readme/images/protection-surfaces.svg" alt="Gate- und Shield-Entscheidungen: erlauben, herausfordern oder sperren">
</picture>

Das Diagramm zeigt die eingebauten Gate- und Shield-Prüfungen. Optionales CRS prüft
zusätzlich. Gültige Sitzungen umgehen weder anwendbare Angriffsprüfungen noch Ratenlimits.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/readme/images/subsystems-dark.svg">
  <img src="docs/readme/images/subsystems.svg" alt="Aufgaben der Module in Sibuna">
</picture>

Die Module trennen Netzwerk, Nachweise, Richtlinien, lokalen Zustand und Verwaltung.
Das [Buch](https://insanai.github.io/sibuna/de/book/) erklärt ihre Aufgaben.

</details>

<a id="deployment-limits"></a>

### Einsatzgrenzen

Sibuna nutzt HTTP/1.1 auf seinem privaten Listener. Der Eingangsproxy übernimmt
öffentliches TLS und HTTP/2. Forward Auth prüft gelieferte Metadaten. Volle CRS-Prüfung
im Reverse-Proxy nutzt eingestellte Body- und Arbeitsgrenzen. Der eingebaute Prüfer deckt
die ersten 8 KiB ab. Ohne CRS werden Uploads gestreamt. WebSocket-Nachrichten werden
ungeprüft weitergeleitet. Volles CRS begrenzt Anfragen standardmäßig auf 4 MiB und Antworten
auf 1 MiB und puffert Bodies. Enforce lehnt unvollständige Prüfung ab. Prüfe Grenzen
und Streaming-Ausnahmen deiner Anwendung vor Aktivierung.

Ratenlimits sind knotenlokal. Sibuna bietet keinen Schutz vor volumetrischen
Netzwerkangriffen. Das strenge Leistungsziel der Konsole ist nicht formal bestanden.
Prüfe [Einsatzgrenzen und Messungen](https://insanai.github.io/sibuna/de/book/operations.html), bevor du sie neben einer produktiven Anwendung aktivierst.

<a id="benchmarks"></a>

## Benchmarks

Das Buch nennt Revision, Konfiguration und Host jedes Laufs. Die Messungen zeigen
Anfragekosten unter einer Last. Sie messen weder gleichwertigen Schutz noch Bot-Genauigkeit.

<a id="three-product-comparison"></a>

### Vergleich dreier Produkte

Dieser Lauf verglich **Sibuna v0.2.0**, Anubis 1.27.0 und BunkerWeb 1.6.15 am 4. Oktober
2026. Server und Lastgenerator liefen auf getrennten physischen Hosts. Jedes Produkt
hatte vier CPUs, 64 Verbindungen und denselben Caddy-Ursprung. Challenges und Verwaltung
waren aus. Die Tabelle zeigt Mediane aus fünf Läufen.

| Profil | Harmloses GET (req/s) | p99 (ms) | 8-KiB-JSON-POST (req/s) | p99 (ms) |
| --- | ---: | ---: | ---: | ---: |
| Ursprung direkt | 70,759 | 4.67 | 13,719 | 9.01 |
| Sibuna Gate | 71,270 | 4.12 | 13,719 | 9.16 |
| Anubis | 28,277 | 7.50 | 13,718 | 9.20 |
| BunkerWeb, CRS aus | 13,617 | 8.27 | 12,300 | 8.94 |
| Sibuna Shield | 70,909 | 4.06 | 13,719 | 9.08 |
| BunkerWeb, CRS an | 2,730 | 32.73 | 797 | 98.42 |

BunkerWebs CRS-Profil prüft mehr als das v0.2.0-Shield-Profil dieser Tabelle. Sibuna
v0.3.0 ergänzt natives CRS; dieser Vergleich ist älter. Beide Hosts sind geteilte
Container. CPU-Frequenz und fremde Host-Aktivität wurden nicht kontrolliert.

<a id="native-crs-in-v030"></a>

### Natives CRS in v0.3.0

Dieser getrennte Lauf nutzte acht Dashboards, vier Produkt-CPUs und 16 Verbindungen von
einem anderen Host. Die Tabelle zeigt Medianraten aus fünf Runden. Der eingebaute Prüfer war aus.

| Arbeitslast | CRS aus (req/s) | Audit, Paranoia 1 (req/s) | Audit, Paranoia 2 (req/s) |
| --- | ---: | ---: | ---: |
| Kleines GET | 47,311 | 10,787 | 7,423 |
| 8-KiB-JSON-POST | 13,726 | 1,151 | 799 |
| 16-KiB-Multipart-Upload | 6,704 | 4,248 | 2,887 |

Bei Paranoia eins lag p99 für diese Lasten bei 2.34 ms, 23.43 ms und 6.34 ms. Spitzen-RSS
betrug über die CRS-Profile 133.8–140.5 MiB. Keine gemessene Anfrage erschöpfte das
Arbeitslimit. Der Lauf nutzte saubere Revision `d461e7f`. Payloads und Nebenläufigkeit unterscheiden
sich vom Drei-Produkt-Vergleich. Die Tabellen sind daher kein abgestimmter Direktvergleich.

Die [Benchmark-Aufzeichnungen](benchmarks/results/README.md) enthalten Bereiche, CPU, Speicher, Enforce und
Wiederholungsbefehle. Diese Zahlen bestehen nicht das getrennte Console-Impact-Gate.

<a id="documentation"></a>

## Dokumentation

- [Buch](https://insanai.github.io/sibuna/de/book/): Konzepte, Algorithmen, Beispiele und Messungen.
- [Whitepaper, Englisch](https://insanai.github.io/sibuna/whitepaper/): Architektur, Beweise und Entwurfsdetails.
- [Betriebsanleitung](https://insanai.github.io/sibuna/de/book/operations.html): Installation und Einsatz.
- [Referenz](https://insanai.github.io/sibuna/de/book/reference.html): CLI und Protokoll.
- [Entwurfsdiskussionen, Englisch](https://insanai.github.io/sibuna/sid/): Entscheidungen und technische Verträge.
- [Mitwirken, Englisch](CONTRIBUTING.md): Quellbuilds und Prüfungen.

<a id="other-software-to-consider"></a>

## Weitere Software

- [Anubis](https://github.com/TecharoHQ/anubis): Browser-Challenges gegen Crawler-Verkehr.
- [BunkerWeb](https://github.com/bunkerity/bunkerweb): nginx, ModSecurity, CRS und Bot-Challenges.
- [ModSecurity](https://github.com/owasp-modsecurity/ModSecurity): WAF-Engine über Connectoren.
- [Coraza](https://github.com/corazawaf/coraza): Go-WAF-Bibliothek für ModSecurity-Regeln und CRS.
- [OWASP Core Rule Set](https://github.com/coreruleset/coreruleset): Angriffserkennungsregeln für WAF-Engines.

Diese Projekte decken verschiedene Bereiche des Webschutzes ab. Sibuna wertet signierte
Standard-CRS-Releases aus. Plugins, Lua und andere ModSecurity-Regelsätze liegen außerhalb seines Umfangs.

<a id="license"></a>

## Lizenz

Die Engine steht unter **LGPL 3.0**, die Konsole einschließlich WebAssembly-Oberfläche
unter **AGPL 3.0**. Das Standardprogramm verbindet beide und wird unter AGPL 3.0
verteilt. Nutze `-Dconsole=false` für den Engine-Build ohne Konsole.

[LICENSE](LICENSE) beschreibt den Umfang, [LICENSES](LICENSES) die vollständigen Bedingungen.
[NOTICE](NOTICE) nennt Abhängigkeiten. Quellen und Build-Skripte stehen unter jedem Release-Tag.

Unternehmen mit anderen Lizenzwünschen können Vikrant Rathore und Ronak Rathore
kontaktieren. Bibliotheken und Materialien Dritter behalten ihre jeweiligen Lizenzen.
