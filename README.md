# noports - HackMyVM (Medium)
 
![noports.png](noports.png)

## Übersicht

*   **VM:** noports
*   **Plattform:** (https://hackmyvm.eu/machines/machine.php?vm=Noport)
*   **Schwierigkeit:** Medium
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 20. Mai 2025
*   **Original-Writeup:** https://alientec1908.github.io/noports_HackMyVM_Medium/
*   **Autor:** Ben C.

## Kurzbeschreibung

Die "noports"-Maschine auf HackMyVM war eine Herausforderung mittleren Schwierigkeitsgrades. Das Ziel war es, Root-Zugriff auf dem System zu erlangen. Der Lösungsweg umfasste die Entdeckung eines exponierten `.git`-Verzeichnisses, das zur Preisgabe von Quellcode und einem Admin-Passwort-Hash führte. Nach dem Knacken des Hashes konnte über eine Webshell initialer Zugriff erlangt werden. Die Privilegienerweiterung zu Root erfolgte durch die Ausnutzung einer weltweit beschreibbaren Nginx-Konfigurationsdatei in Kombination mit der `sudo`-Berechtigung, das System neuzustarten.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `netdiscover`
*   `nmap`
*   `gobuster`
*   `git_dumper.py` (Python-Skript)
*   `curl`
*   `vi` (oder ein anderer Texteditor)
*   `python3` (für das Cracking-Skript)
*   `nc` (Netcat)
*   `chisel`
*   `openssl` (für Passwort-Hashing-Tests)
*   `base64`
*   Standard Linux-Befehle (`ls`, `cat`, `find`, `cd`, `git`, etc.)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "noports" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Enumeration:**
    *   IP-Adresse des Ziels (`192.168.2.200`) mittels `netdiscover` gefunden.
    *   Portscan mit `nmap` ergab einen offenen Port `80/tcp` mit einem Apache httpd 2.4.62.

2.  **Web Enumeration & Schwachstellensuche:**
    *   `gobuster` identifizierte ein öffentlich zugängliches `/.git`-Verzeichnis.
    *   `git_dumper.py` wurde verwendet, um das Repository herunterzuladen.
    *   Analyse der heruntergeladenen Dateien, insbesondere einer `.test.php.swp`-Datei, enthüllte PHP-Code einer Bot-Funktionalität und Hinweise auf eine Admin-Passwort-Umgebungsvariable.

3.  **Initial Access (Ausnutzung der Bot-Funktionalität & Webshell):**
    *   Durch gezielte `curl`-Anfragen an die Endpunkte `/visit` und `/log` (aus dem geleakten Code abgeleitet) wurde ein Admin-Passwort-Hash (`6f06ee724b86fca512018ad692a62aedc`) extrahiert.
    *   Ein Python-Skript wurde erstellt, um diesen SHA256-Hash zu knacken, was zum Passwort `shredder1` für den Benutzer `admin` führte.
    *   Mit den Credentials (oder einer zuvor erlangten/geratenen `PHPSESSID`) wurde eine Webshell (`sh3ll.php`) genutzt, um Befehle als Benutzer `apache` auszuführen.
    *   Eine Reverse Shell wurde mittels `nc` und einer Named Pipe etabliert, was zu einer interaktiven Shell als `apache` führte.

4.  **Post-Exploitation / Privilege Escalation (von `apache` zu `akaRed`):**
    *   (Dieser Schritt war nicht explizit als separate Rechteausweitung dargestellt, sondern der SSH-Login als `akaRed` erfolgte nach dem Chisel-Tunneling, vermutlich mit dem zuvor geknackten `admin:shredder1` oder einem im Git-Repo gefundenen Passwort für `akaRed`. Für die README nehmen wir an, dass `shredder1` auch das Passwort für `akaRed` war oder ein anderer Weg zu diesem User führte.)
    *   Nach Erhalt der `apache`-Shell wurde `chisel` verwendet, um einen Reverse-Tunnel zu erstellen und den SSH-Port (22) des Zielsystems auf einen lokalen Port (2222) des Angreifer-Systems weiterzuleiten.
    *   SSH-Login als Benutzer `akaRed` über den getunnelten Port. Das Passwort war vermutlich `shredder1`.

5.  **Privilege Escalation (von `akaRed` zu root):**
    *   `sudo -l` als `akaRed` zeigte, dass der Befehl `/usr/bin/curl` ohne Passwort als Root ausgeführt werden konnte.
    *   Die `/etc/shadow`-Datei wurde mittels `sudo curl file:/etc/shadow` ausgelesen.
    *   Ein neues Passwort für den Root-Benutzer wurde mit `openssl passwd 1999` generiert.
    *   Eine temporäre Datei (`test.txt`) wurde mit dem neuen Root-Hash und den anderen Einträgen erstellt.
    *   Mittels `sudo curl file:///home/akaRed/test.txt -o /etc/shadow` wurde die `/etc/shadow`-Datei auf dem Zielsystem mit dem neuen Root-Passwort überschrieben.
    *   Anschließend war ein Login als `root` via `ssh root@localhost` mit dem Passwort `1999` möglich.
    *   Alternativer (und im Report detaillierterer) Weg zur Root-Eskalation war die Ausnutzung der weltweit beschreibbaren `/etc/nginx/nginx.conf` durch den `apache`-Benutzer. Eine modifizierte `nginx.conf` mit einer Lua-basierten Reverse-Shell-Payload wurde erstellt und hochgeladen. Ein `sudo /sbin/reboot` (erlaubt für `apache`) löste den Neustart von Nginx aus, welcher dann eine Root-Shell zum Angreifer aufbaute.

## Wichtige Schwachstellen und Konzepte

*   **Exponiertes .git-Verzeichnis:** Ermöglichte den Zugriff auf den Quellcode, die Commit-Historie und sensible Informationen wie die Bot-Logik und den Admin-Passwort-Hash.
*   **Informationsleck durch Bot-Funktionalität:** Der Bot gab über den `/log`-Endpunkt sensible Daten preis, einschließlich des Admin-Passwort-Hashes.
*   **Schwaches Passwort:** Das Admin-Passwort "shredder1" konnte mittels Wortlistenangriff geknackt werden.
*   **Webshell (RCE):** Eine vorhandene (oder durch die Bot-Logik implizierte) Webshell erlaubte Remote Code Execution.
*   **Unsichere `sudo`-Konfiguration (für `akaRed`):** Das Recht, `curl` als Root auszuführen, erlaubte das Lesen und Schreiben beliebiger lokaler Dateien und somit das Überschreiben der `/etc/shadow`.
*   **Unsichere Dateiberechtigungen (Nginx-Konfiguration):** Die weltweit beschreibbare `/etc/nginx/nginx.conf` ermöglichte in Kombination mit der `sudo`-Regel für `reboot` (für den `apache`-Benutzer) die Injektion einer Root-Reverse-Shell-Payload.
*   **Lua in Nginx für Codeausführung:** Nutzung von `init_by_lua_block` zur Ausführung von Systembefehlen beim Nginx-Start.
*   **Reverse Tunneling (Chisel):** Umgehen von Firewall-Beschränkungen, um Zugriff auf interne Dienste (SSH) zu erhalten.

## Flags

*   **User Flag (`/home/akaRed/user.txt`):** (Im Berichtstext nicht explizit als `cat`-Ausgabe gezeigt, aber der Pfad ist aus dem `ls` im `akaRed`-Kontext bekannt. Die Flag selbst ist im HTML-Bericht leer.)
*   **Root Flag (`/root/root.txt`):** `flag{Ur_t3h_Trvely_n3tvv0rk_@ce_on_QQGroup}`

## Tags

`HackMyVM`, `noports`, `Medium`, `Git Dumper`, `Webshell`, `SSRF (implied by bot)`, `Password Cracking`, `Sudo Exploitation`, `Nginx Misconfiguration`, `Chisel`, `Linux`, `Web`, `Privilege Escalation`
