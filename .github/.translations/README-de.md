# AutoSploit

Wie der Name vielleicht sagt, versucht Autosploit automatisiert Remote Hosts zu nutzen. Ziele können automatisch über Shodan, Censys oder Zoomeye gesammelt werden. Es wurden aber außerdem Optionen hinzugefügt, welche es erlauben, eigene Ziele oder Host-Listen hinzuzufügen. Die verfügbaren Metasploit-Module wurden ausgewählt, um die Ausführung von Remote-Code zu erleichtern und um zu versuchen, Reverse TCP Shells und/oder Meterpreter-Sessions zu erhalten.

**Sicherheitserwägung für den Betrieb**

Das Empfangen von Verbindungen über deine lokale Maschine ist vielleicht nicht die beste Idee für einen OPSEC-Standpunkt. Ziehe es stattdessen in Betracht, dieses Tool auf einem VPS auszuführen, welches alle benötigten Abhängigkeiten installiert hat.

Die neue Version von AutoSploit verfügt über ein Feature, welches dir erlaubt, eine Proxy zu setzen, bevor du dich verbindest, und einen benutzerdefinierten User-Agent zu verwenden.

# Hilfreiche Links

 - [Nutzung](https://github.com/NullArray/AutoSploit#usage)
 - [Installation](https://github.com/NullArray/AutoSploit#Installation)
 - [Abhängigkeiten](https://github.com/NullArray/AutoSploit#dependencies)
 - [Benutzerhandbuch](https://github.com/NullArray/AutoSploit/wiki)
   - [Nutzungsmöglichkeiten](https://github.com/NullArray/AutoSploit/wiki/Usage#usage-options)
   - [Screenshots](https://github.com/NullArray/AutoSploit/wiki/Examples-and-images)
   - [Bugs/Ideen melden](https://github.com/NullArray/AutoSploit/wiki/Bugs-and-ideas#bugs)
   - [Entwicklungsleitfäden](https://github.com/NullArray/AutoSploit/wiki/Development-information#development-of-autosploit)
 - [Shoutouts](https://github.com/NullArray/AutoSploit#acknowledgements)
 - [Entwicklung](https://github.com/NullArray/AutoSploit#active-development)
 - [Discord-Server](https://discord.gg/9BeeZQk)
 - [README-Übersetzungen](https://github.com/NullArray/AutoSploit#translations)

# Installation

AutoSploit zu installieren ist sehr einfach. Du kannst den neuesten, Release [hier](https://github.com/NullArray/AutoSploit/releases/tag/2.0) finden. Du kannst außerdem den Master-Branch als [zip](https://github.com/NullArray/AutSploit/zipball/master), als [tarball](https://github.com/NullArray/AutSploit/tarball/master) oder mit einer der folgenden Methoden herunterladen.

###### Cloning

```bash
sudo -s << EOF
git clone https://github.com/NullArray/Autosploit.git
cd AutoSploit
chmod +x install.sh
./install.sh
python2 autosploit.py
EOF
```

###### Docker

```bash
sudo -s << EOF
git clone https://github.com/NullArray/AutoSploit.git
cd AutoSploit
chmod +x install.sh
./installsh
cd AutoSploit/Docker
docker network create -d bridge haknet
docker run --network haknet --name msfdb -e POSTGRES_PASSWORD=s3cr3t -d postgres
docker build -t autosploit .
docker run -it --network haknet -p 80:80 -p 443:443 -p 4444:4444 autosploit
EOF
```

Auf jedem Linux-System sollte folgendes funktionierern;

```bash
git clone https://github.com/NullArray/AutoSploit
cd AutoSploit
chmod +x install.sh
./install.sh
```

Falls du AutoSploit auf einem System mit macOS ausführen willst, musst du das Programm trotz der Kompatibilität mit macOS in einer virtuellen Maschine ausführen, sodass es erfolgreich ausgeführt werden kann. Um dies zu tun, sind folgende Schritte nötig;

```bash
sudo -s << '_EOF'
pip2 install virtualenv --user
git clone https://github.com/NullArray/AutoSploit.git
virtualenv <PFAD-ZU-DEINER-ENV>
source <PFAD-ZU-DEINER-ENV>/bin/activate
cd <PFAD-ZU-AUTOSPLOIT>
pip2 install -r requirements.txt
chmod +x install.sh
./install.sh
python autosploit.py
_EOF
```


Mehr Informationen über die Nutzung von Docker können [hier](https://github.com/NullArray/AutoSploit/tree/master/Docker) gefunden werden.

## Nutzung

Das Programm mit `python autosploit.py` auszuführen, wird eine AutoSploit Terminal Session öffnen. Die Optionen für diese sind im Folgenden aufgelistet.
```
1. Usage And Legal
2. Gather Hosts
3. Custom Hosts
4. Add Single Host
5. View Gathered Hosts
6. Exploit Gathered Hosts
99. Quit
```

Beim Auswählen der Option `2` wirst du aufgefordert, eine Plattform-spezifischen Suchanfrage einzugeben. Gib zum Beispiel `IIS` oder `Apache` ein und wähle eine Suchmaschine aus. Danach werden die gesammelten Hosts gespeichert, um sie in der `Exploit` Komponente nutzen zu können.

Seit Version 2.0 von AutoSploit, kann dieses ebenfalls mit einer Anzahl von Command Line Argumenten/Flags gestartet werden. Gib `python autosploit.py -h` ein, um alle für dich verfügbaren Optionen anzuzeigen. Zur Referenz sind die Optionen nachfolgend ebenfalls aufgelistet *(auf Englisch)*.

```
usage: python autosploit.py -[c|z|s|a] -[q] QUERY
                            [-C] WORKSPACE LHOST LPORT [-e] [--whitewash] PATH
                            [--ruby-exec] [--msf-path] PATH [-E] EXPLOIT-FILE-PATH
                            [--rand-agent] [--proxy] PROTO://IP:PORT [-P] AGENT

optional arguments:
  -h, --help            show this help message and exit

search engines:
  possible search engines to use

  -c, --censys          use censys.io as the search engine to gather hosts
  -z, --zoomeye         use zoomeye.org as the search engine to gather hosts
  -s, --shodan          use shodan.io as the search engine to gather hosts
  -a, --all             search all available search engines to gather hosts

requests:
  arguments to edit your requests

  --proxy PROTO://IP:PORT
                        run behind a proxy while performing the searches
  --random-agent        use a random HTTP User-Agent header
  -P USER-AGENT, --personal-agent USER-AGENT
                        pass a personal User-Agent to use for HTTP requests
  -q QUERY, --query QUERY
                        pass your search query

exploits:
  arguments to edit your exploits

  -E PATH, --exploit-file PATH
                        provide a text file to convert into JSON and save for
                        later use
  -C WORKSPACE LHOST LPORT, --config WORKSPACE LHOST LPORT
                        set the configuration for MSF (IE -C default 127.0.0.1
                        8080)
  -e, --exploit         start exploiting the already gathered hosts

misc arguments:
  arguments that don't fit anywhere else

  --ruby-exec           if you need to run the Ruby executable with MSF use
                        this
  --msf-path MSF-PATH   pass the path to your framework if it is not in your
                        ENV PATH
  --whitelist PATH      only exploit hosts listed in the whitelist file
```

Falls du AutoSploit auf einem System mit macOS ausführen willst, musst du das Programm trotz der Kompatibilität mit macOS in einer virtuellen Maschine ausführen, sodass es erfolgreich ausgeführt werden kann. Um dies zu tun, sind folgende Schritte nötig;

```bash
sudo -s << '_EOF'
pip2 install virtualenv --user
git clone https://github.com/NullArray/AutoSploit.git
virtualenv <PFAD-ZU-DEINER-ENV>
source <PFAD-ZU-DEINER-ENV>/bin/activate
cd <PFAD-ZU-AUTOSPLOIT>
pip2 install -r requirements.txt
chmod +x install.sh
./install.sh
python autosploit.py
_EOF
```

## Abhängigkeiten
_Bitte beachte_: Alle Abhängigkeiten sollten über die obige Installationsmethode installiert werden. Für den Fall, dass die Installation nicht möglich ist:

AutoSploit benötigt die folgenden Python 2.7 Module:

```
requests
psutil
beautifulsoup4
```

Wenn dir auffällt, dass du diese nicht installiert hast, kannst du sie über Pip installieren, wie nachfolgend gezeigt.

```bash
pip install requests psutil beautifulsoup4
```

oder

```bash
pip install -r requirements.txt
```

Da das Programm Funktionalität des Metasploit-Frameworkes nutzt, musst du dieses ebenfalls installiert haben. Hole es dir über Rapid7, indem du [hier](https://www.rapid7.com/products/metasploit/) klickst.

## Danksagung

Ein besonderer Dank gilt [Ekultek](https://github.com/Ekultek) ohne dessen Beiträge die Version 2.0 dieses Projekts wohl weitaus weniger spektakulär wäre.

Ebenfalls danke an [Khast3x](https://github.com/khast3x) für das Einrichten der Docker-Unterstützung.

### Aktive Entwicklung

Falls du gerne zur Entwicklung dieses Projekts beitragen möchtest, bitte lies zuerst [CONTRIBUTING.md](https://github.com/NullArray/AutoSploit/blob/master/CONTRIBUTING.md), da diese unsere Leitfäden für Contributions enthält.

Bitte lies außerdem [die Contribution-Standards](https://github.com/NullArray/AutoSploit/wiki/Development-information#contribution-standards), bevor du eine Pull Request erstellst.

Falls du Hilfe damit brauchst, den Code zu verstehen, oder einfach mit anderen Mitgliedern der AutoSploit-Community chatten möchtest, kannst du gerne unserem [Discord-Server](https://discord.gg/9BeeZQk) joinen.

### Anmerkung

Falls du einem Bug begegnest, bitte fühle dich frei, [ein Ticket zu öffnen](https://github.com/NullArray/AutoSploit/issues).

Danke im Voraus.

## Übersetzungen

 - [FR](https://github.com/NullArray/AutoSploit/blob/master/.github/.translations/README-fr.md)
 - [ZH](https://github.com/NullArray/AutoSploit/blob/master/.github/.translations/README-zh.md)
 - [DE](https://github.com/NullArray/AutoSploit/blob/master/.github/.translations/README-de.md)
