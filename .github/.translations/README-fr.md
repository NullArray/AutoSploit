# AutoSploit

Comme vous pouvez l'imaginer au vu du nom de ce projet, AutoSploit automatise l'exploitation d'hôtes distantes connectées à internet. Les adresses des hôtes à attaquer sont collectées automatiquement grâce à l'aide de Shodan, Censys et Zoomeye. Vous pouvez également utiliser vos propres listes de cibles.
Les modules Metasploit disponibles ont été sélectionnés afin de faciliter l'obtention d'exécution de code à distance ( Remote Code Execution, ou RCE ), qui permettent ensuite de créer des sessions terminal inversées ( reverse shell ) ou meterpreter ( via metasploit ).

**Ne soyez pas stupides**

Recevoir les connexions de vos victimes directement sur votre ordinateur n'est pas vraiment une bonne idée. Vous devriez considérer l'option de dépenser quelques euros dans un VPS ( ou VPN ).

La nouvelle version d'AutoSploit permet néanmoins de définir un proxy et un User-Agent personalisé.

# Liens utiles

 - [Utilisation](https://github.com/NullArray/AutoSploit/README-fr.md#Utilisation)
 - [Installation](https://github.com/NullArray/AutoSploit/README-fr.md#Installation)
 - [Dépendances](https://github.com/NullArray/AutoSploit/README-fr.md#Dépendances))
 - [Wiki](https://github.com/NullArray/AutoSploit/wiki)
   - [Options d'usage extensif](https://github.com/NullArray/AutoSploit/wiki/Usage#usage-options)
   - [Captures d'écran](https://github.com/NullArray/AutoSploit/wiki/Examples-and-images)
   - [Rapporter un bug, donner une idée](https://github.com/NullArray/AutoSploit/wiki/Bugs-and-ideas#bugs)
   - [Lignes directrices du développement](https://github.com/NullArray/AutoSploit/wiki/Development-information#development-of-autosploit)
 - [Développement](https://github.com/NullArray/AutoSploit/README-fr.md#Développement)
 - [Serveur discord ( en anglais, mais ne vous découragez pas ! )](https://discord.gg/9BeeZQk)


# Installation

Installer AutoSploit est un jeu d'enfant. Vous pouvez trouver la dernière version stable [ici](https://github.com/NullArray/AutoSploit/releases/tag/2.0). Vous pouvez aussi télécharger la branche ``master`` en [zip](https://github.com/NullArray/AutSploit/zipball/master) ou en [tarball](https://github.com/NullArray/AutSploit/tarball/master). Vous pouvez également suivre une des méthodes ci-dessous;

###### Cloner

```bash
sudo -s << EOF
git clone https://github.com/NullArray/Autosploit.git
cd AutoSploit
pip2 install -r requirements.txt
python2 autosploit.py
EOF
```

###### Docker

```bash
sudo -s << EOF
git clone https://github.com/NullArray/AutoSploit.git
cd AutoSploit/Docker
docker network create -d bridge haknet
docker run --network haknet --name msfdb -e POSTGRES_PASSWORD=s3cr3t -d postgres
docker build -t autosploit .
docker run -it --network haknet -p 80:80 -p 443:443 -p 4444:4444 autosploit
EOF
```

Plus d'informations sur la façon d'utiliser Docker [ici](https://github.com/NullArray/AutoSploit/tree/master/Docker)

## Utilisation

L'ouverture du programme avec `python autosploit.py` devrait ouvrir une session terminal AutoSploit. Les options sont les suivantes ( en anglais ).

```
1. Usage And Legal
2. Gather Hosts
3. Custom Hosts
4. Add Single Host
5. View Gathered Hosts
6. Exploit Gathered Hosts
99. Quit
```

Sélectionner l'option `2` vous demandra de choisir quel type d'hôtes rechercher. Vous pouvez par exemple rentrer `IIS` ou `Apache`. Ensuite, on vous demandera quel moteurs de recherches doivent être utilisés lors de la recherche. Si tout fontionne correctement, les hôtes collectées seront sauvegardées et utilisables dans le menu d'exploitation ( `Exploit` )

Depuis la version 2.0, AutoSploit peut être lancé avec des arguments/drapeaux. Pour en savoir plus, exécutez `python autosploit.py -h`.
Pour référence, voici les options ( en anglais ).

```
usage: python autosploit.py -[c|z|s|a] -[q] QUERY
                            [-C] WORKSPACE LHOST LPORT [-e]
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
```

# Dépendances

AutoSploit exige la présence des modules Python2.7 suivants.

```
requests
psutil
beautifulsoup4
```

Si vous ne les avez pas, vous pouvez les installer avec les commandes ci-dessous ( dans le dossier d'AutoSploit ):

```bash
pip install requests psutil beautifulsoup4
```

ou

```bash
pip install -r requirements.txt
```

Comme le programme invoque des fonctionalités du Metasploit, vous devez l'avoir installé au préalable. Vous pouvez en obtenir une copie depuis le site de Rapid7 en cliquant [ici](https://www.rapid7.com/products/metasploit/).

### Développement

Même si AutoSploit n'est pas vraiment en Béta, il est sujet à des changements dans le futur.

Si vous souhaitez rester à jour au niveau du développement et obtenir avant tout le monde toutes les super nouvelles fonctionalités, utilisez la [branche de développement](https://github.com/NullArray/AutoSploit/tree/dev-beta).

Si vous voulez contribuer au développement de ce projet, lisez [CONTRIBUTING.md](https://github.com/NullArray/AutoSploit/blob/master/CONTRIBUTING.md). Ce fichier contient nos lignes directrices de contribution.

Aussi, lisez nos [standards de contribution](https://github.com/NullArray/AutoSploit/wiki/Development-information#contribution-standards) avant d'envoyer une pull request.

Si vous souhaitez obtenir de l'aide avec le code, ou juste partager avec les autres membres de la communauté d'AutoSploit, rejoignez-nous sur notre [serveur Discord](https://discord.gg/9BeeZQk). ( Nous ne mordons pas )

## Note

Si vous rencontrez un bug et que vous souhaitez le signaler, [ouvrez un ticket](https://github.com/NullArray/AutoSploit/issues).

Merci d'avance.

Traduction par [jesuiscamille](https://github.com/jesuiscamille). J'ai probablement fait des erreurs de conjugaison/orthographe/traduction. N'hésitez pas à juste [ouvrir un ticket](https://github.com/NullArray/AutoSploit/issues), c'est rapide et ça nous encourage :) !
