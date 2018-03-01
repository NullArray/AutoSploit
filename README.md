# AutoSploit

As the name might suggest AutoSploit attempts to automate the exploitation of remote hosts. Targets can be collected automatically through Shodan, Censys or Zoomeye. But options to add your custom targets and host lists have been included as well.
The available Metasploit modules have been selected to facilitate Remote Code Execution and to attempt to gain Reverse TCP Shells and/or Meterpreter sessions. Workspace, local host and local port for MSF facilitated back connections are configured by filling out the dialog that comes up before the exploit component is started

**Operational Security Consideration**

Receiving back connections on your local machine might not be the best idea from an OPSEC standpoint. Instead consider running this tool from a VPS that has all the dependencies required, available.

The new version of AutoSploit has a feature that allows you to set a proxy before you connect and a custom user-agent.

# Helpful links
 - [Usage](https://github.com/NullArray/AutoSploit#usage)
 - [Dependencies](https://github.com/NullArray/AutoSploit#dependencies)
 - [User Manual](https://github.com/NullArray/AutoSploit/wiki)
 - [Shoutouts](https://github.com/NullArray/AutoSploit#acknowledgements)
 - [Development](https://github.com/NullArray/AutoSploit#active-development)
 - [Discord server](https://discord.gg/9BeeZQk)

## Usage

Clone the repo. Or deploy via Docker. Details for which can be found [here](https://github.com/NullArray/AutoSploit/tree/master/Docker) 

`git clone https://github.com/NullArray/AutoSploit.git`

Starting the program with `python autosploit.py` will open an AutoSploit terminal session. The options for which are as follows.

```
1. Usage And Legal
2. Gather Hosts
3. Custom Hosts
4. Add Single Host
5. View Gathered Hosts
6. Exploit Gathered Hosts
99. Quit
```

Choosing option `2` will prompt you for a platform specific search query. Enter `IIS` or `Apache` in example and choose a search engine. After doing so the collected hosts will be saved to be used in the `Exploit` component.

As of version 2.0 AutoSploit can be started with a number of command line arguments/flags as well. Type `python autosploit.py -h` 
to display all the options available to you. I've posted the options below as well for reference.

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


## Dependencies

AutoSploit depends on the following Python2.7 modules.

```
requests
psutil
```

Should you find you do not have these installed get them with pip like so.

```bash
pip install requests psutil
```

or

```bash
pip install -r requirements.txt
```

Since the program invokes functionality from the Metasploit Framework you need to have this installed also. Get it from Rapid7 by clicking [here](https://www.rapid7.com/products/metasploit/).

## Acknowledgements

Special thanks to [Ekultek](https://github.com/Ekultek) without whoms contributions to the project version 2.0 would have been a lot less spectacular.

And thanks to [Khast3x](https://github.com/khast3x) for setting up Docker support.



### Active Development

While this isn't exactly a Beta release, AutoSploit 2.0 is an early release nonetheless as such the tool might be subject to changes in the future. 

I've been working on the new version of the tool in an open source capacity with the help of a number of developers 
that have expressed an interest in doing so. The new version will include extra features such as the ability to load in a custom target and exploit list among many more enhancements. If you would like to keep up to date on all the most recent developments be sure to check out the [Development Branch](https://github.com/NullArray/AutoSploit/tree/dev-beta).

If you need some help understanding the code, or want to chat with some other AutoSploit community members, feel free to join our [Discord chat](https://discord.gg/9BeeZQk).

### Note

If you happen to encounter a bug please feel free to [Open a Ticket](https://github.com/NullArray/AutoSploit/issues).

Thanks in advance.
