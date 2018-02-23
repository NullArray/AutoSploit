# AutoSploit

As the name might suggest AutoSploit attempts to automate the exploitation of remote hosts. Targets are collected automatically as well by employing the Shodan.io API. The program allows the user to enter their platform specific search query such as; `Apache`, `IIS`, etc, upon which a list of candidates will be retrieved.                           

After this operation has been completed the 'Exploit' component of the program will go about the business of attempting to exploit these targets by running a series of Metasploit modules against them. Which Metasploit modules will be employed in this manner is determined by programmatically comparing the name of the module to the initial search query. However, I have added functionality to run all available modules against the targets in a 'Hail Mary' type of attack as well.

The available Metasploit modules have been selected to facilitate Remote Code Execution and to attempt to gain Reverse TCP Shells and/or Meterpreter sessions. Workspace, local host and local port for MSF facilitated back connections are configured through the dialog that comes up before the 'Exploit' component is started.

**Operational Security Consideration**

Receiving back connections on your local machine might not be the best idea from an OPSEC standpoint. Instead consider running this tool from a VPS that has all the dependencies required, available.

## Usage

Clone the repo. Or deploy via Docker. Details for which can be found [here](https://github.com/NullArray/AutoSploit/tree/master/Docker) Special thanks to [Khast3x](https://github.com/khast3x) for their contribution in this regard.

`git clone https://github.com/NullArray/AutoSploit.git`

After which it can be started from the terminal with `python autosploit.py`. After which you can select one of five actions. Please see the option summary below.
```
+------------------+----------------------------------------------------+
|     Option       |                   Summary                          |
+------------------+----------------------------------------------------+
|1. Usage          | Display this informational message.                |
|2. Gather Hosts   | Query Shodan for a list of platform specific IPs.  |
|3. View Hosts     | Print gathered IPs/RHOSTS.                         |
|4. Exploit        | Configure MSF and Start exploiting gathered targets|
|5. Quit           | Exits AutoSploit.                                  |
+------------------+----------------------------------------------------+
```
## Available Modules
The Metasploit modules available with this tool are selected for RCE. You can find them in the `modules.txt` file that is included in this repo. Should you wish to add more or other modules please do so in the following format.
```
use exploit/linux/http/netgear_wnr2000_rce;exploit -j; 
```
With each new module on it's own line.

## Dependencies
AutoSploit depends on the following Python2.7 modules.
```
shodan
blessings
```
Should you find you do not have these installed get them with pip like so.
```
pip install shodan
pip install blessings
```
Since the program invokes functionality from the Metasploit Framework you need to have this installed also. 
Get it from Rapid7 by clicking [here](https://www.rapid7.com/products/metasploit/).


### Active Development
While this isn't exactly a Beta release it is an early release nonetheless as such the tool might be subject to changes in the future. 

I've been working on the new version of the tool in an open source capacity with the help of a number of developers 
that have expressed an interest in doing so. The new version will include extra features such as the ability to load in a custom target and exploit list among many more enhancements. If you would like to keep up to date on all the most recent developments be sure to check out the [Development Branch](https://github.com/NullArray/AutoSploit/tree/dev-beta)

### Note

If you happen to encounter a bug please feel free to [Open a Ticket](https://github.com/NullArray/AutoSploit/issues).

If you wish to contribute to the development of this project please be sure to read [CONTRIBUTING.md](https://github.com/NullArray/AutoSploit/blob/master/CONTRIBUTING.md) before you get started as it contains our contribution guidelines.

Thanks in advance.

