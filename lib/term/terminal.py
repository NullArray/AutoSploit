import os
import sys

import lib.settings
import lib.output
import lib.exploitation.exploiter
import api_calls.shodan
import api_calls.zoomeye
import api_calls.censys


class AutoSploitTerminal(object):

    """
    class object for the main terminal of the program
    """

    def __init__(self, tokens):
        self.tokens = tokens
        self.usage_path = lib.settings.USAGE_AND_LEGAL_PATH
        self.host_path = lib.settings.HOST_FILE
        self.sep = "-" * 30

    def usage_and_legal(self):
        """
        shows a display of the output and legal information that resides
        in the etc/text_files/general file.

        option 1 must be provided to display
        """
        lib.output.info("preparing to display usage and legal")
        with open(self.usage_path) as usage:
            print(usage.read().strip())

    def help(self, command):
        """
        print the help of the commands
        """
        help_dict = {
            "usage": self.usage_and_legal,
            "view": self.view_gathered_hosts,
            "single": self.add_single_host,
            "exit": self.quit,
            "gather": self.gather_hosts,
            "exploit": self.exploit_gathered_hosts,
            "custom": self.custom_host_list
        }
        for key in help_dict.keys():
            if command == key:
                lib.output.info("help found for provided argument:")
                print(self.sep)
                print(help_dict[key].__doc__)
                print(self.sep)
                break
        else:
            lib.output.warning("unable to find help for provided command '{}'".format(command))
            lib.output.info("available helps '{}'".format(
                ", ".join([k for k in help_dict.keys()])
            ))

    def view_gathered_hosts(self):
        """
        print a list of all available hosts in the hosts.txt file

        option 5 must be provided
        """
        lib.output.info("loading gathered hosts from {}".format(self.host_path))
        with open(self.host_path) as hosts:
            for host in hosts.readlines():
                lib.output.info(host.strip())

    def add_single_host(self):
        """
        add a singluar host to the hosts.txt file and check if the host
        will resolve to a true IP address, if it is not a true IP address
        you will be re-prompted for an IP address

        option 4 must be provided
        """
        provided = False
        while not provided:
            new_host = lib.output.prompt("enter the host IP you wish to add", lowercase=False)
            if not lib.settings.validate_ip_addr(new_host):
                lib.output.warning("provided host does not appear to be a true IP, try again")
            else:
                with open(self.host_path, "a+") as hosts:
                    hosts.write(new_host + os.linesep)
                lib.output.info("successfully wrote provided host to {}".format(self.host_path))
                break

    def quit(self, status):
        """
        quits the terminal and exits the program entirely

        option 99 must be provided
        """
        lib.output.error("aborting terminal session")
        assert isinstance(status, int)
        sys.exit(status)

    def gather_hosts(self, query, given_choice=None):
        """
        gather hosts from either Shodan, Zoomeye, Censys, or multiple
        by providing a comma between integers.

        option 2 must be provided
        """
        choice_dict = {
            1: api_calls.shodan.ShodanAPIHook,
            2: api_calls.zoomeye.ZoomEyeAPIHook,
            3: api_calls.censys.CensysAPIHook
        }
        searching = False
        if given_choice is None:
            lib.output.info("please choose an API to gather from (choosing two or more "
                            "separate by comma IE; 1,2)")
            for i, api in enumerate(lib.settings.API_URLS.keys(), start=1):
                print("{}. {}".format(i, api.title()))
            choice = raw_input(lib.settings.AUTOSPLOIT_PROMPT)
        else:
            choice = given_choice
        while not searching:
            try:
                choice = int(choice)
                if choice == 1:
                    choice_dict[choice](self.tokens["shodan"][0], query).shodan()
                    break
                elif choice == 2:
                    choice_dict[choice](query).zoomeye()
                    break
                elif choice == 3:
                    choice_dict[choice](self.tokens["censys"][1], self.tokens["censys"][0], query).censys()
                    break
                else:
                    lib.output.warning("invalid option provided")
            except (ValueError, KeyError):
                if "," in choice:
                    for i in choice.split(","):
                        if int(i) in choice_dict.keys():
                            self.gather_hosts(query, given_choice=int(i))
                        else:
                            lib.output.warning("invalid option, skipping")
                            break
                    break
                else:
                    lib.output.warning("must be integer between 1-{} not string".format(len(lib.settings.API_URLS.keys())))
                    self.gather_hosts(query)

    def exploit_gathered_hosts(self, loaded_mods, hosts=None):
        """
        exploit already gathered hosts from the hosts.txt file

        option 6 must be provided
        """
        ruby_exec = False
        msf_path = None
        if hosts is None:
            hosts = open(self.host_path).readlines()
        if not lib.settings.check_for_msf():
            msf_path = lib.output.prompt(
                "it appears that MSF is not in your PATH, provide the full path to it"
            )
            ruby_exec = True
        lib.output.info(
            "you will need to do some configuration to MSF.\n"
            "please keep in mind that sending connections back to "
            "your local host is probably not a smart idea."
        )
        configuration = (
            lib.output.prompt("enter your workspace name", lowercase=False),
            lib.output.prompt("enter your LHOST", lowercase=False),
            lib.output.prompt("enter your LPORT", lowercase=False)
        )
        exploiter = lib.exploitation.exploiter.AutoSploitExploiter(
            open(lib.settings.HOST_FILE).readlines(),
            configuration,
            loaded_mods,
            ruby_exec=ruby_exec,
            msf_path=msf_path
        )
        sorted_mods = exploiter.sort_modules_by_query()
        choice = lib.output.prompt(
            "a total of {} modules have been sorted by relevance, would you like to display them[y/N]".format(
                len(sorted_mods)
            )
        )
        if not choice.lower().strip().startswith("y"):
            mods = lib.output.prompt("use relevant modules[y/N]")
            if mods.lower().startswith("n"):
                lib.output.info("starting exploitation with all loaded modules (total of {})".format(len(loaded_mods)))
                exploiter.start_exploit(loaded_mods, hosts)
            elif mods.lower().startswith("y"):
                lib.output.info("starting exploitation with sorted modules (total of {})".format(len(sorted_mods)))
                exploiter.start_exploit(sorted_mods, hosts)
        else:
            exploiter.view_sorted()
            mods = lib.output.prompt("use relevant modules[y/N]")
            if mods.lower().startswith("n"):
                lib.output.info("starting exploitation with all loaded modules (total of {})".format(len(loaded_mods)))
                exploiter.start_exploit(loaded_mods, hosts)
            elif mods.lower().startswith("y"):
                lib.output.info("starting exploitation with sorted modules (total of {})".format(len(sorted_mods)))
                exploiter.start_exploit(sorted_mods, hosts)

    def custom_host_list(self, mods):
        """
        provided a custom host list that will be used for exploitation

        option 3 must be provided
        """
        provided_host_file = lib.output.prompt("enter the full path to your host file", lowercase=False)
        self.exploit_gathered_hosts(mods, hosts=provided_host_file)

    def terminal_main_display(self, loaded_mods):
        """
        main output of the terminal
        """
        lib.output.info("welcome to AutoSploit, choose an option, type 99 to quit")
        selected = False

        try:
            while not selected:
                for i in lib.settings.AUTOSPLOIT_TERM_OPTS.keys():
                    print("{}. {}".format(i, lib.settings.AUTOSPLOIT_TERM_OPTS[i].title()))
                choice = raw_input(lib.settings.AUTOSPLOIT_PROMPT)
                try:
                    choice = int(choice)
                    if choice == 99:
                        print(self.sep)
                        self.quit(0)
                        print(self.sep)
                    elif choice == 6:
                        print(self.sep)
                        self.exploit_gathered_hosts(loaded_mods)
                        print(self.sep)
                    elif choice == 5:
                        print(self.sep)
                        self.view_gathered_hosts()
                        print(self.sep)
                    elif choice == 4:
                        print(self.sep)
                        self.add_single_host()
                        print(self.sep)
                    elif choice == 3:
                        print(self.sep)
                        self.custom_host_list(loaded_mods)
                        print(self.sep)
                    elif choice == 2:
                        print(self.sep)
                        query = lib.output.prompt("enter your search query", lowercase=False)
                        self.gather_hosts(query)
                        print(self.sep)
                    elif choice == 1:
                        print(self.sep)
                        self.usage_and_legal()
                    else:
                        lib.output.warning("invalid option provided")
                except ValueError:
                    if not choice == "help":
                        if "help" in choice:
                            try:
                                help_arg = choice.split(" ")
                                self.help(help_arg[-1])
                            except:
                                lib.output.error("choice must be integer not string")
                        else:
                            lib.output.warning("option must be integer not string")
                    elif choice == "help":
                        lib.output.error("must provide an argument for help IE 'help exploit'")

        except KeyboardInterrupt:
            print("\n")
            self.terminal_main_display(loaded_mods)