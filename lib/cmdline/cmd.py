import os
import sys
import random
import argparse

import lib.output
import lib.jsonize
import lib.settings
import api_calls.censys
import api_calls.shodan
import api_calls.zoomeye
import lib.exploitation.exploiter


class AutoSploitParser(argparse.ArgumentParser):

    def __init__(self):
        super(AutoSploitParser, self).__init__()

    @staticmethod
    def optparser():

        """
        the options function for our parser, it will put everything into play
        """

        parser = argparse.ArgumentParser(
            usage="python autosploit.py -[c|z|s|a] -[q] QUERY\n"
                  "{spacer}[-C] WORKSPACE LHOST LPORT [-e]\n"
                  "{spacer}[--ruby-exec] [--msf-path] PATH [-E] EXPLOIT-FILE-PATH\n"
                  "{spacer}[--rand-agent] [--proxy] PROTO://IP:PORT [-P] AGENT".format(
                    spacer=" " * 28
            )
        )
        se = parser.add_argument_group("search engines", "possible search engines to use")
        se.add_argument("-c", "--censys", action="store_true", dest="searchCensys",
                        help="use censys.io as the search engine to gather hosts")
        se.add_argument("-z", "--zoomeye", action="store_true", dest="searchZoomeye",
                        help="use zoomeye.org as the search engine to gather hosts")
        se.add_argument("-s", "--shodan", action="store_true", dest="searchShodan",
                        help="use shodan.io as the search engine to gather hosts")
        se.add_argument("-a", "--all", action="store_true", dest="searchAll",
                        help="search all available search engines to gather hosts")

        req = parser.add_argument_group("requests", "arguments to edit your requests")
        req.add_argument("--proxy", metavar="PROTO://IP:PORT", dest="proxyConfig",
                         help="run behind a proxy while performing the searches")
        req.add_argument("--random-agent", action="store_true", dest="randomAgent",
                         help="use a random HTTP User-Agent header")
        req.add_argument("-P", "--personal-agent", metavar="USER-AGENT", dest="personalAgent",
                         help="pass a personal User-Agent to use for HTTP requests")
        req.add_argument("-q", "--query", metavar="QUERY", dest="searchQuery",
                         help="pass your search query")

        exploit = parser.add_argument_group("exploits", "arguments to edit your exploits")
        exploit.add_argument("-E", "--exploit-file", metavar="PATH", dest="exploitList",
                             help="provide a text file to convert into JSON and save for later use")
        exploit.add_argument("-C", "--config", nargs=3, metavar=("WORKSPACE", "LHOST", "LPORT"), dest="msfConfig",
                             help="set the configuration for MSF (IE -C default 127.0.0.1 8080)")
        exploit.add_argument("-e", "--exploit", action="store_true", dest="startExploit",
                             help="start exploiting the already gathered hosts")

        misc = parser.add_argument_group("misc arguments", "arguments that don't fit anywhere else")
        misc.add_argument("--ruby-exec", action="store_true", dest="rubyExecutableNeeded",
                          help="if you need to run the Ruby executable with MSF use this")
        misc.add_argument("--msf-path", metavar="MSF-PATH", dest="pathToFramework",
                          help="pass the path to your framework if it is not in your ENV PATH")
        misc.add_argument("--ethics", action="store_true", dest="displayEthics",
                          help=argparse.SUPPRESS)  # easter egg!
        opts = parser.parse_args()
        return opts

    @staticmethod
    def parse_provided(opt):
        """
        parse the provided arguments to make sure that they are all compatible with one another
        """
        parser = any([opt.searchAll, opt.searchZoomeye, opt.searchCensys, opt.searchShodan])

        if opt.rubyExecutableNeeded and opt.pathToFramework is None:
            lib.settings.close("if the Ruby exec is needed, so is that path to metasploit, pass the `--msf-path` switch")
        if opt.pathToFramework is not None and not opt.rubyExecutableNeeded:
            lib.settings.close(
                "if you need the metasploit path, you also need the executable. pass the `--ruby-exec` switch"
            )
        if opt.personalAgent is not None and opt.randomAgent:
            lib.settings.close("you cannot use both a personal agent and a random agent, choose only one")
        if parser and opt.searchQuery is None:
            lib.settings.close("must provide a search query with the `-q/--query` switch")
        if not parser and opt.searchQuery is not None:
            lib.settings.close(
                "you provided a query and no search engine, choose one with `-s/--shodan/-z/--zoomeye/-c/--censys` "
                "or all with `-a/--all`"
            )
        if opt.startExploit and opt.msfConfig is None:
            lib.settings.close(
                "you must provide the configuration for metasploit in order to start the exploits "
                "do so by passing the `-C\--config` switch IE -C default 127.0.0.1 8080"
            )
        if not opt.startExploit and opt.msfConfig is not None:
            lib.settings.close(
                "you have provided configuration without attempting to exploit, you must pass the "
                "`-e/--exploit` switch to start exploiting"
            )

    @staticmethod
    def single_run_args(opt, keys, loaded_modules):
        """
        run the arguments provided
        """
        api_searches = (
            api_calls.zoomeye.ZoomEyeAPIHook,
            api_calls.shodan.ShodanAPIHook,
            api_calls.censys.CensysAPIHook
        )
        headers = lib.settings.configure_requests(
            proxy=opt.proxyConfig, agent=opt.personalAgent, rand_agent=opt.randomAgent
        )
        single_search_msg = "using {} as the search engine"

        if opt.displayEthics:
            ethics_file = "{}/etc/text_files/ethics.lst".format(os.getcwd())
            with open(ethics_file) as ethics:
                ethic = random.choice(ethics.readlines()).strip()
                lib.settings.close("Here we have an ethical lesson for you:\n\n{}".format(ethic))
        if opt.exploitList:
            try:
                lib.output.info("converting {} to JSON format".format(opt.exploitList))
                done = lib.jsonize.text_file_to_dict(opt.exploitList)
                lib.output.info("converted successfully and saved under {}".format(done))
            except IOError as e:
                lib.output.error("caught IOError '{}' check the file path and try again".format(str(e)))
            sys.exit(0)

        if opt.searchCensys:
            lib.output.info(single_search_msg.format("Censys"))
            api_searches[2](
                keys["censys"][1], keys["censys"][0],
                opt.searchQuery, proxy=headers[0], agent=headers[1]
            ).censys()
        if opt.searchZoomeye:
            lib.output.info(single_search_msg.format("Zoomeye"))
            api_searches[0](
                opt.searchQuery, proxy=headers[0], agent=headers[1]
            ).zoomeye()
        if opt.searchShodan:
            lib.output.info(single_search_msg.format("Shodan"))
            api_searches[1](
                keys["shodan"][0], opt.searchQuery, proxy=headers[0], agent=headers[1]
            ).shodan()
        if opt.searchAll:
            lib.output.info("searching all search engines in order")
            api_searches[0](
                opt.searchQuery, proxy=headers[0], agent=headers[1]
            ).zoomeye()
            api_searches[1](
                keys["shodan"][0], opt.searchQuery, proxy=headers[0], agent=headers[1]
            ).shodan()
            api_searches[2](
                keys["censys"][1], keys["censys"][0], opt.searchQuery, proxy=headers[0], agent=headers[1]
            ).censys()
        if opt.startExploit:
            lib.exploitation.exploiter.AutoSploitExploiter(
                opt.msfConfig,
                loaded_modules,
                open(lib.settings.HOST_FILE).readlines(),
                ruby_exec=opt.rubyExecutableNeeded,
                msf_path=opt.pathToFramework
            ).start_exploit()
