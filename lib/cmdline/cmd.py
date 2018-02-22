import os
import sys
import random
import argparse

import lib.jsonize
import lib.output


class AutoSploitParser(argparse.ArgumentParser):

    def __init__(self):
        super(AutoSploitParser, self).__init__()

    @staticmethod
    def optparser():
        parser = argparse.ArgumentParser()
        parser.add_argument("-c", "--censys", action="store_true", dest="searchCensys",
                            help="use censys.io as the search engine instead of shodan.io to gather hosts")
        parser.add_argument("-b", "--both", action="store_true", dest="searchBoth",
                            help="search both shodan.io and censys.io for hosts")
        parser.add_argument("--proxy", metavar="PROTO://IP:PORT", dest="proxyConfig",
                            help="run behind a proxy while performing the searches")
        parser.add_argument("-e", "--exploit-file", metavar="PATH", dest="exploitList",
                            help="provide a text file to convert into JSON and save for later use")
        parser.add_argument("-E", "--exploit", metavar="EXPLOIT", dest="singleExploit",
                            help="pass a single exploit in the same format as the JSON file(s)")
        parser.add_argument("--ethics", action="store_true", dest="displayEthics",
                            help=argparse.SUPPRESS)  # easter egg!
        opts = parser.parse_args()
        return opts

    @staticmethod
    def single_run_args(opt):
        if opt.displayEthics:
            ethics_file = "{}/etc/text_files/ethics.lst".format(os.getcwd())
            with open(ethics_file) as ethics:
                ethic = random.choice(ethics.readlines()).strip()
                print("Your ethic for the day:\n\n{}".format(ethic))
                sys.exit(0)
        if opt.exploitList:
            try:
                lib.output.info("converting {} to JSON format".format(opt.exploitList))
                done = lib.jsonize.text_file_to_dict(opt.exploitList)
                lib.output.info("converted successfully and saved under {}".format(done))
            except IOError as e:
                lib.output.error("caught IOError '{}' check the file path and try again".format(str(e)))
            sys.exit(0)