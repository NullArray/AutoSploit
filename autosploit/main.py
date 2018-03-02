import sys

from lib.cmdline.cmd import AutoSploitParser
from lib.term.terminal import AutoSploitTerminal
from lib.output import (
    info,
    warning,
    error,
    prompt
)
from lib.settings import (
    logo,
    load_api_keys,
    check_services,
    cmdline,
    EXPLOIT_FILES_PATH,
    START_APACHE_PATH,
    START_POSTGRESQL_PATH
)
from lib.jsonize import load_exploits


def main():

    opts = AutoSploitParser().optparser()

    logo()
    info("welcome to autosploit, give us a little bit while we configure")
    info("checking for services")
    # according to ps aux, postgre and apache2 are the names of the services
    service_names = ("postgres", "apache2")
    for service in list(service_names):
        while not check_services(service):
            choice = prompt("it appears that service {} is not enabled, would you like us to enable it for you[y/N]".format(service))
            if choice.lower().startswith("y"):
                if "postgre" in service:
                    cmdline("sudo bash {}".format(START_POSTGRESQL_PATH))
                else:
                    cmdline("sudo bash {}".format(START_APACHE_PATH))
            else:
                error("service {} is required to be started for autosploit to run, exiting".format(service.title()))
                sys.exit(1)
        info("services started successfully")

    if len(sys.argv) > 1:
        info("attempting to load API keys")
        loaded_tokens = load_api_keys()
        AutoSploitParser().parse_provided(opts)
        info("checking if there are multiple exploit files")
        loaded_exploits = load_exploits(EXPLOIT_FILES_PATH)
        AutoSploitParser().single_run_args(opts, loaded_tokens, loaded_exploits)
    else:
        warning("no arguments have been parsed, defaulting to terminal session. press 99 to quit and help to get help")
        info("checking if there are multiple exploit files")
        loaded_exploits = load_exploits(EXPLOIT_FILES_PATH)
        info("attempting to load API keys")
        loaded_tokens = load_api_keys()
        terminal = AutoSploitTerminal(loaded_tokens)
        terminal.terminal_main_display(loaded_exploits)
