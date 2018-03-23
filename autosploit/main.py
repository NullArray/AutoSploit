import sys
import psutil
import platform

from lib.cmdline.cmd import AutoSploitParser
from lib.term.terminal import AutoSploitTerminal
from lib.output import (
    info,
    warning,
    error,
    prompt,
    misc_info
)
from lib.settings import (
    logo,
    load_api_keys,
    check_services,
    cmdline,
    EXPLOIT_FILES_PATH,
    START_APACHE_PATH,
    START_POSTGRESQL_PATH,
    START_POSTGRESQL_OSX_PATH
)
from lib.jsonize import load_exploits


def main():

    opts = AutoSploitParser().optparser()

    logo()
    info("welcome to autosploit, give us a little bit while we configure")
    misc_info("checking for disabled services")
    # according to ps aux, postgre and apache2 are the names of the services

    if platform.system() == "Darwin":
        service_names = ("postgres","httpd")
    elif platform.system() == "Linux":
        service_names = ("postgres", "apache2")

    for service in list(service_names):
        while not check_services(service):
            choice = prompt(
                "it appears that service {} is not enabled, would you like us to enable it for you[y/N]".format(
                    service.title()
                )
            )
            if choice.lower().startswith("y"):
                try:
                    if "postgre" in service:
                        if platform.system() == "Linux":
                            cmdline("sudo bash {}".format(START_POSTGRESQL_PATH))
                        elif platform.system() == "Darwin":
                            #cmdline("sudo bash {}".format(START_POSTGRESQL_OSX_PATH))
                            cmdline("brew services start postgresql")
                        else:
                            error("Currently not supporting windows")
                            sys.exit(1)
                    else:
                        if platform.system() == "Linux":
                            cmdline("sudo bash {}".format(START_APACHE_PATH))
                        elif platform.system() == "Darwin":
                            cmdline("sudo apachectl start")
                        else:
                            error("Currently not supporting windows")
                            sys.exit(1)

                    # moving this back because it was funky to see it each run
                    info("services started successfully")
                # this tends to show up when trying to start the services
                # I'm not entirely sure why, but this fixes it
                except psutil.NoSuchProcess:
                    pass
            else:
                error(
                    "service {} is required to be started for autosploit to run successfully (you can do it manually "
                    "by using the command `sudo service {} start`), exiting".format(
                        service.title(), service
                    )
                )
                sys.exit(1)

    if len(sys.argv) > 1:
        info("attempting to load API keys")
        loaded_tokens = load_api_keys()
        AutoSploitParser().parse_provided(opts)
        misc_info("checking if there are multiple exploit files")
        loaded_exploits = load_exploits(EXPLOIT_FILES_PATH)
        AutoSploitParser().single_run_args(opts, loaded_tokens, loaded_exploits)
    else:
        warning("no arguments have been parsed, defaulting to terminal session. press 99 to quit and help to get help")
        misc_info("checking if there are multiple exploit files")
        loaded_exploits = load_exploits(EXPLOIT_FILES_PATH)
        info("attempting to load API keys")
        loaded_tokens = load_api_keys()
        terminal = AutoSploitTerminal(loaded_tokens)
        terminal.terminal_main_display(loaded_exploits)
