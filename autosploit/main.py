import os
import sys
import ctypes
import psutil
import platform

from lib.cmdline.cmd import AutoSploitParser
from lib.term.terminal import AutoSploitTerminal
from lib.output import (
    info,
    warning,
    prompt,
    misc_info
)
from lib.settings import (
    logo,
    load_api_keys,
    check_services,
    cmdline,
    close,
    EXPLOIT_FILES_PATH,
    START_SERVICES_PATH
)
from lib.jsonize import (
    load_exploits,
    load_exploit_file
)


def main():

    try:
        is_admin = os.getuid() == 0
    except AttributeError:
        # we'll make it cross platform because it seems like a cool idea
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0

    if not is_admin:
        close("must have admin privileges to run")

    opts = AutoSploitParser().optparser()

    logo()
    info("welcome to autosploit, give us a little bit while we configure")
    misc_info("checking your running platform")
    platform_running = platform.system()
    misc_info("checking for disabled services")
    # according to ps aux, postgre and apache2 are the names of the services on Linux systems
    service_names = ("postgres", "apache2")
    if "darwin" in platform_running.lower():
        service_names = ("postgres", "apachectl")

    for service in list(service_names):
        while not check_services(service):
            choice = prompt(
                "it appears that service {} is not enabled, would you like us to enable it for you[y/N]".format(
                    service.title()
                )
            )
            if choice.lower().startswith("y"):
                try:
                    if "darwin" in platform_running.lower():
                        cmdline("{} darwin".format(START_SERVICES_PATH))
                    elif "linux" in platform_running.lower():
                        cmdline("{} linux".format(START_SERVICES_PATH))
                    else:
                        close("your platform is not supported by AutoSploit at this time", status=2)

                    # moving this back because it was funky to see it each run
                    info("services started successfully")
                # this tends to show up when trying to start the services
                # I'm not entirely sure why, but this fixes it
                except psutil.NoSuchProcess:
                    pass
            else:
                process_start_command = "`sudo service {} start`"
                if "darwin" in platform_running.lower():
                    process_start_command = "`brew services start {}`"
                close(
                    "service {} is required to be started for autosploit to run successfully (you can do it manually "
                    "by using the command {}), exiting".format(
                        service.title(), process_start_command.format(service)
                    )
                )

    if len(sys.argv) > 1:
        info("attempting to load API keys")
        loaded_tokens = load_api_keys()
        AutoSploitParser().parse_provided(opts)

        if not opts.exploitFile:
            misc_info("checking if there are multiple exploit files")
            loaded_exploits = load_exploits(EXPLOIT_FILES_PATH)
        else:
            loaded_exploits = load_exploit_file(opts.exploitFile)
            misc_info("Loaded {} exploits from {}.".format(
                len(loaded_exploits),
                opts.exploitFile))

        AutoSploitParser().single_run_args(opts, loaded_tokens, loaded_exploits)
    else:
        warning("no arguments have been parsed, defaulting to terminal session. press 99 to quit and help to get help")
        misc_info("checking if there are multiple exploit files")
        loaded_exploits = load_exploits(EXPLOIT_FILES_PATH)
        info("attempting to load API keys")
        loaded_tokens = load_api_keys()
        terminal = AutoSploitTerminal(loaded_tokens)
        terminal.terminal_main_display(loaded_exploits)
