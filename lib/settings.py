import os
import sys
import time
import socket
import random
import platform
import getpass
import tempfile
import distutils.spawn
from subprocess import (
    PIPE,
    Popen
)

import psutil

import lib.output
import lib.banner

CUR_DIR = "{}".format(os.getcwd())

# path to the file containing all the discovered hosts
HOST_FILE = "{}/hosts.txt".format(CUR_DIR)

# path to the folder containing all the JSON exploit modules
EXPLOIT_FILES_PATH = "{}/etc/json".format(CUR_DIR)

# path to the usage and legal file
USAGE_AND_LEGAL_PATH = "{}/etc/text_files/general".format(CUR_DIR)

# one bash script to rule them all takes an argument via the operating system
START_SERVICES_PATH = "{}/etc/scripts/start_services.sh".format(CUR_DIR)

RC_SCRIPTS_PATH = "{}/autosploit_out/".format(CUR_DIR)

# path to the file that will contain our query
QUERY_FILE_PATH = tempfile.NamedTemporaryFile(delete=False).name

# default HTTP User-Agent
DEFAULT_USER_AGENT = "AutoSploit/{} (Language=Python/{}; Platform={})".format(
    lib.banner.VERSION, sys.version.split(" ")[0], platform.platform().split("-")[0]
)

# the prompt for the platforms
PLATFORM_PROMPT = "\n{}@\033[36mPLATFORM\033[0m$ ".format(getpass.getuser())

# the prompt that will be used most of the time
AUTOSPLOIT_PROMPT = "\n\033[31m{}\033[0m@\033[36mautosploit\033[0m# ".format(getpass.getuser())

# all the paths to the API tokens
API_KEYS = {
    "censys": ("{}/etc/tokens/censys.key".format(CUR_DIR), "{}/etc/tokens/censys.id".format(CUR_DIR)),
    "shodan": ("{}/etc/tokens/shodan.key".format(CUR_DIR), )
}

# all the URLs that we will use while doing the searching
API_URLS = {
    "shodan": "https://api.shodan.io/shodan/host/search?key={token}&query={query}",
    "censys": "https://censys.io/api/v1/search/ipv4",
    "zoomeye": (
        "https://api.zoomeye.org/user/login",
        "https://api.zoomeye.org/web/search"
    )
}

# terminal options
AUTOSPLOIT_TERM_OPTS = {
    1: "usage and legal", 2: "gather hosts", 3: "custom hosts",
    4: "add single host", 5: "view gathered hosts", 6: "exploit gathered hosts",
    99: "quit"
}

stop_animation = False


def validate_ip_addr(provided):
    """
    validate an IP address to see if it is real or not
    """
    not_acceptable = ("0.0.0.0", "127.0.0.1", "255.255.255.255")
    if provided not in not_acceptable:
        try:
            socket.inet_aton(provided)
            return True
        except:
            return False
    return False


def check_services(service_name):
    """
    check to see if certain services ar started
    """
    try:
        all_processes = set()
        for pid in psutil.pids():
            running_proc = psutil.Process(pid)
            all_processes.add(" ".join(running_proc.cmdline()).strip())
        for proc in list(all_processes):
            if service_name in proc:
                return True
        return False
    except psutil.ZombieProcess as e:
        # zombie processes appear to happen on macOS for some reason
        # so we'll just kill them off
        pid = str(e).split("=")[-1].split(")")[0]
        os.kill(int(pid), 0)
        return True


def write_to_file(data_to_write, filename, mode=None):
    """
    write data to a specified file, if it exists, ask to overwrite
    """
    global stop_animation

    if os.path.exists(filename):
        if not mode:
            stop_animation = True
            is_append = lib.output.prompt("would you like to (a)ppend or (o)verwrite the file")
            if is_append.lower() == "o":
                mode = "w"
            elif is_append.lower() == "a":
                mode = "a+"
            else:
                lib.output.error("invalid input provided ('{}'), appending to file".format(is_append))
                lib.output.error("Search results NOT SAVED!")

        if mode == "w":
            lib.output.warning("Overwriting to {}".format(filename))
        if mode == "a":
            lib.output.info("Appending to {}".format(filename))

    else:
        # File does not exists, mode does not matter
        mode = "w"

    with open(filename, mode) as log:
        if isinstance(data_to_write, (tuple, set, list)):
            for item in list(data_to_write):
                log.write("{}{}".format(item.strip(), os.linesep))
        else:
            log.write(data_to_write)
    lib.output.info("successfully wrote info to '{}'".format(filename))
    return filename


def load_api_keys(unattended=False, path="{}/etc/tokens".format(CUR_DIR)):

    """
    load the API keys from their .key files
    """

    # make the directory if it does not exist
    if not os.path.exists(path):
        os.mkdir(path)

    for key in API_KEYS.keys():
        if not os.path.isfile(API_KEYS[key][0]):
            access_token = lib.output.prompt("enter your {} API token".format(key.title()), lowercase=False)
            if key.lower() == "censys":
                identity = lib.output.prompt("enter your {} ID".format(key.title()), lowercase=False)
                with open(API_KEYS[key][1], "a+") as log:
                    log.write(identity)
            with open(API_KEYS[key][0], "a+") as log:
                log.write(access_token.strip())
        else:
            lib.output.info("{} API token loaded from {}".format(key.title(), API_KEYS[key][0]))
    api_tokens = {
        "censys": (open(API_KEYS["censys"][0]).read().rstrip(), open(API_KEYS["censys"][1]).read().rstrip()),
        "shodan": (open(API_KEYS["shodan"][0]).read().rstrip(), )
    }
    return api_tokens


def cmdline(command):
    """
    send the commands through subprocess
    """

    lib.output.info("Executing command '{}'".format(command.strip()))
    split_cmd = [x.strip() for x in command.split(" ") if x]

    sys.stdout.flush()

    proc = Popen(split_cmd, stdout=PIPE, bufsize=1)
    stdout_buff = []
    for stdout_line in iter(proc.stdout.readline, b''):
        stdout_buff += [stdout_line.rstrip()]
        print("(msf)>> {}".format(stdout_line).rstrip())

    return stdout_buff


def check_for_msf():
    """
    check the ENV PATH for msfconsole
    """
    return os.getenv("msfconsole", False) or distutils.spawn.find_executable("msfconsole")


def logo():
    """
    display a random banner from the banner.py file
    """
    print(lib.banner.banner_main())


def animation(text):
    """
    display an animation while working, this will be
    single threaded so that it will not screw with the
    current running process
    """
    global stop_animation
    i = 0
    while not stop_animation:
        """
        if stop_animation is True:
            print("\n")
        """
        temp_text = list(text)
        if i >= len(temp_text):
            i = 0
        temp_text[i] = temp_text[i].upper()
        temp_text = ''.join(temp_text)
        sys.stdout.write("\033[96m\033[1m{}...\r\033[0m".format(temp_text))
        sys.stdout.flush()
        i += 1
        time.sleep(0.1)


def start_animation(text):
    """
    start the animation until stop_animation is False
    """
    global stop_animation

    if not stop_animation:
        import threading

        t = threading.Thread(target=animation, args=(text,))
        t.daemon = True
        t.start()
    else:
        lib.output.misc_info(text)


def close(warning, status=1):
    """
    exit if there's an issue
    """
    lib.output.error(warning)
    sys.exit(status)

def grab_random_agent():
    """
    get a random HTTP User-Agent
    """
    user_agent_path = "{}/etc/text_files/agents.txt"
    with open(user_agent_path.format(CUR_DIR)) as agents:
        return random.choice(agents.readlines()).strip()


def configure_requests(proxy=None, agent=None, rand_agent=False):
    """
    configure the proxy and User-Agent for the requests
    """
    if proxy is not None:
        proxy_dict = {
            "http": proxy,
            "https": proxy,
            "ftp": proxy
        }
        lib.output.misc_info("setting proxy to: '{}'".format(proxy))
    else:
        proxy_dict = None

    if agent is not None:
        header_dict = {
            "User-Agent": agent
        }
        lib.output.misc_info("setting HTTP User-Agent to: '{}'".format(agent))
    elif rand_agent:
        header_dict = {
            "User-Agent": grab_random_agent()
        }
        lib.output.misc_info("setting HTTP User-Agent to: '{}'".format(header_dict["User-Agent"]))
    else:
        header_dict = {
            "User-Agent": DEFAULT_USER_AGENT
        }

    return proxy_dict, header_dict
