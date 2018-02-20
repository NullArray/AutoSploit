import os
import base64

import lib.jsonize

# Global vars
QUERY = ""
WORKSPACE = ""
LOCAL_PORT = ""
LOCAL_HOST = ""
CONFIGURED = False
TOOLBAR_WIDTH = 60
VERSION = "1.4.0"
USAGE_AND_LEGAL_PATH = "{}/etc/general".format(os.getcwd())
LOADED_EXPLOITS = lib.jsonize.load_exploits("{}/etc/json".format(os.getcwd()))
API_PATH = "{}/etc/auth/shodan_auth".format(os.getcwd())
AUTOSPLOIT_OPTS = {
    1: "usage and legal", 2: "gather hosts", 3: "custom hosts",
    4: "add single host", 5: "view gathered hosts", 6: "exploit gathered hosts",
    99: "quit"
}


def get_token(path):
    with open(path) as data:
        encoded = data.read()
        token, n = encoded.split(":")
        for _ in range(int(n)):
            token = base64.b64decode(token)
    return token