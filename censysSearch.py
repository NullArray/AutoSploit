#!/usr/bin/env python2.7
import os
import sys
import time
import pickle
import threading

import requests

import autosploit
from lib.settings import PLATFORM_PROMPT
from lib.output import (
    info,
    error,
)


def censysTargets(clobber=True, hostLimit=-1):
    """Function to gather target host(s) from Censys."""
    global query
    global stop_animation
    API_URL = "https://censys.io/api/v1/search/ipv4"
    UID = ""
    SECRET = ""

    print("\033[H\033[J")  # Clear terminal
    autosploit.logo()

    if not os.path.isfile("uid.p"):
        info("Please provide your Censys API ID.")

        UID = raw_input("API ID: ")
        pickle.dump(UID, open("uid.p", "wb"))
        path = os.path.abspath("uid.p")
        info("Your API ID has been saved to {}".format(path))

    else:
        try:
            UID = pickle.load(open("uid.p", "rb"))
        except IOError as e:
            error("Critical. An IO error was raised while attempting to read API data.{}".format(str(e)))

        path = os.path.abspath("uid.p")
        info("Your API ID was loaded from {}".format(path))

    if not os.path.isfile("secret.p"):
        info("Please provide your Censys Secret key.")

        SECRET = raw_input("Secret key: ")
        pickle.dump(UID, open("secret.p", "wb"))
        path = os.path.abspath("secret.p")
        info("Your Secret key has been saved to {}".format(path))

    else:
        try:
            SECRET = pickle.load(open("secret.p", "rb"))
        except IOError as e:
            error("Critical. An IO error was raised while attempting to read Secret key data.{}".format(e))

        path = os.path.abspath("secret.p")
        info("Your Secret key was loaded from {}".format(path))

    info("Please provide your platform specific search query.")
    info("I.E. 'IIS' will return a list of IPs belonging to IIS servers.")

    while True:
        query = raw_input(PLATFORM_PROMPT)
        if query == "":
            error("Query cannot be null.")
        else:
            break
    params = {'query': query}
    info("Please stand by while results are being collected...")
    time.sleep(1)

    try:
        response = requests.post(API_URL, json = params, auth=(UID, SECRET))
    except Exception as e:
        error("Critical. An error was raised with the following error message. '{}'".format(str(e)))

    result = response.json()

    if response.status_code != 200:
        print(result.json()["error"])
        sys.exit(1)

    thread = threading.Thread(target=autosploit.animation, args=("collecting results", ))
    thread.daemon = True
    thread.start()

    # TODO:/
    # edit the clobber function to work properly
    if clobber:
        with open('hosts.txt', 'wb') as log:
            for _ in xrange(autosploit.toolbar_width):
                time.sleep(0.1)
                for service in result['results']:
                    if hostLimit > 0 or hostLimit < 0:
                        log.write("{}{}".format(service['ip'], os.linesep))
                        hostLimit -= 1
                    else:
                        break
            autosploit.hostpath = os.path.abspath("hosts.txt")
            autosploit.stop_animation = True
        info("Done.")
        info("Host list saved to {}".format(autosploit.hostpath))
    else:
        with open("hosts.txt", "ab") as log:
            for i in xrange(autosploit.toolbar_width):
                time.sleep(0.1)
                for service in result['results']:
                    if hostLimit > 0 or hostLimit < 0:
                        log.write("{}{}".format(service['ip'], os.linesep))
                        hostLimit -= 1
                    else:
                        break
            autosploit.hostpath = os.path.abspath("hosts.txt")
            autosploit.stop_animation = True
        info("Done.")
        info("Hosts appended to list at {}".format(autosploit.hostpath))
