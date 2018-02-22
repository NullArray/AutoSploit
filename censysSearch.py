#!/usr/bin/env python2.7
import os
import sys
import time
import pickle
import threading
import subprocess
import json
import requests
import autosploit
from blessings import Terminal

t = Terminal()

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
        print("[{}]Please provide your Censys API ID.".format(t.green("+")))

        UID = raw_input("API ID: ")
        pickle.dump(UID, open("uid.p", "wb"))
        path = os.path.abspath("uid.p")
        print("[{}]\nYour API ID has been saved to {}".format(t.green("+"), path))

    else:
        try:
            UID = pickle.load(open("uid.p", "rb"))
        except IOError as e:
            print("\n[{}]Critical. An IO error was raised while attempting to read API data.\n{}".format(
                t.red("!"), e))

        path = os.path.abspath("uid.p")
        print("\n[{}]Your API ID was loaded from {}".format(t.green("+"), path))

    if not os.path.isfile("secret.p"):
        print("[{}]Please provide your Censys Secret key.".format(t.green("+")))

        SECRET = raw_input("Secret key: ")
        pickle.dump(UID, open("secret.p", "wb"))
        path = os.path.abspath("secret.p")
        print("[{}]\nYour Secret key has been saved to {}".format(t.green("+"), path))

    else:
        try:
            SECRET = pickle.load(open("secret.p", "rb"))
        except IOError as e:
            print("\n[{}]Critical. An IO error was raised while attempting to read Secret key data.\n{}".format(
                t.red("!"), e))

        path = os.path.abspath("secret.p")
        print("\n[{}]Your Secret key was loaded from {}".format(t.green("+"), path))

    print("[{}]Please provide your platform specific search query.".format(t.green("+")))
    print("[{}]I.E. 'IIS' will return a list of IPs belonging to IIS servers.".format(
    t.green("+")))

    while True:
        query = raw_input("\n<" + t.cyan("PLATFORM") + ">$ ")
        if query == "":
            print("[{}]Query cannot be null.".format(t.red("!")))
        else:
            break
    params = {'query' : query}
    print("[{}]Please stand by while results are being collected...\n\n\n".format(
        t.green("+")))
    time.sleep(1)

    try:
        response = requests.post(API_URL, json = params, auth=(UID, SECRET))
    except Exception as e:
        print("\n[{}]Critical. An error was raised with the following error message.\n".format(t.red("!")))

    if response.status_code != 200:
        print(result.json()["error"])
        sys.exit(1)

    result = response.json()

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
        print("\n\n\n[{}]Done.".format(t.green("+")))
        print("[{}]Host list saved to {}".format(t.green("+"), autosploit.hostpath))
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
        print("\n\n\n[{}]Done.".format(t.green("+")))
        print("[{}]Hosts appended to list at ".format(t.green("+"), autosploit.hostpath))
