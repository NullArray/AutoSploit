import os
import base64
import json

import requests

from lib.errors import AutoSploitAPIConnectionError
from lib.output import error
from lib.settings import (
    API_URLS,
    HOST_FILE,
    write_to_file
)


class ZoomEyeAPIHook(object):

    def __init__(self, query):
        self.query = query
        self.host_file = HOST_FILE
        self.user_file = "{}/etc/text_files/users.lst".format(os.getcwd())
        self.pass_file = "{}/etc/text_files/passes.lst".format(os.getcwd())

    @staticmethod
    def __decode(filepath):
        with open(filepath) as f:
            data = f.read()
            token, n = data.split(":")
            for _ in range(int(n.strip())):
                token = base64.b64decode(token)
        return token.strip()

    def __get_auth(self):
        username = self.__decode(self.user_file)
        password = self.__decode(self.pass_file)
        data = {"username": username, "password": password}
        req = requests.post(API_URLS["zoomeye"][0], json=data)
        token = json.loads(req.content)
        return token

    def zoomeye(self):
        discovered_zoomeye_hosts = set()
        try:
            token = self.__get_auth()
            headers = {"Authorization": "JWT {}".format(str(token["access_token"]))}
            params = {"query": self.query, "page": "1", "facet": "ipv4"}
            req = requests.get(API_URLS["zoomeye"][1].format(query=self.query), params=params, headers=headers)
            _json_data = req.json()
            for item in _json_data["matches"]:
                if len(item["ip"]) > 1:
                    # TODO:/ grab all the IP addresses when there's more then 1
                    discovered_zoomeye_hosts.add(str(item["ip"][0]))
                else:
                    discovered_zoomeye_hosts.add(str(item["ip"][0]))
            write_to_file(discovered_zoomeye_hosts, self.host_file)
            return True
        except Exception as e:
            error(AutoSploitAPIConnectionError(str(e)))
            return False

