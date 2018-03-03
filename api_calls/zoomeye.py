from api_calls.api_hook import *

import os
import base64

class ZoomEyeAPIHook(ApiHook):

    """
    API hook for the ZoomEye API, in order to connect you need to provide a phone number
    so we're going to use some 'lifted' credentials to login for us
    """

    def __init__(self, query=None, proxy=None, agent=None, *args):
        ApiHook.__init__(self, query, proxy, agent)
        self.request_method = requests.get;

        cur_dir = os.getcwd();
        self.user_file = "{}/etc/text_files/users.lst".format(cur_dir)
        self.pass_file = "{}/etc/text_files/passes.lst".format(cur_dir)

    @staticmethod
    def __decode(filepath):
        """
        we all know what this does
        """
        with open(filepath) as f:
            data = f.read()
            token, n = data.split(":")
            for _ in range(int(n.strip())):
                token = base64.b64decode(token)
        return token.strip()

    def __get_auth(self):
        """
        get the authorization for the authentication token, you have to login
        before you can access the API, this is where the 'lifted' creds come into
        play.
        """
        username = self.__decode(self.user_file)
        password = self.__decode(self.pass_file)
        data = {"username": username, "password": password}
        req = requests.post(API_URLS["zoomeye"][0], json=data)
        token = json.loads(req.content)
        return token
    
    def sent_request(self):
        lib.settings.start_animation("searching ZoomEye with given query '{}'".format(self.query))
        token = self.__get_auth()
        if self.user_agent is None:
            headers = {"Authorization": "JWT {}".format(str(token["access_token"]))}
        else:
            headers = {
                "Authorization": "JWT {}".format(str(token["access_token"])),
                "agent": self.user_agent["User-Agent"]
            }
        params = {"query": self.query, "page": "1", "facet": "ipv4"}
        return ApiHook.sent_request(self, API_URLS["zoomeye"],None,params, headers)

    def parse_response(self, resp):
        _json_data = resp.json()
        for item in _json_data["matches"]:
            if len(item["ip"]) > 1:
                for ip in item["ip"]:
                    discovered_zoomeye_hosts.add(ip)
            else:
                discovered_zoomeye_hosts.add(str(item["ip"][0]))
        write_to_file(discovered_zoomeye_hosts, self.host_file)
        return True
 
    def pull_ip(self):
        self.parse_response(self.sent_request())
