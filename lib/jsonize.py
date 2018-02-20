import os
import json
import string
import random


import blessings

t = blessings.Terminal()


def random_file_name(acceptable=string.ascii_letters, length=7):
    """
    create a random filename.

     `note: this could potentially cause issues if there
           a lot of file in the directory`
    """
    retval = set()
    for _ in range(length):
        retval.add(random.choice(acceptable))
    return ''.join(list(retval))


def load_exploits(path, node="exploits"):
    """
    load exploits from a given path, depending on how many files are loaded into
    the beginning `file_list` variable it will display a list of them and prompt
    or just select the one in the list
    """
    retval = []
    file_list = os.listdir(path)
    if len(file_list) != 1:
        print("\n[{}] total of {} files discovered select one".format(
                t.green("+"), len(file_list)))
        for i, f in enumerate(file_list, start=1):
            print("{}. {}".format(i, f[:-5]))
        action = raw_input("\n<" + t.cyan("AUTOSPLOIT") + ">$ ")
        selected_file = file_list[int(action) - 1]
    else:
        selected_file = file_list[0]

    selected_file_path = os.path.join(path, selected_file)

    with open(selected_file_path) as exploit_file:
        # loading it like this has been known to cause Unicode issues later on down
        # the road
        _json = json.loads(exploit_file.read())
        for item in _json[node]:
            # so we'll reload it into a ascii string before we save it into the file
            retval.append(str(item))
    return retval


def text_file_to_dict(path):
    """
    take a text file path, and load all of the information into a `dict`
    send that `dict` into a JSON format and save it into a file. it will
    use the same start node (`exploits`) as the `default_modules.json`
    file so that we can just use one node instead of multiple when parsing
    """
    start_dict = {"exploits": []}
    with open(path) as exploits:
        for exploit in exploits.readlines():
            # load everything into the dict
            start_dict["exploits"].append(exploit.strip())
    filename_path = "{}/etc/json/{}.json".format(os.getcwd(), random_file_name())
    with open(filename_path, "a+") as exploits:
        # sort and indent to make it look pretty
        _data = json.dumps(start_dict, indent=4, sort_keys=True)
        exploits.write(_data)
    return filename_path

