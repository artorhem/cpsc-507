import json
from safety_db import INSECURE_FULL

def get_all_vulnerable_functions(area = "crypto"):
    """
    Parses the .json file containing known vulnerabilities.
    :param area: file name
    :return: parsed dictionary with vulnerabilities
    """
    filename = "data/{area}.json".format(area = area)
    with open(filename) as json_file:
        json_data = json.load(json_file)

    return json_data


def get_vulnerable_dependency(name):
    if name in INSECURE_FULL:
        return INSECURE_FULL[name]
    else:
        return None