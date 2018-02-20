import json


def get_all_vulnerable_functions(area = "crypto"):
    """
    Parses the .json file containing known vulnerabilities.
    :param area: file name
    :return: parsed dictionary with vulnerabilities
    """
    filename = "vulnerable_dependencies/{area}.json".format(area = area)
    with open(filename) as json_file:
        json_data = json.load(json_file)

    return json_data
