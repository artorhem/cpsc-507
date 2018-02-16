import json

def get_vulnerable_functions(area="crypto"):
    filename = "vulnerable_dependencies/{area}.json".format(area=area)
    with open(filename) as json_file:
     json_data = json.load(json_file)

    return json_data
