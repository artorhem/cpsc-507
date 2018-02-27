import json
from safety_db import INSECURE_FULL


class VulnerabilityDB:
    def get_all_vulnerable_functions(self, area="crypto"):
        """
        Parses the .json file containing known vulnerabilities.
        :param area: file name
        :return: parsed dictionary with vulnerabilities
        """
        filename = "data/{area}.json".format(area=area)
        with open(filename) as json_file:
            json_data = json.load(json_file)

        return json_data

    def get_vulnerable_dependency(self, name):
        """
        Returns all information regarding a vulnerable dependency.
        If no information is available then `None` is returned.
        :param name: name of the dependeny
        :return: todo
        """
        if name in INSECURE_FULL:
            return INSECURE_FULL[name]
        else:
            return None
