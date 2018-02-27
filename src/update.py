# todo

class Updater:
    def __init__(self, path):
        """
        Constructor
        :param path: path to project to be updated locally
        """
        self.path = path

    def update_all(self):
        """
        Perform the update for all dependencies in the project.
        """
        # todo
        pass

    def update_dependency(self, dependency, version=None):
        """
        Perform the update for a specific dependency
        :param dependency: name of the dependency to be updated
        :param version: specific version dependency should be updated to
        if version is `None` then the latest version will be used
        """
        # todo
        pass

    # todo: we need to think about a update strategy
