# todo

class Updater:
    def __init__(self, path):
        """
        Constructor
        :param path: path to project to be updated locally
        """
        self.path = path
        self.outdated_dependencies = None
        self.__detect_outdated_dependencies()

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

    def __detect_outdated_dependencies(self):
        """
        Checks the dependencies in the path and detects
        the ones that are outdated.
        """
        # self.outdated_dependencies = todo
        pass

    # todo: we need to think about a update strategy
