import pip
from findimports import find_imports
import contextlib
import re, sys, os
from collections import namedtuple
from pkg_resources import parse_version

Dependency = namedtuple("Dependency", ["name", "version", "all_versions"])


# https://stackoverflow.com/questions/35120646/python-programatically-running-pip-list


@contextlib.contextmanager
def capture():
    import sys
    from io import StringIO
    oldout, olderr = sys.stdout, sys.stderr
    try:
        out = [StringIO(), StringIO()]
        sys.stdout, sys.stderr = out
        yield out
    finally:
        sys.stdout, sys.stderr = oldout, olderr
        out[0] = out[0].getvalue()
        out[1] = out[1].getvalue()


class Updater:
    def __init__(self, path):
        """
        Constructor
        :param path: path to project to be updated locally
        """
        self.path = path
        self.installed_dependencies = []
        self.outdated_dependencies = []
        self.__detect_installed_dependencies()
        self.__detect_outdated_dependencies()

    def update_all(self):
        """
        Perform the update for all dependencies in the project.
        """
        for dependency in self.outdated_dependencies:
            self.outdated_dependency(dependency)

    def update_dependency(self, dependency, version=None):
        """
        Perform the update for a specific dependency
        :param dependency: name of the dependency to be updated
        :param version: specific version dependency should be updated to
        if version is `None` then the latest version will be used
        """
        if version:
            pip.main(['install --upgrade', str(dependency.name) + '==' + str(version)])
        else:
            # if version is None then automatically the newest version is installed
            pip.main(['install --upgrade', str(dependency.name)])

    def __detect_installed_dependencies(self):
        """
        Gets the dependencies with versions that are used and installed
        in the path.
        """
        all_symnames = set()
        for root, dirs, files in os.walk(self.path):
            for file in files:
                # only analyze python files
                if file.endswith(".py"):
                    file_path = os.path.join(root, file)
                    all_symnames.update(x.name.split('.')[0] for x in find_imports(file_path))

        packages = pip.utils.get_installed_distributions()

        for package in packages:
            for dependency in all_symnames:
                if package.project_name == dependency:
                    self.installed_dependencies.append(Dependency(
                        package.project_name,
                        package.version,
                        []
                    ))

    def __detect_outdated_dependencies(self):
        """
        Checks the dependencies in the path and detects
        the ones that are outdated.
        """
        p = re.compile(".*\(from versions: (.*)\).*")

        for dependency in self.installed_dependencies:
            with capture() as out:
                pip.main(['install', dependency.name + '==random'])

            available_versions = p.match(str(out)).group(1).split(', ')

            for version in available_versions:
                if parse_version(version) > parse_version(dependency.version):
                    self.outdated_dependencies.append(Dependency(
                        dependency.name,
                        dependency.version,
                        available_versions
                    ))
                    break
