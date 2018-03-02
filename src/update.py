import pip
from snakefood.util import iter_pyfiles, setup_logging, def_ignores
from snakefood.find import find_imports
import contextlib
import re
from collections import namedtuple
from pkg_resources import parse_version

Dependency = namedtuple("Dependency", ["name", "version", "all_versions"])


# https://stackoverflow.com/questions/35120646/python-programatically-running-pip-list


@contextlib.contextmanager
def capture():
    import sys
    from cStringIO import StringIO
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

    def __detect_installed_dependencies(self):
        """
        Gets the dependencies with versions that are used and installed
        in the path.
        """
        all_symnames = set()
        for fn in iter_pyfiles([self.path], None):
            all_symnames.update(x[0].split('.')[0] for x in find_imports(fn, True, []) if not x[2])

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

    # todo: we need to think about a update strategy
