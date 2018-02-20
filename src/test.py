"""
    This script does the following things:
    1. It parses the project repo for the test subdirectories. Most
    projects have a few standard areas where they keep their tests.
    The plan is to first look at those locations and then identify
    the testing framework is being used.

    2. Create the virtualenv for the project. INstall the deps there,
    and run the test in a manner consistent with the framework being
    used by the project.

    3. Store the log of the test run in a consistent format that is
    consistent despite the choice of testing framework.

"""

import ConfigParser
import pytest
import tox
