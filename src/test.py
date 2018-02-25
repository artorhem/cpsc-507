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
    TODO:Make the list of projects that we aim to test the tool against and the testsuites they employ
    TODO: Will we test against multiple python versions? <- @Anna, @Gleb?
"""
import ConfigParser
import pytest
import tox
import os
import re
import mock
from sys import path
import logging
from pythonjsonlogger import jsonlogger


class TestInfo:
    # TODO:Setup logging. too. lazy. :(
    def __init__(self, path):
        """
        Creates a new TestInfo instance.
        :param path to the repository under analysis
        """
        self.path = path
        self.testDir = self.find_testdir()
        self.requirementFiles = self.find_requirements_file()  # Array of all files that match the requirements[-\w] regex
        self.testRunner = None  # Hash -> <TestRunner,TestDir>
        self.toxPath = self.findToxIni()  # path to the original tox file, or the created tox file
        self.cfgPath = None  # path to the setup.cfg file, None if absent
        self.supportedPythons = None  # Array

    def find_requirements_file(self):
        reqfiles = []
        for dirpath, dirs, files in os.walk(self.path):
            for file in files:
                if re.match('^requirements[-\w]*.txt', file):
                    reqfiles.append(os.path.join(dirpath, file))
        return (reqfiles)

    def find_testdir(self):
        '''
        finds the directory where tests are placed, and returns a hash containing the locations found by looking at multiple sources.
        :return: as of now, the hash : {basepath:<rootdir for repo>,'walkthrough':<dirname>,'setuptools:<dirname>

        '''
        testdirInfo = {}
        for dirpath, dirs, files in os.walk(self.path):
            for directory in dirs:
                if (re.match('^test[s]$', directory)):
                    testdirInfo['basepath'] = self.path
                    testdirInfo['walkthrough'] = directory

        '''
        
        Now we look at the information in the setup.py file to corroborate
         if a test directory exists there. If it does, then we can use
         `python setup.py test` to run the tests. 
        '''

        import setuptools
        path.append(self.path)
        try:
            with mock.patch.object(setuptools, 'setup') as mock_setup:
                import setup
            args, kwargs = mock_setup.call_args
            testdirInfo['setuptools'] = kwargs.get('test_suite', [])
        except Exception as e:
            print("The setup.py was not found. Skipping.")
        return testdirInfo

    '''
    This function locates the tox.ini file. 
    '''

    def findToxIni(self):
        for dirpath, dirs, files in os.walk(self.path):
            for file in files:
                if (re.match('^tox.ini$', file)):
                    return ['dirpath', file]
        print("No tox.ini file was found. Revelio will create one now at " + self.path)

    '''The function testRunners() identifies the test framework used, and the command needed to execute the tests'''

    def testRunners(self):
        pass

    '''
    This following is a placeholder function which might not be needed. It reads the setup.cfg file. 
    Another function will be created to write the cfg file -- again if needed. TBD. 
    '''

    def cfgPath(selfself):
        pass
