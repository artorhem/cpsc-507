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
    TODO: Create functions that
"""
import ConfigParser
import pytest
import tox
import os
import re
import mock

class TestInfo:

    def __init__(self,path):
        """
        Creates a new TestInfo instance.
        :param path to the repository under analysis
        """
        self.path = path
        self.testDir = self.find_testdir(self.path)
        self.requirementFiles = self.find_requirements_file(self.path) #Array of all files that match the requirements[-\w] regex
        self.testRunner = None #Hash -> <TestRunner,TestDir>
        self.toxPath = None #path to the original tox file, or the created tox file
        self.cfgPath = None #path to the setup.cfg file, None if absent
        self.supportedPythons = None #Array

    def find_requirements_file(self, path):
        reqfiles = []
        for dirpath,dirs,files in os.walk(path):
            for file in files:
                if re.match('^requirements[-\w]*.txt', file):
                    reqfiles.append(os.path.join(dirpath,file))
        return(reqfiles)


    def find_testdir(self,path):

        testdirInfo = {}
        testdirInfo['basepath'] = path
        for dirpath,dirs,files in os.walk(path):
            for directory in dirs:
                if(re.match('^test[s]$',directory)):
                    testdirInfo['walkthrough'] = directory

        '''
        
        Now we look at the information in the setup.py file to corroborate
         if a test directory exists there. If it does, then we can use
         `python setup.py test` to run the tests. 
        '''
    
        import setuptools
        os.chdir(path)
        with mock.patch.object(setuptools, 'setup') as mock_setup:
            import setup
        args, kwargs = mock_setup.call_args
        testdirInfo['setuptools'] = kwargs.get('test_suite', [])

        return testdirInfo
