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
    TODO: check if the project has a travis.yml file. That information is usable by tox.
"""
import configparser
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
        self.cfgPath = None  # path to the setup.cfg file, None if absent
        self.supportedPythons = self.findPyVersions()  # Array
        self.constraintsFile = self.find_constraints_file()
        self.toxPath = self.findToxIni()  # path to the original tox file, or the created tox file

    def find_requirements_file(self):
        reqfiles = []
        for dirpath, dirs, files in os.walk(self.path,topdown=False):
            for file in files:
                if re.match('^requirements[-\w]*.txt', file):
                    reqfiles.append(os.path.join(dirpath, file))
        return (reqfiles)

    def find_constraints_file(self):
        reqfiles = []
        for dirpath, dirs, files in os.walk(self.path):
            for file in files:
                if re.match('[\w]*constraints[-\w]*.txt', file):
                    reqfiles.append(os.path.join(dirpath, file))
        if len(reqfiles) == 0 :
            return None
        return reqfiles

    def find_testdir(self):
        '''
        finds the directory where tests are placed, and returns a hash containing the locations found by looking at multiple sources.
        :return: as of now, the hash : {basepath:<rootdir for repo>,'walkthrough':<dirname>,'setuptools:<dirname>

        '''
        testdirInfo = {}
        for dirpath, dirs, files in os.walk(self.path,topdown=True):
            for directory in dirs:
                
                if (re.match('^test[s]$', directory)):
                    testdirInfo['basepath'] = self.path
                    testdirInfo['walkthrough'] = directory
                    break
        print testdirInfo

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
            print(str(e))
        return testdirInfo

    '''
    This function locates the tox.ini file. 
    '''

    def findToxIni(self):
        for dirpath, dirs, files in os.walk(self.path):
            for file in files:
                if (re.match('^tox.ini$', file)):
                    return [dirpath, file]
        print("No tox.ini file was found. Revelio will create one now at " + self.path)
        self.createToxIni()

    '''The function testRunners() identifies the test framework used, and the command needed to execute the tests'''

    def createToxIni(self):
        '''
        There is no reliable way of determining what test framework is used by a project
        In the absence of such information, we resort to using pytests and hoping that it is able to
        find the tests and work its magic.
        I have spent time to see if nose and pytests give similar results, and to the best of my understanding, they do.


        This function accepts no input. It fills in the relevant portions in the tox template file, and saves it in the
        repo basepath.
        '''
        config = configparser.ConfigParser()
        config.readfp(open('tox_template.ini'))
        envString = ", ".join(self.supportedPythons)
        config.set('tox','envlist',envString)
        with open(os.path.join(self.path,'tox.ini'),'wb') as configfile:
            config.write(configfile)



    def findPyVersions(self):
        setupfile = os.path.join(self.path,'setup.py')
        env =[]

        if os.path.exists(setupfile):
            filehandle = open(setupfile,'r')
            lines = filehandle.readlines()
            pattern = re.compile("::\s(\d).(\d)")
            for line in lines:
                found = pattern.findall(line)
                if found:
                    joiner =''
                    env.append('py'+joiner.join(found[0]))
        else:
            #In the event we don't explicitly find a version list,
            #we force create one. Suck on that!
            env = ['py27','py26','py32','py33','py35','py36']
        
        return env


    def runToxTest(self):
        os.chdir(self.path)
        from tox.__main__ import main
        main()
        #tox.cmdline()