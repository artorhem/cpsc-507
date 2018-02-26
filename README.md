[todo]

__@PuneetM__: Make the list of projects that we aim to test the tool against and the testsuites they employ

__@Anna, @Gleb__: Will we test against multiple python versions?

## Installation

+ Download the source code of the tool
+ Install all requirements: `pip install -r requirements.txt`


## Configuration

In order for the tool to access the Github API an API access token needs to be set as environment variable: `export GITHUB_ACCESS_TOKEN=<token>`.

## Usage

To analyze a local repository the path must be provided:

`python cli.py --path "/local/path"`

To analyze a remote repository on github the URL to the repository must be provided:

`python cli.py --url "<URL>"`

To access the github repository the API access token needs to be set (see Configuration).

## Collected Data

For analyzed github repositories metrics will be collected in `/tmp` in `metrics.json`.

## Supported Testing Frameworks
The space of Python testing is very fragmented, and there is not universal method of writing testcases. To make the process simple and extensible, we use the tox test framework, that simplifies the execution of the tests. We look at the standard locations to discover tests, and support the standard testing mechanisms. Here are our assumptions:

+ The tests are placed in the ${project}/test[s] directory

+ The requirements necessary are present in a requirements.txt file. Often developers specify multiple versions of this file. 	We look for all files in the repository that have a name starting with 'requirements' to include for installation in the virtualenv.

+ The supported methods of testing the project are: setup.py with a test recipe, py.tests, nosetests, and plain old unittests.

