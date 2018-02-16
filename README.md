[todo]


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