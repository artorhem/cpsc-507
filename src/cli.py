import click
from vulnerability_analysis import VulnerabilityAnalyzer
from github_repo_handler import GithubRepoHandler
from update import Updater
import uuid
from report import Report
import logging
from pythonjsonlogger import jsonlogger
from test import TestInfo 
import shutil
import sys

@click.command()
@click.option('--url', help='URL to a github repository')
@click.option('--path', help='Path to a local project directory')
@click.option('--replace', is_flag=True, default=False, help='Automatically replace vulnerabilities')
@click.option('--push', is_flag=True, default=False, help='Automatically creates pull-request with changes')
@click.option('--html', help='Create html report in provided file')
def main(url, path, replace, push, html):
    """
    Start vulnerability analysis using command line tool.
    :param url: URL to a github repository
    :param path: path to a locally stored project
    :param replace: flag of whether detected vulnerabilities
    should be automatically replaced with safe alternative
    :param push: flag indicating whether pull-request should
    automatically be created
    :param html: path to html file which will contain report
    """
    # analyze source code of provided project
    print("Start analysis")

    # setup logging
    logger = logging.getLogger()
    logHandler = logging.FileHandler('/home/metrics.json')
    logger.addHandler(logHandler)
    formatter = jsonlogger.JsonFormatter()
    logHandler.setFormatter(formatter)
    logger.setLevel(logging.INFO)

    # store remote repo locally in /tmp
    local_repo_path = '/tmp/' + str(uuid.uuid4())
    gh_handler = None

    if url:
        # download remote repo
        gh_handler = GithubRepoHandler(url)
        gh_handler.download_repository(local_repo_path)
        gh_handler.get_repository_metrics()
    elif path:
        # analyze local repo
        local_repo_path = path

    updater = None

    try:
        updater = Updater(local_repo_path)
    except:
        print("Cannot update due to error")


    vulnerability_analyzer = VulnerabilityAnalyzer(local_repo_path)

    try:
        # check for vulnerable functions and vulnerable dependencies
        vulnerability_analyzer.analyze()
    except:
        print("Python AST cannot be parsed. Terminating analysis")

        if url:
            logger.info(url, extra={'analysis_failed': True})

        sys.exit(1)

    vulnerable_functions = vulnerability_analyzer.detected_vulnerable_functions
    vulnerable_imports = vulnerability_analyzer.detected_vulnerable_imports
    vulnerable_installed_dependencies = vulnerability_analyzer.detected_vulnerable_installed_dependencies

    outdated_dependencies = []

    if updater:
        outdated_dependencies = updater.outdated_dependencies


    pre_test_results = {}
    test_metrics_before = {}

    if len(vulnerable_functions) > 0:
        run tests
        pre_tester = TestInfo(local_repo_path)

        try:
            pre_tester.runToxTest()
        except:
            print("An error occured while executing tests")

        print("Tests done")
        pre_test_results = pre_tester.getTestLog()
        test_metrics_before = pre_tester.get_test_metrics()

    post_test_metrics = {}
    post_test_results = {}

    if replace and len(vulnerable_functions) > 0:
        # automatically replace detected vulnerabilities if available
        print("Replace detected vulnerabilities")
        vulnerability_analyzer.replace_vulnerabilities_in_ast()

        # run tests
        post_tester = TestInfo(local_repo_path)

        try:
            post_tester.runToxTest()
            post_test_results = post_tester.getTestLog()
            post_test_metrics = post_tester.get_test_metrics()
        except:
            print("An error occured while executing tests")


    report = Report(vulnerable_functions, vulnerable_imports, pre_test_results, post_test_results, outdated_dependencies, [], replace)

    # automatically create pull request
    if push and (len(vulnerable_functions) > 0 or len(vulnerable_imports) > 0):
        print("Create pull-request")

        gh_handler.push_updates("bugrevelio@byom.de",
                                "bugrevelio",
                                "Vulnerabilities",
                                report.pull_request_report(),
                                "bugrevelio:master",
                                "master")

    print(report.plain_text_report())

    if html:
        report.html_report(html)

    if url:
        # collect relevant metrics
        repo_metrics = gh_handler.get_repository_metrics()
        vulnerability_metrics = vulnerability_analyzer.get_vulnerability_metrics()
        repo_metrics.update(vulnerability_metrics)
        repo_metrics.update(test_metrics_before)
        repo_metrics.update(post_test_metrics)

        logger.info(url, extra=repo_metrics)


    # delete downloaded repo
    shutil.rmtree(local_repo_path)

if __name__ == '__main__':
    main()
