import click
from vulnerability_analysis import VulnerabilityAnalyzer
from github_repo_handler import GithubRepoHandler
from update import Updater
import uuid
from report import Report
import logging
from pythonjsonlogger import jsonlogger
from test import TestInfo 


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

    updater = Updater(local_repo_path)

    vulnerability_analyzer = VulnerabilityAnalyzer(local_repo_path)
    # check for vulnerable functions and vulnerable dependencies
    vulnerability_analyzer.analyze()

    vulnerable_functions = vulnerability_analyzer.detected_vulnerable_functions
    # todo: add to report and update
    vulnerable_imports = vulnerability_analyzer.detected_vulnerable_imports
    # todo: add to report and update
    vulnerable_installed_dependencies = vulnerability_analyzer.detected_vulnerable_installed_dependencies
    # todo: add to report and update
    outdated_dependencies = updater.outdated_dependencies

    if replace:
        # automatically replace detected vulnerabilities if available
        print("Replace detected vulnerabilities")
        vulnerability_analyzer.replace_vulnerabilities_in_ast()

    # run tests
    tester = TestInfo(local_repo_path)
    tester.runToxTest()


    report = Report(vulnerable_functions, vulnerable_imports, [], outdated_dependencies, [], replace)

    # automatically create pull request
    if push and (len(vulnerable_functions) > 0 or len(vulnerable_imports) > 0):
        print("Create pull-request")

        # todo: include report in pull-request
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
        # todo: test metrics
        repo_metrics = gh_handler.get_repository_metrics()
        vulnerability_metrics = vulnerability_analyzer.get_vulnerability_metrics()
        repo_metrics.update(vulnerability_metrics)

        # setup logging
        logger = logging.getLogger()
        logHandler = logging.FileHandler('/tmp/metrics.json')
        logger.addHandler(logHandler)
        formatter = jsonlogger.JsonFormatter()
        logHandler.setFormatter(formatter)
        logger.setLevel(logging.INFO)

        logger.info(url, extra=repo_metrics)


    # todo: delete downloaded repo


if __name__ == '__main__':
    main()
