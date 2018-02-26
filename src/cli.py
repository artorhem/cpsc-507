import click
import vulnerability_analysis
import vulnerabilities
import crawler
import uuid
from report import Report


# todo: list of URLs to be analyzed
@click.command()
@click.option('--url', help='URL to a github repository')
@click.option('--path', help='Path to a local project directory')
@click.option('--replace', is_flag=True, default=False, help='Automatically replace vulnerabilities')
@click.option('--push', is_flag=True, default=False, help='Automatically creates pull-request with changes')
@click.option('--html', help='Create html report in provided file')
def main(url, path, replace, push, html):
    # analyze source code of provided project
    print "Start analysis"

    local_repo_path = '/tmp/' + str(uuid.uuid4())
    local_repo = None
    remote_repo = None

    if url:
        (local_repo, remote_repo, orig_repo) = crawler.download_repository(url, local_repo_path)
        crawler.get_repository_metrics(remote_repo)
    elif path:
        local_repo_path = path
        
    detected_vulnerabilities = vulnerability_analysis.vulnerability_analysis_in_path(local_repo_path)

    if replace:
        print "Replace detected vulnerabilities"
        vulnerability_analysis.replace_vulnerabilities(detected_vulnerabilities)

        if push and remote_repo:
            print "Create pull-request"
            crawler.push_updates(orig_repo, local_repo, "bugrevelio@byom.de", "bugrevelio", "Test", "Test body", "bugrevelio:master", "master")

    report = Report(detected_vulnerabilities, None, None, replace)
    print report.plain_text_report()

    if html:
        report.html_report(html)


    # todo: delete downloaded repo


if __name__ == '__main__':
    main()
