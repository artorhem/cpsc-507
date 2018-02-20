import click
import vulnerability_analysis
import vulnerabilities
import crawler
import uuid


# todo: list of URLs to be analyzed
@click.command()
@click.option('--url', help='URL to a github repository')
@click.option('--path', help='Path to a local project directory')
def main(url, path):
    # analyze source code of provided project
    print "Start analysis"

    local_repo_path = '/tmp/' + str(uuid.uuid4())

    if url:
        (local_repo, remote_repo) = crawler.download_repository(url, local_repo_path)
        crawler.get_repository_metrics(remote_repo)
    elif path:
        local_repo_path = path
        

    print vulnerability_analysis.vulnerability_analysis_in_path(local_repo_path)

    # dependencies = vulnerability_analysis.get_dependencies(local_repo_path)

    # vulnerable_functions = vulnerabilities.get_vulnerable_functions()

    # print vulnerable_functions

    # for function, properties in vulnerable_functions.items():
    #     if function in dependencies:
    #         print "Found"
    #     print function

    # # print vulnerability_analysis.get_latest()
    # dependencies = vulnerability_analysis.get_dependencies(local_repo_path)

    # for dependency in dependencies:
    #     print dependency
    #     print vulnerability_analysis.get_functions(dependency)

    # todo: delete downloaded repo

if __name__ == '__main__':
    main()
