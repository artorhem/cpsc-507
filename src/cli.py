import click
import vulnerability_analysis
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


    print vulnerability_analysis.get_dependencies(local_repo_path)

    print vulnerability_analysis.get_latest()

    # todo: delete downloaded repo

if __name__ == '__main__':
    main()