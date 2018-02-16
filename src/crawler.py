from github import Github
import os
from git import Repo
import logging
from pythonjsonlogger import jsonlogger

# get token that allows accessing the github API
# the token must be set as environment variable
g = Github(os.environ['GITHUB_ACCESS_TOKEN'])


def download_repository(git_url, target):
    """
    Downloads a specific github repository to the local machine.
    :param git_url: URL to the github repository
    :param target: local path where the repository should be downloaded to
    :return: tuple to access the locally stored repo as well as to access the remote repo
    """

    # download repo and make available locally
    local_repo = Repo.clone_from(git_url, target)

    # get access handle to remote repository
    remote_github_user = g.get_user(git_url.split('/')[-2])
    remote_repo = None
    # workaround: remote_github_user.get_repo(<name>) is not working
    for repo in list(remote_github_user.get_repos()):
        # find repo in list of all available repos of user
        if repo.name == git_url.split('/')[-1]:
            remote_repo = repo
            break

    return (local_repo, remote_repo)


def get_repository_metrics(remote_repo):
    """
    Collect metrics of specific repository and write them into a log file.
    The metrics will later be useful for the evaluation.
    :param remote_repo: handle to remote repository
    """
    # setup logging
    logger = logging.getLogger()
    logHandler = logging.FileHandler('/tmp/metrics.json')    # set in config file
    logger.addHandler(logHandler)
    formatter = jsonlogger.JsonFormatter()
    logHandler.setFormatter(formatter)
    logger.setLevel(logging.INFO)

    # collect metrics
    total_commits = len(list(remote_repo.get_commits()))
    total_tags = len(list(remote_repo.get_tags()))
    total_contributors = len(list(remote_repo.get_contributors()))
    total_open_pull_requests = len(list(remote_repo.get_pulls('open')))
    total_closed_pull_requests = len(list(remote_repo.get_pulls('closed')))
    total_issues = len(list(remote_repo.get_issues()))

    pull_request_times = 0

    for pull_request in list(remote_repo.get_pulls('closed')):
        diff = pull_request.closed_at - pull_request.created_at
        elapsed_seconds = (diff.days * 86400000) + (diff.seconds * 1000) + (diff.microseconds / 1000) * 1000
        pull_request_times += elapsed_seconds

    average_time_to_merge_pull_request = None 
    if pull_request_times > 0:
        average_time_to_merge_pull_request = pull_request_times / total_closed_pull_requests
    age = remote_repo.created_at
    total_forks = remote_repo.forks_count
    total_stars = remote_repo.stargazers_count


    logger.info(remote_repo.git_url, extra={
        'total_commits': total_commits,
        'total_tags': total_tags,
        'total_contributors': total_contributors,
        'total_open_pull_requests': total_open_pull_requests,
        'total_closed_pull_requests': total_closed_pull_requests,
        'total_issues': total_issues,
        'average_time_to_merge_pull_request': average_time_to_merge_pull_request,
        'age': age,
        'total_forks': total_forks,
        'total_stars': total_stars
    })

