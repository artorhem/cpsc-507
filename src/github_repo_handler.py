from github import Github
import os
from git import Repo
import github3


class GithubRepoHandler:
    def __init__(self, git_url):
        """
        Constructor
        :param git_url: URL to the github repository
        """
        self.git_url = git_url

        # remote access to original repository
        # all actions that would otherwise be performed by clicking on the
        # Github website (like creating a pull request, forking, ...) can
        # be performed through this object
        self.remote_original_repo = None

        # remote access to fork from original repo
        self.remote_fork = None

        # access to locally stored repository
        # all actions that are performed locally using git (like committing,
        # accessing history data) can be performed through this object
        self.local_repo = None

        # get token that allows accessing the github API
        # the token must be set as environment variable
        self.g = Github(os.environ['GITHUB_USER'], os.environ['GITHUB_PASSWORD'])

    def download_repository(self, target):
        """
        Downloads a specific github repository to the local machine.
        :param target: local path where the repository should be downloaded to
        :return: tuple to access the locally stored repo as well as to
        access the remote repo
        """
        # get access handle to remote repository
        remote_github_user = self.g.get_user(self.git_url.split('/')[-2])

        # workaround: remote_github_user.get_repo(<name>) is not working
        for repo in list(remote_github_user.get_repos()):
            # find repo in list of all available repos of user
            if repo.name == self.git_url.split('/')[-1]:
                self.remote_original_repo = repo
                break

        # create a fork
        self.remote_fork = self.g.get_user().create_fork(self.remote_original_repo)

        # download repo and make available locally
        self.local_repo = Repo.clone_from(self.remote_fork.git_url, target)

    def get_repository_metrics(self):
        """
        Collect metrics of specific repository and write them into a log file.
        The metrics will later be useful for the evaluation.
        """
        # collect metrics
        total_commits = len(list(self.remote_original_repo.get_commits()))
        total_tags = len(list(self.remote_original_repo.get_tags()))
        total_contributors = len(list(self.remote_original_repo.get_contributors()))
        total_open_pull_requests = len(list(self.remote_original_repo.get_pulls('open')))
        total_closed_pull_requests = len(list(self.remote_original_repo.get_pulls('closed')))
        total_issues = len(list(self.remote_original_repo.get_issues()))

        pull_request_times = 0

        for pull_request in list(self.remote_original_repo.get_pulls('closed')):
            diff = pull_request.closed_at - pull_request.created_at
            elapsed_seconds = (diff.days * 86400000) + (diff.seconds * 1000) + (diff.microseconds / 1000) * 1000
            pull_request_times += elapsed_seconds

        average_time_to_merge_pull_request = None
        if pull_request_times > 0:
            average_time_to_merge_pull_request = pull_request_times / total_closed_pull_requests
        age = self.remote_original_repo.created_at
        total_forks = self.remote_original_repo.forks_count
        total_stars = self.remote_original_repo.stargazers_count
        
        last_commit = list(self.remote_original_repo.get_commits())[0].commit.committer.date

        return {
            'repo_url': self.git_url,
            'total_commits': total_commits,
            'total_tags': total_tags,
            'total_contributors': total_contributors,
            'total_open_pull_requests': total_open_pull_requests,
            'total_closed_pull_requests': total_closed_pull_requests,
            'total_issues': total_issues,
            'average_time_to_merge_pull_request': average_time_to_merge_pull_request,
            'age': age,
            'total_forks': total_forks,
            'total_stars': total_stars,
            'last_commit': last_commit
        }

    def push_updates(self, email, name, title, body, head, base):
        """
        Commits and pushes changes to fork and created pull request.
        :param email: email of committer
        :param name: name of committer
        :param title: title of the pull request
        :param body: content/description of the pull request
        :param head: location of the branch to be merged <username:branch>
        :param base: branch changes are to be merged into
        """
        if self.remote_original_repo:
            # set the appropriate remote location
            remote_url = 'https://%s:%s@github.com/%s/%s.git' % (os.environ['GITHUB_USER'], os.environ['GITHUB_PASSWORD'], os.environ['GITHUB_USER'], self.remote_original_repo.name)
            remote = self.local_repo.create_remote('orig', url=remote_url)

            # configure email address and user name
            cw = self.local_repo.config_writer()
            cw.set_value("user", "email", email)
            cw.set_value("user", "name", name)

            # commit changes
            self.local_repo.git.add(u=True)
            self.local_repo.index.commit('Replaced vulnerable functions and outdated dependencies')

            push to remote
            remote.push(refspec='master')

            # bug in GitPython which prevents using create_pull
            # create pull request
            gh = github3.login(os.environ['GITHUB_USER'], password=os.environ['GITHUB_PASSWORD'])
            repo = gh.repository(self.remote_original_repo.owner.login, self.remote_original_repo.name)
            repo.create_pull(title=title, base=base, head=head, body=body)