"""
This scripts selects repositories from Github which will be analyzed for security vulnerabilities.
The URLs of the selected libraries are written into a file.
"""

from github import Github
import random
import os

MAX_REPOS = 1000
SELECTION_PROP = 0.1

def main():
    g = Github(os.environ['GITHUB_USER'], os.environ['GITHUB_PASSWORD'])
    repos = g.search_repositories("pushed:>2015-03-07,size:<5000", language="Python")
    selected_repos = []
    count = 0

    for repo in repos:
        if len(selected_repos) >= MAX_REPOS:
            break

        # if random.uniform(0, 1) < SELECTION_PROP:
        if count < 100 or count > 900:
            selected_repos.append(repo.html_url)

        count += 1

    print selected_repos

    out_file = open('/tmp/repos.txt', 'w')

    for repo in selected_repos:
        out_file.write("%s\n" % repo)


if __name__ == '__main__':
    main()