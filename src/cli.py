import click
import vulnerability_analysis


# todo: list of URLs to be analyzed
@click.command()
@click.option('--url', help='URL to a github repository')    
@click.option('--path', help='Path to a local project directory')
def main(url, path):
    # analyze source code of provided project
    # todo

    print "Start analysis"

    print vulnerability_analysis.get_dependencies(path)

    print vulnerability_analysis.get_latest()

if __name__ == '__main__':
    main()