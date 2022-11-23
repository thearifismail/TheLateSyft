import os
import jira
import configparser
from pathlib import Path


def authenticate():
    '''
    Build the base authentication thing for jira stuff
    '''

    config = checkConfig()

    return jira.JIRA(config['url'], token_auth=config['token'])


def checkConfig():
    '''
    expand user's home to look for .config/nanny.conf or env
    var's if config not found
    '''

    config = {}
    home = str(Path.home())

    confFile = Path(home + "/.config/nanny.conf")
    if confFile.is_file():
        parser = configparser.ConfigParser()
        parser.read(confFile)
        config = {
            "url": parser['auth']['url'],
            "token": parser['auth']['token'],
            "boards": parser['projects']['boards']
            }

    elif not confFile.is_file():
        url = os.environ.get('JIRA_URL')
        token = os.environ.get('JIRA_TOKEN')
        boards = os.environ.get('JIRA_BOARDS')
        if url is not None and token is not None:
            config = {"url": url, "token": token, "boards": boards}
        else:
            pass

    else:
        print('no config items found. Quiting')
        quit()

    return config


def list_issues(project):
    '''
    Specify the jql for the search, today that looks like:
    project = this/that, with security labels and not closed
    '''

    auth = authenticate()
    search = f'project = {project} AND labels = security AND (status != closed AND status != done)'
    results = auth.search_issues(search, maxResults=1000)
    return results


def read_issues(issue):
    '''
    Simply read the labels, returns the card number and labels
    '''

    auth = authenticate()
    fields = ['labels', ]

    results = auth.issue(issue, fields=fields)

    return results


def updateLabels(issue):
    '''
    This function will (eventually) read the current labels
    and then add the testing flag.
    '''

    auth = authenticate()
    updateLabel = auth.issue(issue)
    updateLabel.update(fields={'labels': ['testing']})

    # auth.add_comment(issue, 'First comment')

    return read_issues(issue)
