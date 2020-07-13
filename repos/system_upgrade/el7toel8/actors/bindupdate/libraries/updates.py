from leapp.models import BindFacts, BindConfigIssuesModel

from leapp.libraries.common import isccfg
from leapp.libraries.stdlib import api
from leapp.libraries.stdlib import run

from leapp import reporting

# Callback for walk function
callbacks = {
    'dnssec-lookaside': isccfg.ModifyState.callback_comment_out,
}

def paths_from_issues(issues):
    """ Extract paths from list of BindConfigIssuesModel """
    paths = []
    for issue in issues:
        paths.append(issue.path)
    return paths

def parser_file(parser, path):
    for cfg in parser.FILES_TO_CHECK:
        if cfg.path == path:
            return cfg
    return None

def debug_log(log, text):
    if log is not None:
        log.debug(text)

def make_backup(path, backup_suffix='.leapp'):
    """ Make backup of a file before modification """
    backup_path = path + backup_suffix
    run(['cp', '--preserve=all', path, backup_path])

def update_section(parser, section):
    """ Modify one section
    :ptype section: ConfigSection
    """
    state = isccfg.ModifyState()
    parser.walk(section, callbacks, state)
    state.finish(section)
    return state.content()

def update_config(parser, cfg):
    """ Modify contents of file accoriding to rules
    :ptype cfg: ConfigFile
    :returns str: Modified config contents
    """
    return update_section(parser, cfg.root_section())

def update_file(parser, path, log=None, write=True):
    """ Prepare modified content for the file, make backup and rewrite it
    :param parser: IscConfigParser
    :param path: String with path to a file
    :param log: Log instance with debug(str) method or None
    :param write: True to allow file modification, false to only return modification status
    """
    cfg = parser_file(parser, path)
    modified = update_config(parser, cfg)
    if modified != cfg.buffer:
        debug_log(log, '{0} needs modification'.format(path))
        if write:
            make_backup(path)
            with open(path, 'w') as f:
                f.write(modified)
            debug_log(log, '{0} updated to size {1}'.format(path, len(modified)))
        return True
    return False

def update_facts(facts, path='/etc/named.conf'):
    """ Parse and update all files according to supplied facts
    :param facts: BindFacts instance
    :param path: String to main configuration file
    :returns: number of modified files
    """
    parser = isccfg.IscConfigParser(path)
    modified_files = 0
    if facts.dnssec_lookaside:
        for model in facts.dnssec_lookaside:
            if update_file(parser, model.path):
                modified_files += 1
    return modified_files
