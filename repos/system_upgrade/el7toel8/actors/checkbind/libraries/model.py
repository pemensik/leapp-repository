from leapp.models import BindFacts, BindConfigIssuesModel
from leapp.libraries.common import isccfg
from leapp import reporting
from leapp.libraries.stdlib import api


def add_statement(statement, state):
    """Add searched statement to found issues."""

    stmt_text = statement.serialize_skip(' ')
    name = statement.var(0).value()
    if name in state:
        state[name].append((stmt_text, statement.config.path))
    else:
        state[name] = [(stmt_text, statement.config.path)]


def find_dnssec_lookaside(statement, state):
    try:
        arg = statement.var(1)
        if not(arg.type() == arg.TYPE_BARE and arg.value() == 'no'):
            # auto or yes statement
            # dnssec-lookaside "." trust-anchor "dlv.isc.org";
            add_statement(statement, state)
    except IndexError:
        api.current_logger().warning('Unexpected statement format: "%s"',
                                     statement.serialize_skip(' '))


def convert_to_issues(statements):
    """Produce list of offending statements in set of files.

    :param statements: one item from list created by add_statement
    """

    files = dict()
    for statement, path in statements:
        if path in files:
            files[path].update(statement)
            if statement not in files[path].statements:
                files[path].statements.append(statement)
        else:
            files[path] = set(statement)
    values = list()
    for path in files:
        values.append(BindConfigIssuesModel(path=path, statements=list(files[path])))
    return values


def convert_found_issues(issues, files):
    """Convert find state results to facts."""

    dnssec_lookaside = None
    if 'dnssec-lookaside' in issues:
        dnssec_lookaside = convert_to_issues(issues['dnssec-lookaside'])
    return BindFacts(config_files=files, dnssec_lookaside=dnssec_lookaside)


def get_facts(path, log=None):
    """Find issues in configuration files.

    Report used configuration files and wrong statements in each file.
    """

    find_calls = {
        'dnssec-lookaside': find_dnssec_lookaside
    }

    parser = isccfg.BindParser(path)
    state = {}
    files = set()

    for cfg in parser.FILES_TO_CHECK:
        parser.walk(cfg.root_section(), find_calls, state)
        files.add(cfg.path)

        api.current_logger().debug('Found state: "%s", files: "%s"',
                                   repr(state), files)

    facts = convert_found_issues(state, list(files))
    return facts


def get_messages(facts):
    if facts.dnssec_lookaside:
        return [
            reporting.Title('BIND configuration issues found'),
            reporting.Summary('BIND configuration contains no longer accepted statements: dnssec-lookaside')
                ]
