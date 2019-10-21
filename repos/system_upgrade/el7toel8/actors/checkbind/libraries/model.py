from leapp import model
from model import BindFacts, BindSectionModel

from leapp.libraries.common import isccfg
from leapp.libraries.stdlib import api

def parseconfig(path='/etc/named.conf'):
    """ Parse configuration """
    parser = isccfg.BindParser(path)

    options = parser.find_options()
    if options:
    views = parser.find_views()

def make_statementstring(parser, section, statement):
    """
    Create single string from variable statements
    :returns: string with just value

    Omits terminating ; from string
    """
    vl = parser.find_values(section, statement)
    if not vl:
        return None
    s = ''
    for v in vl:
        s += v.value() + ' '
        if v.value() != ';':
            s += ' '
    if len(s)>0:
        s = s[:-1]
    return s
            

def makesection_options(parser, section):
    model = BindSectionModel()
    model.type = 'options'
    model.config_file = section.config.path
    model.name = model.type


def makeconfig(parser, cfgfile):
    config = BindConfigModel()
    config.path = cfgfile.path

    opt = parser.find_options(cfgfile)
    if opt:
        config.options = makesection(parser, opt)
    views = parser.find_views_file(cfgfile)
    
    api.produce(config)
    pass
