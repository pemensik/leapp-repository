from leapp.models import Model, fields
from leapp.topics import SystemInfoTopic

class BindSectionModel(Model):
    """
    Model for part of configuration file, in which configuration statements might reside.
    It would be options {} section or view {}. Contains more statements, which are recorded here.
    """

    topic = SystemInfoTopic
    name = fields.String() # name of view or zone.
    config_path = fields.String() # path of config file, which contains this section
    stype = fields.StringEnum(['options', 'view', 'zone'])
    zoneclass = fields.Nullable(fields.StringEnum(['IN', 'CH', 'HS']))

    # dnssec-lookaside arguments
    dnssec_lookaside = fields.Nullable(fields.String())


class BindFacts(Model):
    """
    Whole facts related to BIND configuration
    """

    topic = SystemInfoTopic

    # Detected configuration files via includes
    config_files = fields.List(fields.String())

    # Only issues detected.
    # unsupported dnssec-lookaside statements with old values
    # found in list of files. List of files, where unsupported
    # statements were found. Context not yet provided
    dnssec_lookaside = fields.Nullable(fields.String())
