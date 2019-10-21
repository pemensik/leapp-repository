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

    config_files = fields.List(fields.String())
    options = fields.Nullable(fields.Model(BindSectionModel))
    views = fields.Nullable(fields.List(fields.Model(BindSectionModel)))
    zones = fields.Nullable(fields.List(fields.Model(BindSectionModel)))
