from leapp.models import Model, fields
from leapp.topics import SystemInfoTopic

class BindSectionModel(Model):
    """
    Model for part of configuration file, in which configuration statements might reside.
    It would be options {} section or view {}.
    """
    topic = SystemInfoTopic
    name = fields.String()
    dnssec_lookaside = fields.Nullable(fields.String())

class BindConfigModel(Model):
    """
    Model for specifying single configuration file and what is included
    """
    topic = SystemInfoTopic

    path = fields.String()
    options = fields.Nullable(fields.Model(BindSectionModel))
    views = fields.Nullable(fields.List(fields.Model(BindSectionModel)))
    zones = fields.Nullable(fields.List(fields.Model(BindSectionModel)))

class BindFacts(Model):
    """
    Whole facts related to BIND configuration
    """

    topic = SystemInfoTopic

    config_files = fields.List(fields.Model(BindConfigModel))
