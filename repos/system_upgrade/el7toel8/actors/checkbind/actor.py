from leapp.actors import Actor
from leapp.libraries.common.rpms import has_package
from leapp.models import Report, BindFacts, InstalledRedHatSignedRPM
from leapp.tags import ChecksPhaseTag, IPUWorkflowTag
from leapp import reporting
from leapp.libraries.common import isccfg
from leapp.libraries.stdlib import api
from leapp.libraries.actor import model

class CheckBind(Actor):
    """
    Actor parsing BIND configuration and checking for known issues in it
    """

    name = 'check_bind'
    consumes = (InstalledRedHatSignedRPM,)
    produces = (BindFacts,)
    tags = (ChecksPhaseTag, IPUWorkflowTag)

    def process(self):

        if not has_package(InstalledRedHatSignedRPM, 'bind'):
            return

        facts = model.get_facts('/etc/named.conf')
        issues = model.get_messages(facts)

        if issues is not None:
            api.produce(facts)
            issues.extend([
                reporting.Severity(reporting.Severity.HIGH),
                reporting.Tags([reporting.Tags.SERVICES, reporting.Tags.NETWORK]),
                reporting.Flags([reporting.Flags.INHIBITOR]),
            ])
            reporting.create_report(issues)
        else:
            self.log.info('The BIND configuration seems compatible.')

        pass
