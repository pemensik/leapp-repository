from leapp.actors import Actor
from leapp.models import BindFacts, InstalledRedHatSignedRPM
from leapp.tags import ChecksPhaseTag, IPUWorkflowTag
from leapp import reporting
from leapp.libraries.stdlib import api
from leapp.libraries.actor import model


class CheckBind(Actor):
    """Actor parsing BIND configuration and checking for known issues in it."""

    name = 'check_bind'
    consumes = (InstalledRedHatSignedRPM,)
    produces = (BindFacts, reporting.Report)
    tags = (ChecksPhaseTag, IPUWorkflowTag)

    pkg_names = {'bind', 'bind-sdb', 'bind-pkcs11'}

    def has_package(self, t_rpms):
        """Replacement for broken leapp.libraries.common.rpms.has_package."""
        for fact in self.consume(t_rpms):
            for rpm in fact.items:
                if rpm.name in self.pkg_names:
                    return True
        return False

    def process(self):
        if not self.has_package(InstalledRedHatSignedRPM):
            self.log.debug('bind is not installed')
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
            self.log.info('BIND configuration issues were found.')
        else:
            self.log.info('BIND configuration seems compatible.')

        pass
