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
    produces = (BindFacts, reporting.Report)
    tags = (ChecksPhaseTag, IPUWorkflowTag)

    def process(self):

        pkg_names = ['bind', 'bind-sdb', 'bind-pkcs11']
        found = False
        for fact in self.consume(InstalledRedHatSignedRPM):
            for rpm in fact.items:
                if rpm.name in pkg_names:
                    found = True
        #if not has_package(InstalledRedHatSignedRPM, 'bind':
        if not found:
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
