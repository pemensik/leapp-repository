from leapp.actors import Actor
from leapp.models import BindFacts, InstalledRedHatSignedRPM
from leapp.tags import PreparationPhaseTag, IPUWorkflowTag
from leapp.libraries.actor import updates


class BindUpdate(Actor):
    """
    Actor parsing facts found in configuration and modifing configuration.
    """

    name = 'bind_update'
    consumes = (InstalledRedHatSignedRPM, BindFacts)
    produces = ()
    tags = (PreparationPhaseTag, IPUWorkflowTag)

    pkg_names = {'bind', 'bind-sdb', 'bind-pkcs11'}

    def has_package(self, t_rpms):
        """ Replacement for broken leapp.libraries.common.rpms.has_package """
        for fact in self.consume(t_rpms):
            for rpm in fact.items:
                if rpm.name in self.pkg_names:
                    return True
        return False

    def process(self):
        if not self.has_package(InstalledRedHatSignedRPM):
            self.log.debug('bind is not installed')
            return

        for bindfacts in self.consume(BindFacts):
            modified = updates.update_facts(bindfacts)
            self.log.info('{0} BIND configuration files modified.'.format(modified))
