from leapp.actors import Actor
from leapp.libraries.common.rpms import has_package
#from leapp.actors.library import *
from leapp.models import Report, BindFacts, InstalledRedHatSignedRPM
from leapp.tags import ChecksPhaseTag, IPUWorkflowTag
from leapp.reporting import Report, create_report


class CheckBind(Actor):
    """
    No documentation has been provided for the check_bind actor.
    """

    name = 'check_bind'
    consumes = (InstalledRedHatSignedRPM, BindFacts)
    produces = (Report,)
    tags = (ChecksPhaseTag, IPUWorkflowTag)

    def process(self):

	if not has_package(InstalledRedHatSignedRPM, 'bind'):
	    return

            create_report([
                reporting.Title('Bind is installed'),
                reporting.Summary(
                    'Notification that BIND is installed'
                ),
                reporting.Severity(reporting.Severity.HIGH),
                reporting.Tags(COMMON_REPORT_TAGS + [reporting.Tags.NETWORK]),
                reporting.Flags([reporting.Flags.INHIBITOR])
            ])
        pass
