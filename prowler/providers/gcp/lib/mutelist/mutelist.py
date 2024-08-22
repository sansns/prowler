from prowler.lib.mutelist.mutelist import Mutelist
from prowler.lib.outputs.finding import Finding
from prowler.lib.outputs.utils import unroll_dict, unroll_tags


class GCPMutelist(Mutelist):
    def is_finding_muted(
        self,
        finding: Finding,
    ) -> bool:
        return self.is_muted(
            finding.account_uid,
            finding.check_id,
            finding.region,
            finding.resource_name,
            unroll_dict(unroll_tags(finding.resource_tags)),
        )
