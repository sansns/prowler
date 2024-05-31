from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.rds.rds_client import rds_client


class rds_cluster_backtrack_enabled(Check):
    def execute(self):
        findings = []
        for db_cluster in rds_client.db_clusters:
            if rds_client.db_clusters[db_cluster].engine == "aurora-mysql":
                report = Check_Report_AWS(self.metadata())
                report.region = rds_client.db_clusters[db_cluster].region
                report.resource_id = rds_client.db_clusters[db_cluster].id
                report.resource_arn = rds_client.db_clusters[db_cluster].arn
                report.resource_tags = rds_client.db_clusters[db_cluster].tags
                report.status = "FAIL"
                report.status_extended = f"RDS Cluster {rds_client.db_clusters[db_cluster].id} does not have backtrack enabled."
                # Check RDS Clusters that support TLS encryption
                if rds_client.db_clusters[db_cluster].backtrack > 0:
                    report.status = "PASS"
                    report.status_extended = f"RDS Cluster {rds_client.db_clusters[db_cluster].id} has backtrack enabled."

                findings.append(report)

        return findings
