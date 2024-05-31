from unittest import mock

from prowler.providers.aws.services.rds.rds_service import DBCluster
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, AWS_REGION_US_EAST_1


# Currently have to mock the tests as moto does not return the value for backtrack. Issue: https://github.com/getmoto/moto/issues/7734
class Test_rds_cluster_backtrack_enabled:
    def test_no_rds_clusters(self):
        rds_client = mock.MagicMock
        rds_client.db_clusters = {}
        with mock.patch(
            "prowler.providers.aws.services.rds.rds_service.RDS",
            rds_client,
        ):
            from prowler.providers.aws.services.rds.rds_cluster_backtrack_enabled.rds_cluster_backtrack_enabled import (
                rds_cluster_backtrack_enabled,
            )

            check = rds_cluster_backtrack_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_rds_cluster_aurora_mysql_backtrack_enabled(self):
        rds_client = mock.MagicMock
        rds_client.db_clusters = {}
        rds_client.db_clusters["db-cluster"] = DBCluster(
            id="db-cluster-1",
            arn=f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:cluster:db-cluster-1",
            endpoint=f"db-cluster-1.cluster-cnpexample.{AWS_REGION_US_EAST_1}.rds.amazonaws.com",
            engine="aurora-mysql",
            status="available",
            public=False,
            encrypted=True,
            auto_minor_version_upgrade=True,
            backup_retention_period=1,
            backtrack=86400,
            cloudwatch_logs=[],
            deletion_protection=True,
            parameter_group="test",
            multi_az=True,
            region=AWS_REGION_US_EAST_1,
            tags=[],
        )
        with mock.patch(
            "prowler.providers.aws.services.rds.rds_service.RDS",
            rds_client,
        ):
            from prowler.providers.aws.services.rds.rds_cluster_backtrack_enabled.rds_cluster_backtrack_enabled import (
                rds_cluster_backtrack_enabled,
            )

            check = rds_cluster_backtrack_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "RDS Cluster db-cluster-1 has backtrack enabled."
            )
            assert result[0].resource_id == "db-cluster-1"
            assert result[0].region == AWS_REGION_US_EAST_1
            assert (
                result[0].resource_arn
                == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:cluster:db-cluster-1"
            )
            assert result[0].resource_tags == []

    def test_rds_cluster_aurora_mysql_backtrack_disabled(self):
        rds_client = mock.MagicMock
        rds_client.db_clusters = {}
        rds_client.db_clusters["db-cluster"] = DBCluster(
            id="db-cluster-1",
            arn=f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:cluster:db-cluster-1",
            endpoint=f"db-cluster-1.cluster-cnpexample.{AWS_REGION_US_EAST_1}.rds.amazonaws.com",
            engine="aurora-mysql",
            status="available",
            public=False,
            encrypted=True,
            auto_minor_version_upgrade=True,
            backup_retention_period=1,
            backtrack=0,
            cloudwatch_logs=[],
            deletion_protection=True,
            parameter_group="test",
            multi_az=True,
            region=AWS_REGION_US_EAST_1,
            tags=[],
        )
        with mock.patch(
            "prowler.providers.aws.services.rds.rds_service.RDS",
            rds_client,
        ):
            from prowler.providers.aws.services.rds.rds_cluster_backtrack_enabled.rds_cluster_backtrack_enabled import (
                rds_cluster_backtrack_enabled,
            )

            check = rds_cluster_backtrack_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "RDS Cluster db-cluster-1 does not have backtrack enabled."
            )
            assert result[0].resource_id == "db-cluster-1"
            assert result[0].region == AWS_REGION_US_EAST_1
            assert (
                result[0].resource_arn
                == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:cluster:db-cluster-1"
            )
            assert result[0].resource_tags == []

    # Expeted to return nothing as only Aurora MySQL has backtrack features
    def test_rds_cluster_aurora_postgres(self):
        rds_client = mock.MagicMock
        rds_client.db_clusters = {}
        rds_client.db_clusters["db-cluster"] = DBCluster(
            id="db-cluster-1",
            arn=f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:cluster:db-cluster-1",
            endpoint=f"db-cluster-1.cluster-cnpexample.{AWS_REGION_US_EAST_1}.rds.amazonaws.com",
            engine="aurora-postgres",
            status="available",
            public=False,
            encrypted=True,
            auto_minor_version_upgrade=True,
            backup_retention_period=1,
            backtrack=0,
            cloudwatch_logs=[],
            deletion_protection=True,
            parameter_group="test",
            multi_az=True,
            region=AWS_REGION_US_EAST_1,
            tags=[],
        )
        with mock.patch(
            "prowler.providers.aws.services.rds.rds_service.RDS",
            rds_client,
        ):
            from prowler.providers.aws.services.rds.rds_cluster_backtrack_enabled.rds_cluster_backtrack_enabled import (
                rds_cluster_backtrack_enabled,
            )

            check = rds_cluster_backtrack_enabled()
            result = check.execute()
            assert len(result) == 0
