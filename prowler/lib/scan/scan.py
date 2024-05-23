from typing import Any

from prowler.lib.check.check import execute, update_audit_metadata
from prowler.lib.check.models import Check_Report
from prowler.lib.logger import logger
from prowler.providers.common.models import Audit_Metadata
from prowler.providers.common.provider import Provider


class Scan:
    _provider: Provider
    # Refactor(Core): This should replace the Audit_Metadata
    _number_of_checks_to_execute: int = 0
    _number_of_checks_completed: int = 0
    _service_checks_to_execute: dict[str, set[str]]
    _service_checks_completed: dict[str, set[str]]
    _progress: float = 0.0

    def __init__(self, provider, checks_to_execute):
        self._provider = provider

        self._number_of_checks_to_execute = len(checks_to_execute)

        service_checks_to_execute = dict()
        service_checks_completed = dict()

        for check in checks_to_execute:
            # check -> accessanalyzer_enabled
            # service -> accessanalyzer
            service = check.split["_"][0]
            if service not in service_checks_to_execute:
                service_checks_to_execute[service] = set()
            service_checks_to_execute[service].add(check)

            # service_checks_completed this should be empty to know when a service finishes
            if service not in service_checks_completed:
                service_checks_completed[service] = set()

        self._service_checks_to_execute = service_checks_to_execute
        self._service_checks_completed = service_checks_completed

    @property
    def checks_to_execute(self):
        return self._checks_to_execute

    @property
    def checks_completed(self):
        return self._checks_completed

    @property
    def provider(self):
        return self._provider

    @property
    def services_to_execute(self):
        return self._services_to_execute

    @property
    def services_completed(self):
        return self._services_completed

    @property
    def progress(self):
        return self._number_of_checks_completed / self._number_of_checks_to_execute

    def scan(
        self,
        custom_checks_metadata: Any,
    ) -> list[Check_Report]:
        try:
            # List to store all the check's findings
            all_findings = []
            # Services and checks executed for the Audit Status
            services_executed = set()
            checks_executed = set()

            # Initialize the Audit Metadata
            # TODO: this should be done in the provider class
            # Refactor(Core): Audit manager?
            self.global_provider.audit_metadata = Audit_Metadata(
                services_scanned=0,  # Refactor(Core): This shouldn't be nee
                expected_checks=self.checks_to_execute,
                completed_checks=0,
                audit_progress=0,
            )

            for check_name in self.checks_to_execute:
                try:
                    # Recover service from check name
                    service = check_name.split("_")[0]

                    check_findings = execute(
                        service,
                        check_name,
                        self.global_provider,
                        custom_checks_metadata,
                    )
                    all_findings.extend(check_findings)

                    # Update Audit Status
                    self._services_completed.add(service)
                    #
                    self._checks_completed.add(check_name)

                    # This should be done just once all the service's checks are completed
                    # This metadata needs to get to the services not within the provider
                    # since it is present in the Scan class
                    self.global_provider.audit_metadata = update_audit_metadata(
                        self.global_provider.audit_metadata,
                        services_executed,
                        checks_executed,
                    )

                # If check does not exists in the provider or is from another provider
                except ModuleNotFoundError:
                    logger.error(
                        f"Check '{check_name}' was not found for the {self.global_provider.type.upper()} provider"
                    )
                except Exception as error:
                    logger.error(
                        f"{check_name} - {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
        except Exception as error:
            logger.error(
                f"{check_name} - {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

        return all_findings
