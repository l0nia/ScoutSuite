from ScoutSuite.core.console import print_exception
from ScoutSuite.providers.gcp.facade.basefacade import GCPBaseFacade
from ScoutSuite.providers.gcp.facade.utils import GCPFacadeUtils


class AccessContextManagerFacade(GCPBaseFacade):
    def __init__(self):
        super().__init__('accesscontextmanager', 'v1')

    async def list_policies(self, organization_id: str):
        try:
            client = self._get_client()
            policies_group = client.accessPolicies()
            request = policies_group.list(parent=f'organizations/{organization_id}')
            return await GCPFacadeUtils.get_all('accessPolicies', request, policies_group)
        except Exception as e:
            print_exception(f'Failed to retrieve Access Context Manager policies: {e}')
            return []

    async def list_service_perimeters(self, policy_name: str):
        try:
            client = self._get_client()
            perimeters_group = client.accessPolicies().servicePerimeters()
            request = perimeters_group.list(parent=policy_name)
            return await GCPFacadeUtils.get_all('servicePerimeters', request, perimeters_group)
        except Exception as e:
            print_exception(f'Failed to retrieve Service Perimeters for policy {policy_name}: {e}')
            return []

    async def list_access_levels(self, policy_name: str):
        try:
            client = self._get_client()
            access_levels_group = client.accessPolicies().accessLevels()
            request = access_levels_group.list(parent=policy_name)
            return await GCPFacadeUtils.get_all('accessLevels', request, access_levels_group)
        except Exception as e:
            print_exception(f'Failed to retrieve Access Levels for policy {policy_name}: {e}')
            return []

    async def list_gcp_user_access_bindings(self, organization_id: str):
        try:
            client = self._get_client()
            bindings_group = client.organizations().gcpUserAccessBindings()
            request = bindings_group.list(parent=f'organizations/{organization_id}')
            return await GCPFacadeUtils.get_all('gcpUserAccessBindings', request, bindings_group)
        except Exception as e:
            print_exception(
                f'Failed to retrieve GCP User Access Bindings for organization {organization_id}: {e}')
            return []
