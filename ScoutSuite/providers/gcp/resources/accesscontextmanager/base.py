from ScoutSuite.core.console import print_exception, print_warning
from ScoutSuite.providers.base.resources.base import Resources
from ScoutSuite.providers.gcp.facade.base import GCPFacade
from ScoutSuite.providers.utils import get_non_provider_id


class AccessContextManager(Resources):
    def __init__(self, facade: GCPFacade):
        super().__init__(facade)

    async def fetch_all(self):
        self.clear()
        self['filters'] = {}
        self['findings'] = {}
        self['policies'] = {}
        self['projects'] = {}
        self['organizations'] = {}

        raw_projects = await self.facade.get_projects()
        project_number_to_id = {}
        project_id_to_number = {}
        org_ids = set()

        if getattr(self.facade, 'organization_id', None):
            org_ids.add(str(self.facade.organization_id))

        for project in raw_projects:
            project_id = project.get('projectId')
            if not project_id:
                continue
            try:
                enabled = await self.facade.is_api_enabled(project_id, self.__class__.__name__)
            except Exception as e:
                print_exception(
                    f'Unable to determine Access Context Manager API state for project {project_id}: {e}')
                continue
            if not enabled:
                continue
            project_number = project.get('projectNumber')
            if project_number is not None:
                project_number = str(project_number)
                project_number_to_id[project_number] = project_id
            project_id_to_number[project_id] = project_number
            parent = project.get('parent', {})
            if parent.get('type') == 'organization' and parent.get('id'):
                org_ids.add(str(parent['id']))
            self['projects'][project_id] = {
                'project_number': project_number,
                'service_perimeters': {},
                'access_levels': {},
                'policies': {}
            }

        if not org_ids:
            print_warning('Access Context Manager: no organization identifier available; skipping resource collection.')
            self['projects_count'] = len(self['projects'])
            self['policies_count'] = 0
            self['organizations_count'] = 0
            self['gcp_user_access_bindings_count'] = 0
            return

        for org_id in org_ids:
            await self._collect_for_organization(org_id, project_number_to_id, project_id_to_number)

        self['policies_count'] = len(self['policies'])
        self['projects_count'] = len(self['projects'])

        for project in self['projects'].values():
            project['service_perimeters_count'] = len(project['service_perimeters'])
            project['access_levels_count'] = len(project['access_levels'])
            project['policies_count'] = len(project['policies'])

        if not self['organizations']:
            self.pop('organizations', None)
            self['organizations_count'] = 0
            self['gcp_user_access_bindings_count'] = 0
        else:
            self['organizations_count'] = len(self['organizations'])
            self['gcp_user_access_bindings_count'] = sum(
                org.get('gcp_user_access_bindings_count', 0) for org in self['organizations'].values())

    async def _collect_for_organization(self, organization_id: str, project_number_to_id: dict,
                                        project_id_to_number: dict):
        organization_id = str(organization_id)
        policies = await self.facade.accesscontextmanager.list_policies(organization_id)
        if not policies:
            return

        for policy in policies:
            policy_name = policy.get('name')
            if not policy_name:
                print_warning('Access Context Manager policy without name encountered; skipping')
                continue
            policy_id, policy_data = self._parse_policy(policy, organization_id)

            access_levels = await self.facade.accesscontextmanager.list_access_levels(policy_name)
            for access_level in access_levels:
                level_id, level_data = self._parse_access_level(access_level)
                policy_data['access_levels'][level_id] = level_data
            policy_data['access_levels_count'] = len(policy_data['access_levels'])

            service_perimeters = await self.facade.accesscontextmanager.list_service_perimeters(policy_name)
            policy_project_ids = set()
            unresolved_numbers = set()
            for perimeter in service_perimeters:
                perimeter_id, perimeter_data = self._parse_service_perimeter(perimeter, project_number_to_id)
                policy_data['service_perimeters'][perimeter_id] = perimeter_data
                policy_project_ids.update(perimeter_data['project_ids'])
                unresolved_numbers.update(perimeter_data.get('unresolved_project_numbers', []))
                self._assign_perimeter_to_projects(perimeter_data, policy_id, policy_data, project_id_to_number)
            policy_data['service_perimeters_count'] = len(policy_data['service_perimeters'])
            policy_data['project_ids'] = sorted(policy_project_ids)
            policy_data['project_ids_count'] = len(policy_data['project_ids'])
            if unresolved_numbers:
                policy_data['unresolved_project_numbers'] = sorted(unresolved_numbers)

            self['policies'][policy_id] = policy_data

        bindings = await self.facade.accesscontextmanager.list_gcp_user_access_bindings(organization_id)
        if bindings:
            org_entry = self['organizations'].setdefault(organization_id, {'gcp_user_access_bindings': {}})
            for binding in bindings:
                binding_id, binding_data = self._parse_binding(binding)
                org_entry['gcp_user_access_bindings'][binding_id] = binding_data
            org_entry['gcp_user_access_bindings_count'] = len(org_entry['gcp_user_access_bindings'])

    def _parse_policy(self, policy: dict, organization_id: str):
        name = policy.get('name', '')
        policy_id = get_non_provider_id(name) if name else get_non_provider_id(policy.get('title', 'policy'))
        policy_dict = {
            'id': policy_id,
            'name': name,
            'title': policy.get('title'),
            'scopes': policy.get('scopes', []),
            'create_time': policy.get('createTime'),
            'update_time': policy.get('updateTime'),
            'etag': policy.get('etag'),
            'organization_id': organization_id,
            'service_perimeters': {},
            'access_levels': {}
        }
        return policy_id, policy_dict

    def _parse_service_perimeter(self, perimeter: dict, project_number_to_id: dict):
        name = perimeter.get('name', '')
        perimeter_id = get_non_provider_id(name) if name else get_non_provider_id(perimeter.get('title', 'perimeter'))
        status = perimeter.get('status', {}) or {}
        resources = status.get('resources', []) or []
        mapped_projects = []
        unresolved_numbers = []
        project_numbers = []
        for resource in resources:
            if isinstance(resource, str) and resource.startswith('projects/'):
                number = resource.split('/', 1)[1]
                project_numbers.append(number)
                project_id = project_number_to_id.get(number)
                if project_id:
                    mapped_projects.append(project_id)
                else:
                    unresolved_numbers.append(number)
        access_level_names = status.get('accessLevels', []) or []
        access_level_ids = [get_non_provider_id(level) for level in access_level_names]

        perimeter_dict = {
            'id': perimeter_id,
            'name': name,
            'title': perimeter.get('title'),
            'description': perimeter.get('description'),
            'create_time': perimeter.get('createTime'),
            'update_time': perimeter.get('updateTime'),
            'status': status,
            'spec': perimeter.get('spec', {}),
            'project_numbers': project_numbers,
            'project_ids': mapped_projects,
            'unresolved_project_numbers': unresolved_numbers,
            'access_level_names': access_level_names,
            'access_level_ids': access_level_ids
        }
        return perimeter_id, perimeter_dict

    def _parse_access_level(self, access_level: dict):
        name = access_level.get('name', '')
        level_id = get_non_provider_id(name) if name else get_non_provider_id(access_level.get('title', 'accesslevel'))
        level_dict = {
            'id': level_id,
            'name': name,
            'title': access_level.get('title'),
            'description': access_level.get('description'),
            'create_time': access_level.get('createTime'),
            'update_time': access_level.get('updateTime'),
            'basic': access_level.get('basic', {}),
            'custom': access_level.get('custom', {})
        }
        return level_id, level_dict

    def _parse_binding(self, binding: dict):
        name = binding.get('name', '')
        binding_id = get_non_provider_id(name) if name else get_non_provider_id(binding.get('groupKey', {}).get('id', 'binding'))
        binding_dict = {
            'id': binding_id,
            'name': name,
            'group_key': binding.get('groupKey', {}),
            'access_levels': binding.get('accessLevels', []),
            'create_time': binding.get('createTime'),
            'update_time': binding.get('updateTime')
        }
        return binding_id, binding_dict

    def _assign_perimeter_to_projects(self, perimeter: dict, policy_id: str, policy_data: dict,
                                      project_id_to_number: dict):
        for project_id in perimeter['project_ids']:
            project_entry = self._ensure_project_entry(project_id, project_id_to_number.get(project_id))
            project_entry['service_perimeters'][perimeter['id']] = {
                'id': perimeter['id'],
                'name': perimeter.get('name'),
                'title': perimeter.get('title'),
                'description': perimeter.get('description'),
                'status': perimeter.get('status', {}),
                'spec': perimeter.get('spec', {}),
                'policy_id': policy_id,
                'policy_name': policy_data.get('name'),
                'policy_title': policy_data.get('title'),
                'access_level_ids': perimeter.get('access_level_ids', []),
                'access_level_names': perimeter.get('access_level_names', []),
                'restricted_services': perimeter.get('status', {}).get('restrictedServices', []),
                'project_numbers': perimeter.get('project_numbers', [])
            }
            project_entry['policies'][policy_id] = {
                'id': policy_id,
                'name': policy_data.get('name'),
                'title': policy_data.get('title'),
                'scopes': policy_data.get('scopes', []),
                'organization_id': policy_data.get('organization_id')
            }
            for level_id in perimeter.get('access_level_ids', []):
                level = policy_data['access_levels'].get(level_id)
                if level:
                    project_entry['access_levels'][level_id] = level

    def _ensure_project_entry(self, project_id: str, project_number: str):
        if project_id not in self['projects']:
            self['projects'][project_id] = {
                'project_number': project_number,
                'service_perimeters': {},
                'access_levels': {},
                'policies': {}
            }
        return self['projects'][project_id]
