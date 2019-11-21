import json
import logging
import os
from googleapiclient._auth import authorized_http
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError


logger = logging.getLogger('crawl-gcp')
logger.setLevel(logging.INFO)
logging.getLogger('googleapiclient.http').setLevel(logging.ERROR)
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)


class CrawlGcp:
    def __init__(self, credentials, output_dir):
        self._services = {}
        self._zones = {}
        self._regions = {}
        self._creds = credentials
        self._authorized_http = authorized_http(self._creds)
        self._resources = {}
        self._all_links = set()
        self._output_dir = output_dir
        self._organization_id = None
        self._projects = []
        self._folders = []
        self._datasets = []

    def scan_organization(self, organization_id):
        self._organization_id = organization_id

    def scan_projects(self, projects):
        self._projects = projects

    def crawl(self):
        projects = []
        if self._organization_id:
            projects += self._get_projects_by_organization()
        if self._projects:
            projects += self._get_requested_projects()

        if not projects:
            projects = self._get_all_projects()
        self._dump_json('projects', data=projects)

        total = len(projects)
        i = 0
        for project in projects:
            i += 1
            project_id= project['projectId']
            logger.info(f'[{i}/{total}] Fetching resources for {project_id} ...')
            self._crawl_compute(project_id)
            self._crawl_resourcemanager(project_id)
            self._crawl_iam(project_id)
            self._crawl_storage(project_id)
            self._crawl_bigquery(project_id)

        self._get_folder_and_org_iam()
        self._get_missing_resources()
        self._store_resources()

    def _crawl_compute(self, project_id):
        try:
            logger.info(f'Crawling compute for {project_id} ...')
            self._dump_project_info(project_id)
            self._dump_aggregated_list('compute', 'v1', 'acceleratorTypes', project_id)
            self._dump_aggregated_list('compute', 'v1', 'addresses', project_id)
            self._dump_aggregated_list('compute', 'v1', 'autoscalers', project_id)
            self._dump_aggregated_list('compute', 'v1', 'backendServices', project_id)
            self._dump_aggregated_list('compute', 'v1', 'disks', project_id)
            self._dump_aggregated_list('compute', 'v1', 'diskTypes', project_id)
            self._dump_aggregated_list('compute', 'v1', 'forwardingRules', project_id)
            self._dump_aggregated_list('compute', 'v1', 'globalOperations', project_id)
            self._dump_aggregated_list('compute', 'v1', 'instanceGroupManagers', project_id)
            self._dump_aggregated_list('compute', 'v1', 'instanceGroups', project_id)
            self._dump_aggregated_list('compute', 'v1', 'instances', project_id)
            self._dump_aggregated_list('compute', 'v1', 'interconnectAttachments', project_id)
            self._dump_aggregated_list('compute', 'v1', 'machineTypes', project_id)
            self._dump_aggregated_list('compute', 'v1', 'networkEndpointGroups', project_id)
            self._dump_aggregated_list('compute', 'v1', 'nodeGroups', project_id)
            self._dump_aggregated_list('compute', 'v1', 'nodeTemplates', project_id)
            self._dump_aggregated_list('compute', 'v1', 'nodeTypes', project_id)
            self._dump_aggregated_list('compute', 'v1', 'regionCommitments', project_id)
            self._dump_aggregated_list('compute', 'v1', 'reservations', project_id)
            self._dump_aggregated_list('compute', 'v1', 'resourcePolicies', project_id)
            self._dump_aggregated_list('compute', 'v1', 'routers', project_id)
            self._dump_aggregated_list('compute', 'v1', 'subnetworks', project_id)
            self._dump_aggregated_list('compute', 'v1', 'targetInstances', project_id)
            self._dump_aggregated_list('compute', 'v1', 'targetPools', project_id)
            self._dump_aggregated_list('compute', 'v1', 'targetVpnGateways', project_id)
            self._dump_aggregated_list('compute', 'v1', 'vpnTunnels', project_id)

            self._dump_list('compute', 'v1', 'backendBuckets', project_id)
            self._dump_list('compute', 'v1', 'firewalls', project_id)
            self._dump_list('compute', 'v1', 'globalAddresses', project_id)
            self._dump_list('compute', 'v1', 'globalForwardingRules', project_id)
            self._dump_list('compute', 'v1', 'healthChecks', project_id)
            self._dump_list('compute', 'v1', 'httpHealthChecks', project_id)
            self._dump_list('compute', 'v1', 'httpsHealthChecks', project_id)
            self._dump_list('compute', 'v1', 'images', project_id)
            self._dump_list('compute', 'v1', 'instanceTemplates', project_id)
            self._dump_list('compute', 'v1', 'interconnectLocations', project_id)
            self._dump_list('compute', 'v1', 'interconnects', project_id)
            self._dump_list('compute', 'v1', 'licenses', project_id)
            self._dump_list('compute', 'v1', 'networks', project_id)
            self._dump_list('compute', 'v1', 'regions', project_id)
            self._dump_list('compute', 'v1', 'routes', project_id)
            self._dump_list('compute', 'v1', 'securityPolicies', project_id)
            self._dump_list('compute', 'v1', 'snapshots', project_id)
            self._dump_list('compute', 'v1', 'sslCertificates', project_id)
            self._dump_list('compute', 'v1', 'sslPolicies', project_id)
            self._dump_list('compute', 'v1', 'targetHttpProxies', project_id)
            self._dump_list('compute', 'v1', 'targetHttpsProxies', project_id)
            self._dump_list('compute', 'v1', 'targetSslProxies', project_id)
            self._dump_list('compute', 'v1', 'targetTcpProxies', project_id)
            self._dump_list('compute', 'v1', 'urlMaps', project_id)
            self._dump_list('compute', 'v1', 'zones', project_id)

        except HttpError as e:
            if e.resp.status == 403:
                logger.info(f'Compute api not enabled for {project_id}')
            else:
                raise e

    def _crawl_resourcemanager(self, project_id):
        logger.info(f'Crawling resource manager for {project_id} ...')
        self._dump_constaints(project_id)
        self._dump_liens(project_id)
        self._dump_projectIamPolicies(project_id)

    def _crawl_iam(self, project_id):
        logger.info(f'Crawling iam for {project_id} ...')
        self._dump_serviceaccounts(project_id)

    def _crawl_storage(self, project_id):
        logger.info(f'Crawling storage for {project_id} ...')
        self._dump_storage(project_id)

    def _crawl_bigquery(self, project_id):
        logger.info(f'Crawling bigquery for {project_id} ...')
        self._dump_datasets(project_id)
        self._dump_tables(project_id)
        self._datasets = []

    def _get_missing_resources(self):
        missing_resources = []
        while True:
            logger.info(f'Finding missing resources...')
            missing_links = []
            for link in self._all_links:
                if link not in self._resources:
                    missing_links.append(link)
            if not missing_links:
                break

            for uri in missing_links:
                try:
                    logger.info(f'Fetching {uri}...')
                    response = self._get_resource_by_uri(uri)
                    self._collect_all_links(response)
                except HttpError as e:
                    if e.resp.status in [403, 404]:
                        reason = e._get_reason()
                        logger.warning(f'Error: {reason}')
                        response = {
                            'error': {
                                'reason': reason,
                                'status': e.resp.status,
                            },
                            'selfLink': uri,
                        }
                    else:
                        raise e
                missing_resources.append(response)
                self._resources[uri] = response
        logger.info(f'Done fetching missing resources')
        self._dump_json('missing-resources', data=missing_resources)

    def _get_resource_by_uri(self, uri):
        resp, content = self._authorized_http.request(uri)
        if resp.status != 200:
            raise HttpError(resp, content, uri=uri)
        try:
            return json.loads(content.decode('utf-8'))
        except:
            raise HttpError(resp, content, uri=uri)

    def _get_projects_by_organization(self):
        projects = []
        logger.info(f'Finding projects in organization {self._organization_id}...')

        org_resource = f'organizations/{self._organization_id}'
        resourcemanager_v1 = self._get_service('cloudresourcemanager', 'v1')
        try:
            response = resourcemanager_v1.organizations().get(name=org_resource).execute()
        except HttpError as e:
            if e.resp.status == 403:
                logger.warning(f'Not allowed to crawl organization {self._organization_id}')
            elif e.resp.status == 404:
                logger.warning(f'Could not find organization {self._organization_id}')
            else:
                raise e
            return projects
        self._dump_json('organization', data=response)

        self._folders = []
        resourcemanager_v2 = self._get_service('cloudresourcemanager', 'v2')
        try:
            backlog = [org_resource]
            while backlog:
                next_item = backlog.pop(0)
                next_page_token = None
                while True:
                    response = resourcemanager_v2.folders().list(parent=next_item, pageToken=next_page_token).execute()
                    for folder in response.get('folders', []):
                        if folder['lifecycleState'] == 'ACTIVE':
                            self._folders.append(folder)
                            backlog.append(folder['name'])
                    if 'nextPageToken' in response:
                        next_page_token = response['nextPageToken']
                    else:
                        break
        except HttpError as e:
            if e.resp.status == 403:
                logger.warning(f'Not allowed to list folders in organization {self._organization_id}')
            else:
                raise e
        self._dump_json('folders', data=self._folders)

        filters = [
            f'parent.type:organization parent.id:{self._organization_id}'
        ]
        for folder in self._folders:
            folder_id = folder['name'].split('/')[1]
            folder_filter = f'parent.type:folder parent.id:{folder_id}'
            filters.append(folder_filter)

        for resource_filter in filters:
            try:
                next_page_token = None
                while True:
                    response = resourcemanager_v1.projects().list(filter=resource_filter, pageToken=next_page_token).execute()
                    for project in response.get('projects', []):
                        if project['lifecycleState'] == 'ACTIVE':
                            projects.append(project)
                    if 'nextPageToken' in response:
                        next_page_token = response['nextPageToken']
                    else:
                        break
            except HttpError as e:
                if e.resp.status == 403:
                    logger.warning(f'Not allowed to list projects for filter {resource_filter}')
                else:
                    raise e
        return projects


    def _get_all_projects(self):
        logger.info('Fetching all projects...')
        cloudresourcemanager = self._get_service('cloudresourcemanager', 'v1')
        next_page_token = None
        projects = []
        while True:
            response = cloudresourcemanager.projects().list(pageToken=next_page_token).execute()
            for project in response.get('projects', []):
                if project['lifecycleState'] == 'ACTIVE':
                    projects.append(project)
            if 'nextPageToken' in response:
                next_page_token = response['nextPageToken']
            else:
                break
        return projects

    def _get_requested_projects(self):
        logger.info(f'Fetching projects {self._projects}...')
        cloudresourcemanager = self._get_service('cloudresourcemanager', 'v1')
        projects = []
        for project in self._projects:
            response = cloudresourcemanager.projects().list(filter=f'name:{project}').execute()
            for project in response.get('projects', []):
                if project['lifecycleState'] == 'ACTIVE':
                    projects.append(project)
        return projects

    def _dump_project_info(self, project):
        service = self._get_service('compute', 'v1')
        response = service.projects().get(project=project).execute()
        if 'selfLink' in response:
            self._resources[response['selfLink']] = response
            self._collect_all_links(response)
        self._dump_json(project, service='compute', method='get', data=response)

    def _dump_aggregated_list(self, service_name, version, method, project):
        data = self._get_aggregated_list(service_name, version, method, project)
        for resource_list in data.values():
            for resource in resource_list:
                if 'selfLink' in resource:
                    self._resources[resource['selfLink']] = resource
                    self._collect_all_links(resource)
        self._dump_json(project, service='compute', method=method, data=data)

    def _get_aggregated_list(self, service_name, version, method, project):
        service = self._get_service(service_name, version)
        next_page_token = None
        aggregated_list = {}
        while True:
            response = getattr(service, method)().aggregatedList(project=project, pageToken=next_page_token).execute()
            for zone, data in response['items'].items():
                if method in data:
                    if zone not in aggregated_list:
                        aggregated_list[zone] = []
                    aggregated_list[zone] += data[method]
            if 'nextPageToken' in response:
                next_page_token = response['nextPageToken']
            else:
                break
        return aggregated_list

    def _dump_list(self, service_name, version, method, project):
        data = self._get_list(service_name, version, method, project)
        for resource in data:
            if 'selfLink' in resource:
                self._resources[resource['selfLink']] = resource
                self._collect_all_links(resource)
        self._dump_json(project, service=service_name, method=method, data=data)

    def _get_list(self, service_name, version, method, project):
        service = self._get_service(service_name, version)
        next_page_token = None
        data = []
        while True:
            response = getattr(service, method)().list(project=project, pageToken=next_page_token).execute()
            if 'items' in response:
                data += response['items']
            if 'nextPageToken' in response:
                next_page_token = response['nextPageToken']
            else:
                break
        return data

    def _dump_constaints(self, project_id):
        service = self._get_service('cloudresourcemanager', 'v1')
        next_page_token = None
        constraint_list = []
        resource = f'projects/{project_id}'
        while True:
            body = {
                'pageToken': next_page_token,
            }
            response = service.projects().listAvailableOrgPolicyConstraints(resource=resource, body=body).execute()
            if 'constraints' in response:
                constraint_list += response['constraints']
            if 'nextPageToken' in response:
                next_page_token = response['nextPageToken']
            else:
                break

        constraints = {}
        for constraint in constraint_list:
            body = {
                'constraint': constraint['name']
            }
            name = constraint['name'].split('/')[1]
            response = service.projects().getEffectiveOrgPolicy(resource=resource, body=body).execute()
            for key, value in response.items():
                if key != 'constraint':
                    constraint[key] = value
            constraints[name] = constraint
        self._dump_json(project_id, service='cloudresourcemanager', method='listEffectiveOrgPolicies', data=constraints)

    def _dump_liens(self, project_id):
        service = self._get_service('cloudresourcemanager', 'v1')
        next_page_token = None
        liens = []
        resource = f'projects/{project_id}'
        while True:
            response = service.liens().list(parent=resource, pageToken=next_page_token).execute()
            if 'liens' in response:
                liens += response['liens']
            if 'nextPageToken' in response:
                next_page_token = response['nextPageToken']
            else:
                break
        self._dump_json(project_id, service='cloudresourcemanager', method='listLiens', data=liens)

    def _dump_projectIamPolicies(self, project_id):
        service = self._get_service('cloudresourcemanager', 'v1')
        response = service.projects().getIamPolicy(resource=project_id, body={}).execute()
        bindings = response.get('bindings', [])
        self._dump_json(project_id, service='cloudresourcemanager', method='getIamPolicies', data=bindings)

    def _get_folder_and_org_iam(self):
        if self._organization_id:
            service_v1 = self._get_service('cloudresourcemanager', 'v1')
            try:
                resource = f'organizations/{self._organization_id}'
                response = service_v1.organizations().getIamPolicy(resource=resource, body={}).execute()
                bindings = response.get('bindings', [])
                self._dump_json(f'organization_{self._organization_id}', service='cloudresourcemanager', method='getIamPolicies', data=bindings)
            except HttpError as e:
                if e.resp.status == 403:
                    logger.warning(f'Not allowed to get iamPolicies for organization {self._organization_id}')
                else:
                    raise e
        if self._folders:
            service_v2 = self._get_service('cloudresourcemanager', 'v2')
            for folder in self._folders:
                try:
                    folder_id = folder['name'].split('/')[1]
                    response = service_v2.folders().getIamPolicy(resource=folder['name'], body={}).execute()
                    bindings = response.get('bindings', [])
                    self._dump_json(f'folder_{folder_id}', service='cloudresourcemanager', method='getIamPolicies', data=bindings)
                except HttpError as e:
                    if e.resp.status == 403:
                        logger.warning(f'Not allowed to get iamPolicies for folder {folder_id}')
                    else:
                        raise e

    def _dump_serviceaccounts(self, project_id):
        service = self._get_service('iam', 'v1')
        next_page_token = None
        serviceaccounts = []
        resource = f'projects/{project_id}'
        while True:
            response = service.projects().serviceAccounts().list(name=resource, pageToken=next_page_token).execute()
            if 'accounts' in response:
                serviceaccounts += response['accounts']
            if 'nextPageToken' in response:
                next_page_token = response['nextPageToken']
            else:
                break
        self._dump_json(project_id, service='iam', method='listServiceAccounts', data=serviceaccounts)

        for sa in serviceaccounts:
            response = service.projects().serviceAccounts().keys().list(name=sa['name']).execute()
            keys = response.get('keys', [])
            sa_name = sa['name'].split('/')[-1]
            self._dump_json(project_id, service='iam', method=f'{sa_name}.keys', data=keys)

    def _dump_storage(self, project_id):
        service = self._get_service('storage', 'v1')
        next_page_token = None
        buckets = []
        resource = f'projects/{project_id}'
        while True:
            response = service.buckets().list(project=project_id, pageToken=next_page_token, projection='full').execute()
            if 'items' in response:
                buckets += response['items']
            if 'nextPageToken' in response:
                next_page_token = response['nextPageToken']
            else:
                break
        self._dump_json(project_id, service='storage', method='listBuckets', data=buckets)

        for bucket in buckets:
            try:
                response = service.buckets().getIamPolicy(bucket=bucket['name']).execute()
                self._dump_json(project_id, service='storage', method=f'bucket.{bucket["name"]}.getIamPolicy', data=response)
            except HttpError as e:
                if e.resp.status == 403:
                    logger.warning(f'Not allowed to get iamPolicies for bucket {bucket["name"]}')
                else:
                    raise e

    def _dump_datasets(self, project_id):
        try:
            service = self._get_service('bigquery', 'v2')
            next_page_token = None
            self._datasets = []
            while True:
                response = service.datasets().list(projectId=project_id, pageToken=next_page_token).execute()
                if 'datasets' in response:
                    self._datasets += response['datasets']
                if 'nextPageToken' in response:
                    next_page_token = response['nextPageToken']
                else:
                    break
            self._dump_json(project_id, service='bigquery', method='listDatasets', data=self._datasets)
        except HttpError as e:
            if e.resp.status == 400:
                logger.info(f'Bigquery not enabled for {project_id}')
                return
            else:
                raise e

        for dataset in self._datasets:
            try:
                dataset_id = dataset['datasetReference']['datasetId']
                response = service.datasets().get(projectId=project_id, datasetId=dataset_id).execute()
                self._dump_json(project_id, service='bigquery', method=f'dataset.{dataset_id}', data=response)
            except HttpError as e:
                if e.resp.status == 403:
                    logger.warning(f'Not allowed to get dataset {dataset_id}')
                else:
                    raise e

    def _dump_tables(self, project_id):
        service = self._get_service('bigquery', 'v2')

        for dataset in self._datasets:
            dataset_id = dataset['datasetReference']['datasetId']
            next_page_token = None
            tables = []
            while True:
                response = service.tables().list(projectId=project_id, datasetId=dataset_id, pageToken=next_page_token).execute()
                if 'tables' in response:
                    tables += response['tables']
                if 'nextPageToken' in response:
                    next_page_token = response['nextPageToken']
                else:
                    break
            self._dump_json(project_id, service='bigquery', method=f'tableList.{dataset_id}', data=tables)

            for table in tables:
                try:
                    table_id = table['tableReference']['tableId']
                    response = service.tables().get(projectId=project_id, datasetId=dataset_id, tableId=table_id).execute()
                    self._dump_json(project_id, service='bigquery', method=f'table.{dataset_id}.{table_id}', data=response)
                except HttpError as e:
                    if e.resp.status == 403:
                        logger.warning(f'Not allowed to get table {table_id} in dataset {dataset_id}')
                    else:
                        raise e

    def _store_resources(self):
        with open(f'{self._output_dir}/resources.json', 'w') as f:
            json.dump(self._resources, f, sort_keys=True)

    def _collect_all_links(self, resource):
        if type(resource) == list:
            resources = resource
        elif type(resource) == dict:
            resources = resource.values()
        else:
            raise Exception('must be dict or list')

        for value in resources:
            if type(value) == str:
                if value.startswith('https://www.googleapis.com/') and not value.startswith('https://www.googleapis.com/auth/'):
                    self._all_links.add(value)
            elif type(value) in [dict, list]:
                self._collect_all_links(value)

    def _dump_json(self, base_name, service=None, method=None, data=None):
        if not data:
            return
        dirs = [self._output_dir]
        if not service and not method:
            filename = f'{base_name}.json'
        elif service and not method:
            dirs.append(base_name)
            filename = f'{service}.json'
        elif not service and method:
            dirs.append(base_name)
            filename = f'{method}.json'
        else:
            dirs += [base_name, service]
            filename = f'{method}.json'

        directory = os.path.join(*dirs)
        os.makedirs(directory, exist_ok=True)
        with open(os.path.join(directory, filename), 'w') as f:
            json.dump(data, f, sort_keys=True)

    def _get_service(self, service, version):
        if service not in self._services:
            self._services[service] = {}

        if version not in self._services[service]:
            self._services[service][version] = build(service, version, credentials=self._creds)
        return self._services[service][version]
