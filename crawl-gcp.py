#!/usr/bin/env python3

import json
import logging
from googleapiclient._auth import authorized_http
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from oauth2client.service_account import ServiceAccountCredentials

logger = logging.getLogger('crawl-gcp')
logger.setLevel(logging.INFO)
logging.getLogger('googleapiclient.http').setLevel(logging.ERROR)


class CrawlGcp:
    def __init__(self, credentials_file):
        self._services = {}
        self._zones = {}
        self._regions = {}
        scope = [
            'https://www.googleapis.com/auth/cloud-platform.read-only',
            'https://www.googleapis.com/auth/compute.readonly',
        ]
        self._creds = ServiceAccountCredentials.from_json_keyfile_name('credentials.json', scope)
        self._authorized_http = authorized_http(self._creds)
        self._resources = {}
        self._all_links = set()

    def get_missing_resources(self):
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
                    response = self.get_resource_by_uri(uri)
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
        self._dump_json('missing', 'resources', missing_resources)

    def get_resource_by_uri(self, uri):
        resp, content = self._authorized_http.request(uri)
        if resp.status != 200:
            raise HttpError(resp, content, uri=uri)
        try:
            return json.loads(content.decode('utf-8'))
        except:
            raise HttpError(resp, content, uri=uri)


    def get_all_projects(self):
        logger.info('Fetching all projects...')
        cloudresourcemanager = self._get_service('cloudresourcemanager', 'v1')
        next_page_token = None
        projects = []
        while True:
            response = cloudresourcemanager.projects().list(pageToken=next_page_token).execute()
            for project in response['projects']:
                if project['lifecycleState'] == 'ACTIVE':
                    projects.append(project)
            if 'nextPageToken' in response:
                next_page_token = response['nextPageToken']
            else:
                break
        return projects

    def dump_project_info(self, project):
        service = self._get_service('compute', 'v1')
        response = service.projects().get(project=project).execute()
        if 'selfLink' in response:
            self._resources[response['selfLink']] = response
            self._collect_all_links(response)
        self._dump_json(project, 'get', response)

    def dump_aggregated_list(self, service_name, version, method, project):
        data = self.get_aggregated_list(service_name, version, method, project)
        for resource_list in data.values():
            for resource in resource_list:
                if 'selfLink' in resource:
                    self._resources[resource['selfLink']] = resource
                    self._collect_all_links(resource)
        self._dump_json(project, method, data)

    def get_aggregated_list(self, service_name, version, method, project):
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

    def dump_list(self, service_name, version, method, project):
        data = self.get_list(service_name, version, method, project)
        for resource in data:
            if 'selfLink' in resource:
                self._resources[resource['selfLink']] = resource
                self._collect_all_links(resource)
        self._dump_json(project, method, data)

    def get_list(self, service_name, version, method, project):
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

    def store_resources(self):
        with open('resources.json', 'w') as f:
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

    def _dump_json(self, project, method, data):
        if data:
            with open(f'cache/{project}-{method}.json', 'w') as f:
                json.dump(data, f, sort_keys=True)

    def _get_service(self, service, version):
        if service not in self._services:
            self._services[service] = {}

        if version not in self._services[service]:
            self._services[service][version] = build(service, version, credentials=self._creds)
        return self._services[service][version]


def dump_json(filename, data):
    if data:
        with open(f'cache/{filename}.json', 'w') as f:
            json.dump(data, f, sort_keys=True)


if __name__ == '__main__':
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    crawler = CrawlGcp(credentials_file='credentials.json')
    projects = crawler.get_all_projects()
    dump_json('projects', projects)

    total = len(projects)
    i = 0
    for project in projects:
        i += 1
        project_id= project['projectId']
        logger.info(f'[{i}/{total}] Fetching resources for {project_id} ...')
        #compute
        try:
            crawler.dump_project_info(project_id)
            crawler.dump_aggregated_list('compute', 'v1', 'acceleratorTypes', project_id)
            crawler.dump_aggregated_list('compute', 'v1', 'addresses', project_id)
            crawler.dump_aggregated_list('compute', 'v1', 'autoscalers', project_id)
            crawler.dump_aggregated_list('compute', 'v1', 'backendServices', project_id)
            crawler.dump_aggregated_list('compute', 'v1', 'disks', project_id)
            crawler.dump_aggregated_list('compute', 'v1', 'diskTypes', project_id)
            crawler.dump_aggregated_list('compute', 'v1', 'forwardingRules', project_id)
            crawler.dump_aggregated_list('compute', 'v1', 'globalOperations', project_id)
            crawler.dump_aggregated_list('compute', 'v1', 'instanceGroupManagers', project_id)
            crawler.dump_aggregated_list('compute', 'v1', 'instanceGroups', project_id)
            crawler.dump_aggregated_list('compute', 'v1', 'instances', project_id)
            crawler.dump_aggregated_list('compute', 'v1', 'interconnectAttachments', project_id)
            crawler.dump_aggregated_list('compute', 'v1', 'machineTypes', project_id)
            crawler.dump_aggregated_list('compute', 'v1', 'networkEndpointGroups', project_id)
            crawler.dump_aggregated_list('compute', 'v1', 'nodeGroups', project_id)
            crawler.dump_aggregated_list('compute', 'v1', 'nodeTemplates', project_id)
            crawler.dump_aggregated_list('compute', 'v1', 'nodeTypes', project_id)
            crawler.dump_aggregated_list('compute', 'v1', 'regionCommitments', project_id)
            crawler.dump_aggregated_list('compute', 'v1', 'reservations', project_id)
            crawler.dump_aggregated_list('compute', 'v1', 'resourcePolicies', project_id)
            crawler.dump_aggregated_list('compute', 'v1', 'routers', project_id)
            crawler.dump_aggregated_list('compute', 'v1', 'subnetworks', project_id)
            crawler.dump_aggregated_list('compute', 'v1', 'targetInstances', project_id)
            crawler.dump_aggregated_list('compute', 'v1', 'targetPools', project_id)
            crawler.dump_aggregated_list('compute', 'v1', 'targetVpnGateways', project_id)
            crawler.dump_aggregated_list('compute', 'v1', 'vpnTunnels', project_id)

            crawler.dump_list('compute', 'v1', 'backendBuckets', project_id)
            crawler.dump_list('compute', 'v1', 'firewalls', project_id)
            crawler.dump_list('compute', 'v1', 'globalAddresses', project_id)
            crawler.dump_list('compute', 'v1', 'globalForwardingRules', project_id)
            crawler.dump_list('compute', 'v1', 'healthChecks', project_id)
            crawler.dump_list('compute', 'v1', 'httpHealthChecks', project_id)
            crawler.dump_list('compute', 'v1', 'httpsHealthChecks', project_id)
            crawler.dump_list('compute', 'v1', 'images', project_id)
            crawler.dump_list('compute', 'v1', 'instanceTemplates', project_id)
            crawler.dump_list('compute', 'v1', 'interconnectLocations', project_id)
            crawler.dump_list('compute', 'v1', 'interconnects', project_id)
            crawler.dump_list('compute', 'v1', 'licenses', project_id)
            crawler.dump_list('compute', 'v1', 'networks', project_id)
            crawler.dump_list('compute', 'v1', 'regions', project_id)
            crawler.dump_list('compute', 'v1', 'routes', project_id)
            crawler.dump_list('compute', 'v1', 'securityPolicies', project_id)
            crawler.dump_list('compute', 'v1', 'snapshots', project_id)
            crawler.dump_list('compute', 'v1', 'sslCertificates', project_id)
            crawler.dump_list('compute', 'v1', 'sslPolicies', project_id)
            crawler.dump_list('compute', 'v1', 'targetHttpProxies', project_id)
            crawler.dump_list('compute', 'v1', 'targetHttpsProxies', project_id)
            crawler.dump_list('compute', 'v1', 'targetSslProxies', project_id)
            crawler.dump_list('compute', 'v1', 'targetTcpProxies', project_id)
            crawler.dump_list('compute', 'v1', 'urlMaps', project_id)
            crawler.dump_list('compute', 'v1', 'zones', project_id)

        except HttpError as e:
            if e.resp.status == 403:
                logger.info(f'Compute api not enabled for {project_id}')
            else:
                raise e
    crawler.get_missing_resources()
    crawler.store_resources()
