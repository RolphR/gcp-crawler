#!/usr/bin/env python3

import json
import os
import shutil
from crawl_gcp import CrawlGcp


def get_credentials(source='application-default'):
    if source == 'application-default':
        from oauth2client.client import GoogleCredentials
        return GoogleCredentials.get_application_default()
    elif source == 'service-account':
        from oauth2client.service_account import ServiceAccountCredentials
        scope = [
            'https://www.googleapis.com/auth/cloud-platform.read-only',
            'https://www.googleapis.com/auth/compute.readonly',
            'https://www.googleapis.com/auth/devstorage.full_control',
            'https://www.googleapis.com/auth/iam',
        ]
        return ServiceAccountCredentials.from_json_keyfile_name('credentials.json', scope)


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Crawl GCP organization or projects')
    parser.add_argument('-c', '--credentials',
                        choices=['application-default', 'service-account'],
                        default='application-default',
                        help='What credentials to use. service-account credentials are stored in credentials.json'
                        )
    parser.add_argument('-o', '--organization',
                        default=None,
                        help='Organization ID to scan'
                        )
    parser.add_argument('-p', '--projects',
                        nargs='+',
                        type=str,
                        default=[],
                        help='Projects to scan'
                        )
    parser.add_argument('-d', '--output-dir',
                        type=str,
                        default='data',
                        help='Output directory'
                        )
    args = parser.parse_args()

    try:
        shutil.rmtree(args.output_dir)
    except:
        pass
    os.mkdir(args.output_dir)

    credentials = get_credentials(args.credentials)
    crawler = CrawlGcp(credentials = credentials, output_dir=args.output_dir)

    if args.organization:
        crawler.scan_organization(args.organization)

    if args.projects:
        crawler.scan_projects(args.projects)

    crawler.crawl()
