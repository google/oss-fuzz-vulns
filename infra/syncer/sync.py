# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""OSS-Fuzz -> OSV feed Syncer."""

import argparse
import json
import logging
import os
import pprint
import re
import urllib.request
import urllib.parse

from google.cloud import datastore
from google.cloud.datastore.query import PropertyFilter
from google.cloud import pubsub_v1
from google.cloud import storage
import yaml

from google_issue_tracker import client
from google_issue_tracker import issue_tracker

_TASKS_TOPIC = 'projects/oss-vdb/topics/tasks'

_LOOKBACK_DAYS = 14

_QUERY = ('modified>today-{lookback_days} type:vulnerability '
          '-title:"build failure" componentid:1638179')

_SEVERITY_MAP = {
    0: 'Critical',
    1: 'High',
    2: 'Medium',
    3: 'Low',
    4: 'Missing',
}


def main():
  logging.basicConfig(level=logging.INFO)

  parser = argparse.ArgumentParser()
  parser.add_argument(
      '--oss-fuzz-dir',
      type=str,
      required=True,
      help='Path to OSS-Fuzz checkout.')
  parser.add_argument(
      '--dry-run', action=argparse.BooleanOptionalAction, default=True)

  args = parser.parse_args()
  syncer = Syncer(args.oss_fuzz_dir, args.dry_run)
  syncer.sync()


class Syncer:
  """OSS-Fuzz -> OSV Syncer.
  
  OSS-Fuzz issues are partially bisected by ClusterFuzz. The granularity of the
  bisection depends on how frequent builds in OSS-Fuzz happen.

  OSV needs the exact commit that both introduces and fixes a vulnerability, so
  we need to do a finer-grained bisect starting from the revisions that
  ClusterFuzz has.
  """

  def __init__(self, oss_fuzz_dir: str, dry_run: bool):
    # TODO(ochang): Make the oss-fuzz-vulns repo the source of truth instead of
    # the OSV datastore. This means completely removing access to the OSV
    # datastore also.
    self.osv_db = datastore.Client(project='oss-vdb')
    # TODO(ochang): Use the OSS-Fuzz REST testcase JSON endpoint instead to
    # avoid depending directly on the OSS-Fuzz datastore.
    self.oss_fuzz_db = datastore.Client(project='clusterfuzz-external')
    # TODO(ochang): Migrate the actual bisection functionality out of OSV.
    self.osv_publisher = pubsub_v1.PublisherClient()
    self.oss_fuzz_dir = oss_fuzz_dir
    self.storage = storage.Client.create_anonymous_client()

    self.dry_run = dry_run

  def process_issue(self, issue: dict):
    """Process an OSS-Fuzz issue."""
    if is_wontfix(issue):
      logging.info('%s is wontfix', issue['issueId'])

      self.send_osv_request({
          'type': 'invalid',
          'testcase_id': self.get_oss_fuzz_testcase(issue['issueId']).key.id,
      })
      return

    cf_testcase = self.get_oss_fuzz_testcase(issue['issueId'])
    if not self.has_analyzed_regression(cf_testcase.key.id):
      logging.info('%s has not analyzed regression', cf_testcase.key.id)
      self.send_bisection_request(cf_testcase, 'regressed')

    if is_fixed(issue) and not self.has_analyzed_fixed(cf_testcase.key.id):
      logging.info('%s is fixed but has not analyzed fixed', cf_testcase.key.id)
      self.send_bisection_request(cf_testcase, 'fixed')

  def sync(self):
    """Runs the sync."""
    # Look through the past _LOOKBACK_DAYS to ensure updates are reflected in
    # the OSV feed.
    tracker = issue_tracker.IssueTracker(client.build())
    counter = 0

    for issue in tracker.find_issues(
        _QUERY.format(lookback_days=_LOOKBACK_DAYS)):
      counter += 1
      if counter % 10 == 0:
        logging.info('Processed %d issues', counter)

      try:
        self.process_issue(issue)
      except Exception:
        logging.error(
            'Failed to process issue %s', issue['issueId'], exc_info=True)

  def send_bisection_request(self, cf_testcase: datastore.Entity,
                             bisect_type: str):
    """Sends bisection request to OSV."""
    if bisect_type == 'regressed':
      commit_range = cf_testcase['regression']
    else:
      assert bisect_type == 'fixed'
      commit_range = cf_testcase['fixed']

    main_repo = get_main_repo(self.oss_fuzz_dir, cf_testcase['project_name'])
    try:
      # Map the ClusterFuzz-bisected build revision numbers into commit hashes
      # as starting points for OSV's bisection infra.
      old_commit, new_commit = get_commits(cf_testcase, main_repo, commit_range)
    except ValueError:
      logging.info(
          'Failed to extract bisected commit range. Deriving this instead.')
      # Create a best effort starting range for bisection.
      old_commit, new_commit = self.derive_commit_range(cf_testcase,
                                                        bisect_type, main_repo)

    request = {
        'type':
            bisect_type,
        'project_name':
            cf_testcase['project_name'],
        'sanitizer':
            get_sanitizer_name(cf_testcase['job_type']),
        'fuzz_target':
            json.loads(cf_testcase['additional_metadata'])
            ['fuzzer_binary_name'],
        'old_commit':
            old_commit,
        'new_commit':
            new_commit,
        'testcase_id':
            str(cf_testcase.key.id),
        'issue_id':
            cf_testcase['bug_information'],
        'crash_type':
            cf_testcase['crash_type'],
        'crash_state':
            cf_testcase['crash_state'],
        'security':
            str(cf_testcase['security_flag']),
        'timestamp':
            cf_testcase['timestamp'].isoformat(),
        'repo_url':
            main_repo,
    }

    if cf_testcase.get('security_severity'):
      request['severity'] = _SEVERITY_MAP[cf_testcase['security_severity']]

    self.send_osv_request(request)

  def send_osv_request(self, request: dict):
    """Sends a request to OSV."""
    logging.info('Sending request: %s', pprint.pformat(request, indent=2))
    if not self.dry_run:
      self.osv_publisher.publish(_TASKS_TOPIC, b'', **request)

  def get_oss_fuzz_testcase(self, issue_id: str) -> datastore.Entity:
    """Gets an OSS-Fuzz testcase entity from an issue ID."""
    query = self.oss_fuzz_db.query(kind='Testcase')
    query = query.add_filter(
        filter=PropertyFilter('bug_information', '=', issue_id))
    testcase = next(query.fetch(limit=1), None)
    if not testcase:
      raise ValueError(f'No testcase found for issue {issue_id}')

    return testcase

  def has_analyzed_regression(self, testcase_id: str) -> bool:
    key = self.osv_db.key('RegressResult', f'oss-fuzz:{testcase_id}')
    return bool(self.osv_db.get(key))

  def has_analyzed_fixed(self, testcase_id: str) -> bool:
    key = self.osv_db.key('FixResult', f'oss-fuzz:{testcase_id}')
    return bool(self.osv_db.get(key))

  def derive_commit_range(self, cf_testcase: datastore.Entity, bisect_type: str,
                          main_repo: str):
    """Derives a best effort commit range in absense of a valid
    ClusterFuzz-bisected revision range."""
    url_format = get_revisions_url_format(cf_testcase)

    # Get the very first and very last revision available.
    first_revision, last_revision = self.get_first_and_last_revision(
        cf_testcase)

    # Map them to commit hashes.
    first_commit = get_commit(
        url_format.format(revision=first_revision), main_repo)
    last_commit = get_commit(
        url_format.format(revision=last_revision), main_repo)
    crash_commit = get_commit(
        url_format.format(revision=cf_testcase['crash_revision']), main_repo)

    if bisect_type == 'regressed':
      # If we are bisecting for the the commit that introduced, the starting
      # range is (earliest build revision, crashing revision)
      return first_commit, crash_commit

    assert bisect_type == 'fixed'
    # If we are bisecting for the the commit that fixed, the starting
    # range is (crashing revision, lastest available build revision)
    return crash_commit, last_commit

  def get_first_and_last_revision(self, cf_testcase: datastore.Entity):
    """Gets the last and first revision number of the build for a testcase."""
    build_url = json.loads(cf_testcase['additional_metadata'])['build_url']
    # Turn the build URL into a regex that matches any revision number.
    build_url_pattern = re.sub(r'(\d+)\.zip$', r'(\\d+).zip', build_url)

    _, netloc, path, _, _ = urllib.parse.urlsplit(build_url_pattern)
    bucket = self.storage.get_bucket(netloc)
    directory, pattern = path.rsplit('/', maxsplit=1)

    first_revision = None
    last_revision = None

    blob_names = [
        blob.name for blob in bucket.list_blobs(
            prefix=directory.lstrip('/') + '/', delimiter='/')
    ]
    blob_names.sort()
    for blob in blob_names:
      match = re.match(pattern, os.path.basename(blob))
      if match:
        if first_revision is None:
          first_revision = match.group(1)

        last_revision = match.group(1)

    return first_revision, last_revision


def is_wontfix(issue):
  return issue['issueState']['status'] in ('NOT_REPRODUCIBLE',
                                           'INTENDED_BEHAVIOUR', 'OBSOLETE',
                                           'INFEASIBLE')


def is_fixed(issue):
  return issue['issueState']['status'] in ('FIXED', 'VERIFIED')


def get_sanitizer_name(job_type: str) -> str:
  """Gets the sanitizer name from a ClusterFuzz job type."""
  if '_asan' in job_type:
    return 'address'

  if '_msan' in job_type:
    return 'memory'

  if '_ubsan' in job_type:
    return 'undefined'

  raise ValueError('unknown sanitizer')


def get_revisions_url_format(cf_testcase: datastore.Entity):
  """Gets a format string for retrieving git commit information from an OSS-Fuzz
  revision number."""
  build_url = json.loads(cf_testcase['additional_metadata'])['build_url']
  build_url = build_url.replace('gs://', 'https://storage.googleapis.com/')
  return re.sub(r'(\d+)\.zip$', '{revision}.srcmap.json', build_url)


def get_commits(cf_testcase: datastore.Entity, main_repo: str,
                commit_range: str) -> tuple[str, str]:
  """Gets the commit hashes corresponding to an OSS-Fuzz ClusterFuzz commit
  range."""
  if not commit_range or commit_range == 'NA':
    raise ValueError(f'Invalid commit range "{commit_range}"')

  start_revision, end_revision = commit_range.split(':')

  url_format = get_revisions_url_format(cf_testcase)
  old_commit_srcmap_url = url_format.format(revision=start_revision)
  new_commit_srcmap_url = url_format.format(revision=end_revision)

  old_commit = get_commit(old_commit_srcmap_url, main_repo)
  new_commit = get_commit(new_commit_srcmap_url, main_repo)

  if old_commit == new_commit:
    # This indicates an infrastructure issue.
    raise ValueError('old_commit is equal to new_commit')

  return old_commit, new_commit


def get_commit(srcmap_url: str, main_repo: str) -> str:
  """Gets the relevant commit hash from an OSS-Fuzz srcmap."""
  with urllib.request.urlopen(srcmap_url) as f:
    srcmap = json.load(f)

  def normalize_url(url: str) -> str:
    return url.rstrip('/').removesuffix('.git')

  for entry in srcmap.values():
    if normalize_url(entry['url']) == normalize_url(main_repo):
      return entry['rev']

  raise ValueError(f'main repo {main_repo} not found in srcmap')


def get_main_repo(oss_fuzz_dir: str, project_name: str):
  """Gets the main repo for a given OSS-Fuzz project."""
  with open(
      os.path.join(oss_fuzz_dir, 'projects', project_name,
                   'project.yaml')) as f:
    project = yaml.safe_load(f)

  return project['main_repo']


if __name__ == '__main__':
  main()
