# Script to import failed OSS-Fuzz vulns for manual fixup.
import json
import os
import sys
import urllib.error
import urllib.request

import yaml

_BUCKET = 'oss-fuzz-osv-vulns'
_VULN_URL = f'https://{_BUCKET}.storage.googleapis.com/issue'
_ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _yaml_str_representer(dumper, data):
  """YAML str representer override."""
  if '\n' in data:
    return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')
  return dumper.represent_scalar('tag:yaml.org,2002:str', data)


class _YamlDumper(yaml.SafeDumper):
  """Overridden dumper to to use | for multiline strings."""


_YamlDumper.add_representer(str, _yaml_str_representer)


def main():
  if len(sys.argv) < 2:
    print(f'Usage: {sys.argv[0]} <oss-fuzz issue_id>')

  issue_id = sys.argv[1]
  try:
    data = urllib.request.urlopen(f'{_VULN_URL}/{issue_id}.json').read()
  except urllib.error.HTTPError:
    print('Vuln does not exist. OSS-Fuzz bugs need to '
          'be marked as security to be included.', file=sys.stderr)
    return

  data = json.loads(data)
  project_name = data['package']['name']
  project_dir = os.path.join(_ROOT_DIR, 'vulns', project_name)
  os.makedirs(project_dir, exist_ok=True)
  vuln_path = os.path.join(project_dir, issue_id + '.yaml')

  with open(vuln_path, 'w') as handle:
    yaml.dump(data, handle, sort_keys=False, Dumper=_YamlDumper)

  print('Vuln written to', os.path.relpath(vuln_path, os.getcwd()))


if __name__ == '__main__':
  main()
