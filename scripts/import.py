Python
import json
import os
import sys
import urllib.error
import urllib.request
import yaml

_BUCKET = 'oss-fuzz-osv-vulns'
_VULN_URL = f'https://{_BUCKET}.storage.googleapis.com/issue'
_ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

class YamlDumper(yaml.SafeDumper):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.add_representer(str, self.yaml_str_representer)

    def yaml_str_representer(self, dumper, data):
        if '\n' in data:
            return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')
        return dumper.represent_scalar('tag:yaml.org,2002:str', data)


def main():
    if len(sys.argv) != 2:
        print(f'Usage: {sys.argv[0]} <oss-fuzz issue_id>')
        sys.exit(1)

    issue_id = sys.argv[1]
    try:
        with urllib.request.urlopen(f'{_VULN_URL}/{issue_id}.json') as response:
            data = json.loads(response.read())
    except urllib.error.HTTPError:
        print('Vuln does not exist. OSS-Fuzz bugs need to '
              'be marked as security to be included.', file=sys.stderr)
        sys.exit(1)

    project_name = data['package']['name']
    project_dir = os.path.join(_ROOT_DIR, 'vulns', project_name)
    os.makedirs(project_dir, exist_ok=True)
    vuln_path = os.path.join(project_dir, issue_id + '.yaml')

    with open(vuln_path, 'w') as handle:
        yaml.dump(data, handle, sort_keys=False, Dumper=YamlDumper)

    print('Vuln written to', os.path.relpath(vuln_path, os.getcwd()))


if __name__ == '__main__':
    main()
