"""Parse edited workflow YAML and enforce the local release safety invariants.

This is not a substitute for GitHub execution or actionlint.
"""
from pathlib import Path
import re
import yaml

root = Path(__file__).resolve().parents[1] / '.github/workflows'
docs = {name: yaml.load((root/(name+'.yml')).read_text(), Loader=yaml.BaseLoader) for name in ('ci', 'release')}
for job in docs['release']['jobs'].values():
    for step in job.get('steps', []):
        if 'uses' in step:
            assert re.fullmatch(r'[^@]+@[0-9a-f]{40}', step['uses']), step['uses']
assert 'workflow_call' in docs['ci']['on']
release = docs['release']['jobs']
assert release['checks']['uses'] == './.github/workflows/ci.yml'
assert release['build']['needs'] == 'checks'
assert release['publish']['needs'] == ['checks', 'build']
assert release['build']['strategy']['matrix']['replica'] == ['a', 'b']
assert [n for n, job in release.items() if 'packages' in job.get('permissions', {})] == ['publish']
assert 'packages' not in docs['release']['permissions']
print('PASS: release actions pinned; mandatory CI; independent candidate builds; only the comparing job publishes.')
