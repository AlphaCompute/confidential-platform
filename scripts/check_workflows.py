"""Parse edited workflow YAML and enforce the local release safety invariants.

This is not a substitute for GitHub execution or actionlint.
"""
from pathlib import Path
import re
import yaml

root = Path(__file__).resolve().parents[1] / '.github/workflows'
docs = {}
for name in ('ci', 'release', 'deploy', 'deploy-app'):
    doc = yaml.load((root/(name+'.yml')).read_text(), Loader=yaml.BaseLoader)
    assert 'on' in doc and doc['jobs']
    for job in doc['jobs'].values():
        for step in job.get('steps', []):
            if 'uses' in step:
                assert re.fullmatch(r'[^@]+@[0-9a-f]{40}', step['uses']), step['uses']
    docs[name] = doc
assert 'workflow_call' in docs['ci']['on']
assert docs['ci']['jobs']['db-tests']['env']['ALPHA_REQUIRE_DATABASE_TESTS'] == '1'
release = docs['release']['jobs']
assert release['checks']['uses'] == './.github/workflows/ci.yml'
assert release['build']['needs'] == 'checks'
assert release['compare']['needs'] == 'build'
assert release['build']['strategy']['matrix']['replica'] == ['a', 'b']
assert docs['release']['permissions'].get('packages') != 'write'
assert 'docker push' not in (root/'release.yml').read_text()
print('PASS: four workflows parse; actions pinned; mandatory database CI; independent candidate builds; no automatic registry push.')
