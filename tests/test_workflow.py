from pathlib import Path

import yaml


def test_workflow_structure_and_release_boundary():
    path = Path(__file__).resolve().parents[1] / '.github/workflows/ci.yml'
    data = yaml.load(path.read_text(encoding='utf-8'), Loader=yaml.BaseLoader)
    assert set(data['jobs']) == {'test', 'build', 'release'}
    assert data['permissions'] == {'contents': 'read'}
    assert data['jobs']['release']['permissions'] == {'contents': 'write'}
    assert data['jobs']['release']['needs'] == 'build'
    assert 'refs/tags/v' in data['jobs']['release']['if']
    assert set(data['jobs']['test']['strategy']['matrix']['os']) == {'ubuntu-22.04', 'ubuntu-24.04'}
    assert any('sha256sum -c' in step.get('run', '') for step in data['jobs']['release']['steps'])
