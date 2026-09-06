"""Build, pack, install outside the checkout, and test actual file-store persistence failures."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--output', required=True, type=Path)
a = p.parse_args()
root = Path(__file__).resolve().parents[1]
out = a.output.resolve()
out.mkdir(parents=True, exist_ok=False)
npm = shutil.which('npm.cmd') or shutil.which('npm')
node = shutil.which('node')
if not npm or not node:
    raise SystemExit('npm and node must be available')
receipt = {'ok': False, 'steps': [], 'scope': 'installed npm package; real filesystem rename failures; single writer only'}

def run(name, command, cwd):
    r = subprocess.run(command, cwd=cwd, capture_output=True, timeout=180)
    (out / (name + '.stdout')).write_bytes(r.stdout)
    (out / (name + '.stderr')).write_bytes(r.stderr)
    receipt['steps'].append({'name': name, 'exit': r.returncode})
    if r.returncode:
        raise RuntimeError(name + ' failed; inspect retained transcript')
    return r.stdout

try:
    receipt['commit'] = run('commit', ['git', 'rev-parse', 'HEAD'], root).decode().strip()
    run('build', [npm, 'run', 'build'], root)
    packed = run('pack', [npm, 'pack', '--workspace', '@tsk/core', '--workspace', '@tsk/server',
                         '--ignore-scripts', '--json', '--pack-destination', str(out)], root)
    names = [row['filename'] for row in json.loads(packed)]
    receipt['packages'] = [{'name': name, 'sha256': hashlib.sha256((out/name).read_bytes()).hexdigest()} for name in names]
    install = out / 'installed'
    install.mkdir()
    (install/'package.json').write_text('{"name":"tsk-installed-store-proof","private":true,"type":"module"}\n')
    run('install', [npm, 'install', '--ignore-scripts', '--no-audit', '--no-fund', *[str(out/name) for name in names]], install)
    module = install/'node_modules/@tsk/server/dist/index.js'
    receipt['installed_file_store_sha256'] = hashlib.sha256((module.parent/'file-store.js').read_bytes()).hexdigest()
    run('regression', [node, '--import', (root/'node_modules/tsx/dist/loader.mjs').as_uri(),
                       str(root/'file-store-failure-suite.mts'), str(out/'regression'), str(module), 'regression'], install)
    receipt['regression'] = json.loads((out/'regression/receipt.json').read_text())
    run('authority', [node, str(root/'file-store-authority-suite.mjs'), str(out/'authority'), str(module)], install)
    receipt['authority'] = json.loads((out/'authority/receipt.json').read_text())
    receipt['ok'] = receipt['regression']['ok'] is True and receipt['authority']['ok'] is True
except Exception as error:
    receipt['error'] = str(error)
finally:
    (out/'receipt.json').write_text(json.dumps(receipt, indent=2)+'\n')
print(json.dumps(receipt))
sys.exit(0 if receipt['ok'] else 1)
