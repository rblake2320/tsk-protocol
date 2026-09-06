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
p.add_argument('--identity-only', action='store_true', help='Run only changed inherited-key boundary cases')
a = p.parse_args()
root = Path(__file__).resolve().parents[1]
out = a.output.resolve()
out.mkdir(parents=True, exist_ok=False)
npm = shutil.which('npm.cmd') or shutil.which('npm')
node = shutil.which('node')
if not npm or not node:
    raise SystemExit('npm and node must be available')
receipt = {'ok': False, 'steps': [], 'scope': 'installed npm package; local filesystem persistence failures and exclusive transaction boundaries'}

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
    status = run('source-status', ['git', 'status', '--porcelain', '--untracked-files=no'], root).decode()
    receipt['source_dirty'] = bool(status.strip())
    tracked = run('source-files', ['git', 'ls-files', '-z', '--', 'packages', 'scripts/verify_file_store_install.py', 'file-store-*.m*', 'package.json', 'package-lock.json'], root).decode().split('\0')
    source_hashes = {name: hashlib.sha256((root/name).read_bytes()).hexdigest()
                     for name in sorted(set(tracked)) if name and (root/name).is_file()}
    receipt['source_files_sha256'] = source_hashes
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
    if not a.identity_only:
        run('regression', [node, '--import', (root/'node_modules/tsx/dist/loader.mjs').as_uri(),
                           str(root/'file-store-failure-suite.mts'), str(out/'regression'), str(module), 'regression'], install)
        receipt['regression'] = json.loads((out/'regression/receipt.json').read_text())
        run('authority', [node, str(root/'file-store-authority-suite.mjs'), str(out/'authority'), str(module)], install)
        receipt['authority'] = json.loads((out/'authority/receipt.json').read_text())
    run('identity', [node, str(root/'file-store-identity-suite.mjs'), str(out/'identity'), str(module)], install)
    receipt['identity'] = json.loads((out/'identity/receipt.json').read_text())
    receipt['scope'] = 'installed package; inherited-key boundary only' if a.identity_only else receipt['scope']
    receipt['ok'] = all(receipt[name]['ok'] is True for name in ('regression', 'authority', 'identity') if name in receipt)
except Exception as error:
    receipt['error'] = str(error)
finally:
    (out/'receipt.json').write_text(json.dumps(receipt, indent=2)+'\n')
print(json.dumps(receipt))
sys.exit(0 if receipt['ok'] else 1)
