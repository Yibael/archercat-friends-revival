"""Validate the explicit public file list without printing matched secrets."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
IPA = 'runtime-revive/ArcherCat-unsigned-resignable.ipa'
MANIFEST = 'DISTRIBUTION.json'
WHEEL = 'vendor/frida-17.15.4-cp37-abi3-macosx_11_0_arm64.whl'
OFFICIAL_FRIDA_SHA256 = 'ec0cb8e0720978c35b0abadf73c5deb80a1e6fbb652b97ce474b0ffcb964281f'
SECRET_PATTERNS = {
    'private_key': rb'-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----',
    'github_token': rb'(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})',
    'openai_token': rb'sk-(?:proj-|svcacct-)[A-Za-z0-9_-]{24,}',
    'aws_access_key': rb'(?:AKIA|ASIA)[A-Z0-9]{16}',
    'credential_url': rb'https?://[^\s/:@]+:[^\s/@]+@',
}
EXCLUDED_SUFFIXES = {'.jsonl', '.log', '.ips', '.crash', '.pem', '.key', '.p12', '.pfx', '.mobileprovision', '.xcent', '.sqlite', '.db'}


def content_findings(data, *, binary=False, home=None):
    labels = [label for label, pattern in SECRET_PATTERNS.items() if re.search(pattern, data)]
    current_home = str(home or Path.home()).encode()
    if current_home not in (b'/', b'') and (current_home + b'/') in data:
        labels.append('current_user_home_path')
    if (b'/private/' + b'tmp/archercat-') in data:
        labels.append('private_test_directory')
    # Original third-party Mach-O libraries retain historical build paths.
    # Text source/docs must not include concrete machine home directories.
    if not binary and re.search(rb'/(?:Users|home)/[A-Za-z0-9._-]+/', data):
        labels.append('absolute_home_path')
    return labels


def public_files(root):
    lines = (root / 'PUBLIC_FILES.txt').read_text().splitlines()
    paths = [line.strip() for line in lines if line.strip() and not line.startswith('#')]
    if len(paths) != len(set(paths)):
        raise ValueError('Duplicate public file')
    for name in paths:
        path = PurePosixPath(name)
        if path.is_absolute() or '..' in path.parts or '.git' in path.parts:
            raise ValueError('Unsafe public path')
        if path.suffix.lower() in EXCLUDED_SUFFIXES or any(x in {'logs', '.venv', '__pycache__'} for x in path.parts):
            raise ValueError(f'Excluded public file type: {name}')
        if path.suffix == '.whl' and name != WHEEL:
            raise ValueError('Only the pinned official Frida wheel may be public')
        if path.suffix == '.ipa' and name != IPA:
            raise ValueError('Only the reviewed IPA may be public')
    return paths


def scan_ipa(path):
    count = 0
    historical_paths = 0
    with zipfile.ZipFile(path) as archive:
        seen = set()
        for info in archive.infolist():
            name = info.filename
            member = PurePosixPath(name)
            if name in seen or member.is_absolute() or '..' in member.parts or not (name.startswith('Payload/ArcherCat.app/') or (info.is_dir() and name == 'Payload/')):
                raise ValueError('Unexpected or duplicated IPA member')
            seen.add(name)
            if member.suffix.lower() in EXCLUDED_SUFFIXES or any(p.lower() in {'documents', 'library', 'preferences', '_codesignature'} for p in member.parts) or re.search(r'(?i)(itunesmetadata|receipt|keychain|\.env)', name):
                raise ValueError(f'Private/signing metadata in IPA: {name}')
            if info.is_dir():
                continue
            data = archive.read(info)
            count += 1
            # Paths in the original executable are static upstream build metadata.
            original_binary = member.name == 'ArcherCatXFacebook'
            findings = content_findings(data, binary=original_binary)
            if findings:
                raise ValueError(f'IPA content rejected: {name}; categories={findings}')
            if original_binary:
                historical_paths = len(set(re.findall(rb'/(?:Users|home)/[A-Za-z0-9._-]+/[^\x00\r\n]{1,220}', data)))
        if archive.testzip() is not None:
            raise ValueError('Corrupt IPA archive')
    return {'checkedFiles': count, 'originalBinaryBuildPaths': historical_paths}



def scan_wheel(root):
    source = json.loads((root / 'vendor/SOURCES.json').read_text())
    wheel = root / WHEEL
    if source['sha256'] != OFFICIAL_FRIDA_SHA256 or hashlib.sha256(wheel.read_bytes()).hexdigest() != OFFICIAL_FRIDA_SHA256:
        raise ValueError('Bundled wheel differs from its official upstream hash')
    count = 0
    parser_markers = set()
    with zipfile.ZipFile(wheel) as archive:
        seen = set()
        for info in archive.infolist():
            name = info.filename
            path = PurePosixPath(name)
            if name in seen or path.is_absolute() or '..' in path.parts:
                raise ValueError('Unsafe wheel member')
            seen.add(name)
            if info.is_dir():
                continue
            data = archive.read(info)
            native = name == 'frida/_frida.abi3.so'
            findings = content_findings(data, binary=native)
            if native:
                # Public upstream native library includes PEM parser delimiters and
                # example URL format strings. Only this exact, hash-pinned wheel
                # receives this exception; current-user paths/tokens remain fatal.
                parser_markers.update(set(findings) & {'private_key', 'credential_url'})
                findings = [f for f in findings if f not in {'private_key', 'credential_url'}]
            if findings:
                raise ValueError(f'Wheel content rejected: {name}; categories={findings}')
            count += 1
        if archive.testzip() is not None:
            raise ValueError('Corrupt wheel archive')
    return {'checkedFiles': count, 'officialSha256Verified': True,
            'upstreamNativeParserMarkers': sorted(parser_markers)}


def inspect(root, refresh=False):
    files = public_files(root)
    if MANIFEST not in files or IPA not in files:
        raise ValueError('Public list lacks manifest or IPA')
    hashes = {}
    for name in files:
        if name == MANIFEST:
            continue
        path = root / name
        if path.is_symlink() or not path.is_file():
            raise ValueError(f'Missing or symlinked public file: {name}')
        data = path.read_bytes()
        if name not in (IPA, WHEEL):
            findings = content_findings(data)
            if findings:
                raise ValueError(f'Public text rejected: {name}; categories={findings}')
        hashes[name] = {'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}
    ipa_result = scan_ipa(root / IPA)
    wheel_result = scan_wheel(root)
    provenance = json.loads((root / 'PROVENANCE.json').read_text())
    if hashes[IPA]['sha256'] != provenance['distributedIpaSha256']:
        raise ValueError('IPA differs from its provenance record')
    if (root / '.git').exists():
        result = subprocess.run(['git', '-C', str(root), 'ls-files', '-z'], check=True, capture_output=True)
        tracked = set(result.stdout.decode().split('\0')) - {''}
        if tracked and tracked != set(files):
            raise ValueError('Tracked files differ from PUBLIC_FILES.txt')
    manifest = {'schemaVersion': 1, 'files': hashes}
    if refresh:
        (root / MANIFEST).write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
    elif json.loads((root / MANIFEST).read_text()) != manifest:
        raise ValueError('File hashes changed; review changes before --refresh')
    return {'status': 'ok', 'publicFiles': len(files), 'ipa': ipa_result, 'wheel': wheel_result,
            'note': 'Pattern scan and file review; not a proof of absence of unknown secrets.'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--refresh', action='store_true')
    args = parser.parse_args()
    try:
        print(json.dumps(inspect(ROOT, args.refresh), ensure_ascii=False, indent=2))
    except (ValueError, OSError, subprocess.SubprocessError, zipfile.BadZipFile) as error:
        print(f'Distribution check failed: {error}', file=sys.stderr)
        raise SystemExit(1)
