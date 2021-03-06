#!/usr/bin/env python3

import hashlib
import json
import magic
import os
import re
import subprocess
import sys
import yara

from multiprocessing import Pool
from os.path import isdir, isfile, join, basename, abspath, dirname, realpath
from pathlib import Path
from tqdm import tqdm
from typing import Optional, Dict, List


sha256_regex = re.compile(r'^[a-f0-9]{64}$', re.IGNORECASE)
yara_signatures_dir = join(join(dirname(realpath(__file__)), 'yara_signatures'))
yarac_signatures_dir = join(join(dirname(realpath(__file__)), 'yarac_signatures'))


def compile_signatures() -> int:
    for root, dirs, files in os.walk(yara_signatures_dir, topdown=False):
        for dir in dirs:
            dir_path = join(root, dir)
            namespace_to_signatures = dict()
            rule_found = False
            for f in os.listdir(dir_path):
                if f.endswith('.yara'):
                    rule_found = True
                    # -6 's.yara'
                    namespace_to_signatures[f[:-6]] = join(dir_path, f)
            if rule_found:
                p = Path(dir_path)
                arch = p.name
                fformat = p.parent.name
                dst_file = join(yarac_signatures_dir, f'{fformat}_{arch}.yarac')
                yara.compile(filepaths=namespace_to_signatures).save(dst_file)
    return len(os.listdir(yarac_signatures_dir)) - 1  # 1 is .gitkeep file


def is_supported_file(file_path: str) -> bool:
    try:
        with open(file_path, 'rb') as fp:
            first_two_bytes = fp.read(2)
            if first_two_bytes == b'MZ':
                return True  # PE
            if first_two_bytes == b'\x7fE' and fp.read(2) == b'LF':
                return True  # ELF
            if first_two_bytes == b'\xfe\xed' and fp.read(1) == b'\xfa':
                return True  # Mach-O
    except Exception:
        pass
    return False


def get_file_sha256sum(file_path: str) -> str:
    hash_function = hashlib.sha256()
    with open(file_path, 'rb', buffering=0) as f:
        for chunk in iter(lambda: f.read(65536), b''):
            hash_function.update(chunk)
    return hash_function.hexdigest()


def diec(file_path: str) -> Optional[Dict]:
    cmd = ['/die_lin64_portable/diec.sh', '--json', file_path]
    try:
        out = json.loads(
            subprocess.check_output(cmd, stderr=subprocess.STDOUT).strip().decode(errors='ignore'))
        if len(out['detects']) == 0:
            out['detects'] = None
        else:
            new_detects = list()
            for d in out['detects']:
                del d['string']
                new_d = dict()
                for k, v in d.items():
                    if v == '-':
                        new_d[k] = None
                    else:
                        new_d[k] = v
                new_detects.append(new_d)
            out['detects'] = new_detects
        return out
    except (subprocess.CalledProcessError, ValueError) as e:
        sys.exit(f"Exception: {e.output.decode(errors='replace') if e.output else e}")


def yarac(file_path: str, fformat: str, arch: str) -> Optional[List[Dict[str, str]]]:
    rules = yara.load(join(yarac_signatures_dir, f'{fformat}_{arch}.yarac'))
    match = rules.match(file_path)
    if len(match) == 0:
        return None
    out = list()
    for m in match:
        entry = dict()
        entry['type'] = m.namespace
        entry['rule'] = m.rule
        m.meta.pop('pattern', None)
        m.meta.pop('tool', None)
        m.meta.pop('source', None)
        for k, v in m.meta.items():
            entry[k] = v
        out.append(entry)
    return out


def aggregator(file_path: str) -> Optional[Dict]:
    if not is_supported_file(file_path):
        return None
    out = dict()
    magic_sig = magic.from_file(file_path)
    out['magic'] = magic_sig
    fformat = arch = None
    if magic_sig.startswith('PE32'):  # if x64 -> 'PE32+'
        fformat = 'pe'
        if magic_sig[4] == '+':
            arch = 'x64'
        elif '80386' in magic_sig:
            arch = 'x86'
    elif magic_sig.startswith('ELF'):
        fformat = 'elf'
        if '64-bit' in magic_sig:
            arch = 'x64'
        elif '32-bit' in magic_sig:
            arch = 'x86'
    elif magic_sig.startswith('MachO'):
        fformat = 'macho'
        if '64-bit' in magic_sig:
            arch = 'x64'
        elif '32-bit' in magic_sig:
            arch = 'x86'
    if fformat is None or arch is None:
        return None
    out['format'] = fformat
    out['arch'] = arch
    out['die'] = diec(file_path)
    out['yara'] = yarac(file_path, fformat, arch)
    bname = basename(file_path)
    if sha256_regex.match(bname):
        out['sha256'] = bname
    else:
        out['sha256'] = get_file_sha256sum(file_path)
    return out


def listdir_file_abspath(folder: str) -> List:
    assert isdir(folder)
    return [abspath(join(folder, f)) for f in os.listdir(folder)
            if not isdir(abspath(join(folder, f)))]


def run_parallel(tgt_folder: str) -> List[Dict]:
    print('> Scanning input directory...')
    files = listdir_file_abspath(tgt_folder)
    print(f'> Found {len(files)} files. Analysis in progress...')
    with Pool() as pool:
        outputs = list(tqdm(pool.imap(aggregator, files), total=len(files)))
        print('> Analysis done!')
        return list(filter(None, outputs))


if __name__ == "__main__":
    assert isdir(yara_signatures_dir)
    assert isdir(yarac_signatures_dir)

    if len(os.listdir(yarac_signatures_dir)) <= 1:
        nof_sigs = compile_signatures()
        print(f'> {nof_sigs} rules compiled')

    if len(sys.argv) != 3:
        sys.exit(f'Usage: {basename(__file__)} IN_DIR OUT_FILE')
    tgt_dir = sys.argv[1]
    assert isdir(tgt_dir)
    tgt_file = sys.argv[2]
    if isfile(tgt_file):
        os.remove(tgt_file)

    results = run_parallel(tgt_dir)
    print(f'> Found {len(results)} executable files. Writing output file...')

    with open(tgt_file, 'w') as fp:
        json.dump(results, fp)
    print(f'> "{basename(tgt_file)}" written. Bye!')
