#!/usr/bin/python3
import argparse
import hashlib
import os
import magic
import yara
import shutil
import sys
import json
import uuid
import re
import subprocess

from multiprocessing import Pool, freeze_support
from itertools import repeat
from os.path import isdir, isfile, join, basename, abspath, dirname, realpath
from pathlib import Path
from collections import Counter, OrderedDict
from typing import Optional, Dict, List


sha256_regex = re.compile(r"^[a-f0-9]{64}$", re.IGNORECASE)
yara_signatures_dir = join(join(dirname(realpath(__file__)), 'yara_signatures'))


def is_pe(file_path: str) -> bool:
    try:
        return open(file_path, 'rb').read(2) == b'MZ'
    except Exception:
        return False


def get_file_sha256sum(file_path: str) -> str:
    hash_function = hashlib.sha256()
    with open(file_path, 'rb', buffering=0) as f:
        for chunk in iter(lambda: f.read(65536), b''):
            hash_function.update(chunk)
    return hash_function.hexdigest()


def diec(file_path: str) -> Optional[Dict]:
    cmd = ['/home/simo/die_lin64_portable/diec.sh', '--json', file_path]
    try:
        return json.loads(
            subprocess.check_output(cmd, stderr=subprocess.STDOUT).strip().decode(errors='ignore'))
    except (subprocess.CalledProcessError, ValueError) as e:
        logger.error(f"Exception: {e.output.decode(errors='replace') if e.output else e}")
    return None


def yarac(file_path: str, fformat: str, arch: str) -> Optional[List[Dict[str, str]]]:
    yara_sigs = join(yara_signatures_dir, fformat, arch)
    rules = yara.compile(filepaths={
        'compiler': join(yara_sigs, 'compilers.yara'),
        #'installers': join(yara_sigs, 'installers.yara'),
        'packer': join(yara_sigs, 'packers.yara'),
    })
    match = rules.match(file_path)
    if match is None:
        return None
    out = list()
    for m in match:
        entry = dict()
        entry['type'] = m.namespace
        entry['rule'] = m.rule
        entry['name'] = m.meta['name']
        entry['version'] = m.meta['version']
        out.append(entry)
    return out


def aggregator(file_path: str) -> Dict:
    out = dict()
    bname = basename(file_path)
    if sha256_regex.match(bname):
        out['sha256'] = bname
    else:
        out['sha256'] = get_file_sha256sum(file_path)
    magic_sig = magic.from_file(file_path)
    out['magic'] = magic_sig
    fformat = arch = None
    if magic_sig.startswith('ELF'):
        fformat = 'elf'
        if '64-bit' in magic_sig:
            arch = 'x64'
        elif '32-bit' in magic_sig:
            arch = 'x86'
    if magic_sig.startswith('PE32'):  # 'PE32+' if x64
        fformat = 'pe'
        if 'x86-64' in magic_sig:
            arch = 'x64'
        elif '80386' in magic_sig:
            arch = 'x86'
    if fformat is not None and arch is not None:
        out['format'] = fformat
        out['arch'] = arch
        out['die'] = diec(file_path)
        out['yara'] = yarac(file_path, fformat, arch)
    return out


if __name__ == "__main__":
    assert isdir(yara_signatures_dir)
    r = aggregator('/home/simo/test/a.out')
    print(r)