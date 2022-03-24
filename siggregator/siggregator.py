#!/usr/bin/env python3

import argparse
import hashlib
import json
import magic
import os
import re
import subprocess
import sys
import yara
import ordlookup
import pefile
import ssdeep
import tlsh

from multiprocessing import Pool
from os.path import isdir, isfile, join, basename, abspath, dirname, realpath
from pathlib import Path
from tqdm import tqdm
from typing import Optional, Dict, List

from results_to_csv import generate_csv


sha256_regex = re.compile(r'^[a-f0-9]{64}$', re.IGNORECASE)
yara_signatures_dir = join(join(dirname(realpath(__file__)), 'yara_signatures'))
yarac_signatures_dir = join(join(dirname(realpath(__file__)), 'yarac_signatures'))
GEN_SIM_HASHES = False  # similarity hashes generation?


def subprocess_check_output_strip(cmd: List):
    return subprocess.check_output(cmd, stderr=subprocess.STDOUT).strip().decode(errors='ignore')


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


def get_impfuzzy(pe: pefile.PE) -> str:
        impstrs = []
        exts = ["ocx", "sys", "dll"]
        if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            return ""
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            if isinstance(entry.dll, bytes):
                libname = entry.dll.decode().lower()
            else:
                libname = entry.dll.lower()
            parts = libname.rsplit(".", 1)

            if len(parts) > 1 and parts[1] in exts:
                libname = parts[0]

            for imp in entry.imports:
                funcname = None
                if not imp.name:
                    funcname = ordlookup.ordLookup(
                        entry.dll.lower(), imp.ordinal, make_name=True
                    )
                    if not funcname:
                        raise pefile.PEFormatError(
                            f"Unable to look up ordinal {entry.dll}:{imp.ordinal:04x}"
                        )
                else:
                    funcname = imp.name

                if not funcname:
                    continue

                if isinstance(funcname, bytes):
                    funcname = funcname.decode()
                impstrs.append("%s.%s" % (libname.lower(), funcname.lower()))

        return ssdeep.hash(",".join(impstrs).encode())


def diec(file_path: str) -> Optional[Dict]:
    try:
        die: Dict = json.loads(subprocess_check_output_strip(['diec', '--json', file_path]))
        if 'detects' not in die:
            return None
        assert len(die['detects']) == 1
        detect = die['detects'][0]
        if 'values' in detect:
            new_values = list()
            for d in detect['values']:
                if 'string' in d:
                    del d['string']
                new_d = dict()
                for k, v in d.items():
                    if v == '-':
                        new_d[k] = None
                    else:
                        new_d[k] = v
                new_values.append(new_d)
        else:
            new_values = None
        detect['values'] = new_values
        return detect
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


def sim_hashes(file_path: str) -> Optional[Dict]:
    out = {}
    with open(file_path, 'rb') as fp:
        buff = fp.read() 
        out['ssdeep'] = ssdeep.hash(buff)
        out['tlsh'] = tlsh.hash(buff)
    out['sdhash'] = subprocess_check_output_strip(['sdhash', file_path])
    pe = pefile.PE(file_path)
    out['imphash'] = pe.get_imphash()
    out['impfuzzy'] = get_impfuzzy(pe)
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
        else:  # if '80386' in magic_sig:
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
    else:
        try:
            pe = pefile.PE(file_path, fast_load=True)
            fformat = 'pe'
            machine = pe.FILE_HEADER.Machine
            if machine == 0x14c:
                arch = 'x86'
            elif machine & 0x00ff == 0x64:
                arch = 'x64'
        except:
            pass
    if fformat is None or arch is None:
        return None
    out['format'] = fformat
    out['arch'] = arch
    out['die'] = diec(file_path)
    out['yara'] = yarac(file_path, fformat, arch)
    if GEN_SIM_HASHES:
        out['hashes'] = sim_hashes(file_path)
    bname = basename(file_path)
    if sha256_regex.match(bname):
        out['sha256'] = bname
    else:
        out['sha256'] = get_file_sha256sum(file_path)
    return out


def recursive_files_listing(folder: str) -> List:
    assert isdir(folder)
    return [join(root, f) for root, _, files in os.walk(folder, topdown=False) for f in files]


def run_parallel(tgt_folder: str) -> List[Dict]:
    print('> Recursively scanning input directory...')
    files = recursive_files_listing(tgt_folder)
    print(f'> Found {len(files)} files. Analysis in progress...')
    outputs = None
    if True:  # parallel
        with Pool() as pool:
            outputs = list(tqdm(pool.imap(aggregator, files), total=len(files)))
    else:  # sequential -- debug
        outputs = [aggregator(f) for f in files]
    print(f'> Analyzed {len(outputs)} files')
    return list(filter(None, outputs))


if __name__ == "__main__":
    assert isdir(yara_signatures_dir)
    assert isdir(yarac_signatures_dir)

    if len(os.listdir(yarac_signatures_dir)) <= 1:
        nof_sigs = compile_signatures()
        print(f'> {nof_sigs} rules compiled')

    parser = argparse.ArgumentParser(
        description='PyPEfilter filters out non-native Portable Executable files')
    parser.add_argument('--hashes', help='Generates similarity hashes', action='store_true')
    parser.add_argument('--csv', help='Generate CSV with aggregate results', action='store_true')
    parser.add_argument('-d', '--dir', type=str, help='Target directory', required=True)
    parser.add_argument('-o', '--out', type=str, help='Output JSON file', required=True)
    args = parser.parse_args()

    tgt_dir = args.dir
    assert isdir(tgt_dir)
    tgt_file = args.out
    if isfile(tgt_file):
        print(f'> File {tgt_file} already exists. Skipping JSON generation.')
    else:
        GEN_SIM_HASHES = args.hashes
        results = run_parallel(tgt_dir)
        print(f'> Found {len(results)} valid files. Writing JSON file...')
        with open(tgt_file, 'w') as fp:
            json.dump(results, fp)
        print(f'> "{basename(tgt_file)}" written!')
    if args.csv:
        print('> Generating CSV...')
        if tgt_file.endswith('.json'):
            tgt_csv = f'{tgt_file[:-5]}.csv'
        else:
            tgt_csv = f'{tgt_file}.csv'
        if isfile(tgt_csv):
            print(f'> File {tgt_csv} already exists. Skipping CSV generation...')
        else:
            generate_csv(tgt_file, tgt_csv)
            print(f'> "{basename(tgt_csv)}" written. Bye :)')
