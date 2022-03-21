#!/usr/bin/env python3

import csv
import json
import os
import sys

from collections import defaultdict
from os.path import isfile, basename
from typing import Tuple, Optional, List, Dict

FIELD_NAMES = ['SHA256', 'FILE_FORMAT', 'ARCH_BITS', 'ENDIANESS', 'COMPILER', 'LINKER', 'LIBRARY',
               'PACKER/PROTECTOR', 'INSTALLER', 'SFX/ARCHIVE', 'OVERLAY', 'SSDEEP', 'SDHASH', 'TLSH', 'IMPHASH', 'IMPFUZZY', 'OTHER']

AGGREGATOR_MAP = {
    'PROTECTOR': 'PACKER/PROTECTOR',
    'PACKER': 'PACKER/PROTECTOR',
    'SFX': 'SFX/ARCHIVE',
    'ARCHIVE': 'SFX/ARCHIVE',
    'OTHER': 'OTHER',
    'PLAYER': 'OTHER',
    'JOINER': 'OTHER',
    'PATCHER': 'OTHER',
    'EMULATOR': 'OTHER'
}


def rm_version_to_lower(label: str) -> str:
    i = label.find('(')
    if i == -1:
        return label.lower()
    return label[:i].lower()


def pre_cleaner(field: str, name: str) -> Tuple[str, Optional[str]]:
    field = field.upper()
    field = AGGREGATOR_MAP.get(field, field)
    name = rm_version_to_lower(name)
    if field == 'INSTALLER':
        if name.startswith('nullsoft'):
            name = 'nullsoft'
        elif name.startswith('inno'):
            name = 'inno'
        elif name.startswith('7-zip'):
            return 'SFX/ARCHIVE', '7-zip'
        elif name.startswith('zip'):
            return 'SFX/ARCHIVE', 'zip'
        else:
            name = name.replace('installer', '')
    elif field == 'SFX/ARCHIVE':
        if name.startswith('microsoft cabinet'):
            name = name.replace(' file', '')
        elif name == 'winrar':
            name = 'rar'
        elif name.startswith('7-zip'):
            name = '7-zip'
        elif name.startswith('zip'):
            name = 'zip'
    elif field == 'OVERLAY':
        if name.startswith('inno'):
            name = 'inno installer data'
    elif field == 'COMPILER' and name.startswith('microsoft visual c'):
        name = 'msvc'
    if name == 'unknown':
        return field, None
    return field, name.strip()


def diz_add_elems(diz: Dict[str, set], elems: List) -> None:
    if elems is None:
        return
    for e in elems:
        field, name = pre_cleaner(e['type'], e['name'])
        if name is None:
            continue
        diz[field].add(name)


def generate_csv(in_file, out_file) -> None:
    json_data = json.load(open(in_file, encoding='utf8', errors='ignore'))
    print(f'> Input json file contains {len(json_data)} elements')

    with open(out_file, 'w', newline='') as fp:
        csv_writer = csv.DictWriter(fp, fieldnames=FIELD_NAMES)
        csv_writer.writeheader()
        for j in json_data:
            diz_set = defaultdict(set)
            if 'die' not in j: continue  # TODO backward compatibility, will be removed
            diz_set['SHA256'].add(j['sha256'])
            diz_set['FILE_FORMAT'].add(j['format'])
            diz_set['ARCH_BITS'].add(j['die']['mode'])
            diz_set['ENDIANESS'].add(j['die']['endianess'])
            diz_add_elems(diz_set, j['die']['detects'])
            yara = j['yara']
            if yara is not None:
                diz_add_elems(diz_set, yara)
            hashes = j['hashes']
            if hashes is not None:
                diz_set['SSDEEP'].add(j['hashes']['ssdeep'])
                diz_set['TLSH'].add(j['hashes']['tlsh'])
                diz_set['SDHASH'].add(j['hashes']['sdhash'])
                diz_set['IMPHASH'].add(j['hashes']['imphash'])
                diz_set['IMPFUZZY'].add(j['hashes']['impfuzzy'])
            diz_row: Dict[str, str] = dict()
            for k, v in diz_set.items():
                if len(v) == 1:
                    diz_row[k] = v.pop()
                else:  # cell with multiple values
                    v = list(v)
                    v.sort()
                    diz_row[k] = str(v)[1:-1].replace(', ', ';').replace("'", "")
            csv_writer.writerow(diz_row)
    print(f'> "{out_file}" written. Bye!')


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(f'Usage: {basename(__file__)} IN_FILE_JSON OUT_FILE_CSV')
    in_file = sys.argv[1]
    assert isfile(in_file)
    out_file = sys.argv[2]
    if isfile(out_file):
        os.remove(out_file)

    generate_csv(in_file, out_file)

    '''
    import pandas as pd
    c = pd.read_csv(out_file)
    print(c)
    '''
