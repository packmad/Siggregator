#!/usr/bin/env python3

import csv
import json
import os
import sys

from collections import defaultdict
from os.path import isfile, basename
from typing import Tuple, Optional, List, Dict

FIELD_NAMES = ['COMPILER', 'LINKER', 'LIBRARY', 'PACKER/PROTECTOR',
               'INSTALLER', 'SFX/ARCHIVE', 'OVERLAY', 'OTHER']

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
        else:
            name = name.replace('installer', '')
    elif field == 'SFX/ARCHIVE':
        if name.startswith('microsoft cabinet'):
            name = name.replace(' file', '')
        elif name == 'winrar':
            name = 'rar'
    elif field == 'OVERLAY':
        if name.startswith('inno'):
            name = 'inno installer data'
    if name == 'unknown':
        return field, None
    return field, name.strip()


def diz_add_elems(diz: Dict[str, set], elems: List) -> None:
    for e in elems:
        field, name = pre_cleaner(e['type'], e['name'])
        if name is None:
            continue
        diz[field].add(name)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(f'Usage: {basename(__file__)} IN_FILE_JSON OUT_FILE_CSV')
    in_file = sys.argv[1]
    assert isfile(in_file)
    out_file = sys.argv[2]
    if isfile(out_file):
        os.remove(out_file)

    json_data = json.load(open(in_file, encoding='utf8', errors='ignore'))
    print(f'> Input json file contains {len(json_data)} elements')

    with open(out_file, 'w', newline='') as fp:
        csv_writer = csv.DictWriter(fp, fieldnames=FIELD_NAMES)
        csv_writer.writeheader()
        for j in json_data:
            dict_row = defaultdict(set)
            if 'die' not in j: continue  # TODO backward compatibility, will be removed
            diz_add_elems(dict_row, j['die']['detects'])
            yara = j['yara']
            if yara is not None:
                diz_add_elems(dict_row, yara)
            csv_writer.writerow(dict_row)
    print(f'> "{out_file}" written. Bye!')

    '''
    import pandas as pd
    c = pd.read_csv(out_file)
    print(c)
    '''
