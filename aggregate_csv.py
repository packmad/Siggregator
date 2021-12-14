#!/usr/bin/env python3

import sys
import os
import csv

from os.path import isfile, isdir, basename, join

FIELD_NAMES = ['SHA256', 'FAMILY', 'FILE_FORMAT', 'ARCH_BITS', 'ENDIANESS', 'COMPILER', 'LINKER', 'LIBRARY',
               'PACKER/PROTECTOR', 'INSTALLER', 'SFX/ARCHIVE', 'OVERLAY', 'SSDEEP', 'SDHASH', 'TLSH', 'IMPHASH', 'IMPFUZZY', 'OTHER']

def main(in_dir: str, out_file: str) -> None:
    print(f'> Input dir contains {len(next(os.walk(in_dir))[2])} files')
    csv.field_size_limit(sys.maxsize)
    with open(out_file, 'w', newline='') as fp:
        csv_writer = csv.DictWriter(fp, fieldnames=FIELD_NAMES)
        csv_writer.writeheader()
        for filename in os.listdir(in_dir):
            filepath = join(in_dir, filename)
            if not isfile(filepath) or os.path.splitext(filename)[1] != '.csv':
                continue
            print(f'> Aggregating {filename}...')
            with open(filepath, 'r') as f:
                csv_reader = csv.DictReader(f)
                for row in csv_reader:
                    row['FAMILY'] = os.path.splitext(filename)[0]
                    csv_writer.writerow(row)
            print(f'Done!')
            


                


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(f'Usage: {basename(__file__)} IN_DIR_CSV OUT_FILE_CSV')
    in_dir = sys.argv[1]
    assert isdir(in_dir)
    out_file = sys.argv[2]
    if isfile(out_file):
        os.remove(out_file)

    main(in_dir, out_file)