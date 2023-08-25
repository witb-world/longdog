import click
import json
import jsonlines
import re
import os
from lib import file_parser

# Just putting these here for global accessibility now, will move into classes later
GROUPER_PATH = ''
SHARPHOUND_BASE_PATH = ''

@click.command()
@click.option('--grouper-input', help='Path to Group3r JSONL input', required=False, type=click.Path())
@click.option('--sharphound-dir', help='Path to directory containing SharpHound .json files', required=True, type=click.Path())
@click.option('--output', default='longdog-out.json', help='Output file', type=str)
@click.option('--recurse-links', help='Recursively resolve AD relatioinships for Group policy links. May degrade performance.', type=bool, default=False)

def load_files(sharphound_dir, grouper_input, output, recurse_links):
    if grouper_input:
        GROUPER_PATH = grouper_input
        print("Loading group3r data from", GROUPER_PATH)
    else:
        GROUPER_PATH = None

    SHARPHOUND_BASE_PATH = sharphound_dir
    print(os.listdir(SHARPHOUND_BASE_PATH))
    print("Beginning to parse files...")

    fp = file_parser.FileParser(sharphound_dir_path=SHARPHOUND_BASE_PATH, grouper_file_path=GROUPER_PATH, recurse=recurse_links)
    res = fp.parse_files()

    # print("Producing output:", res)
    with open(output, 'w') as mapped:
        json.dump(res, mapped)

if __name__ == '__main__':
    load_files()

   