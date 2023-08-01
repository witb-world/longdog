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
@click.option('--grouper-input', help='Path to Group3r JSONL input', required=False, type=str)
@click.option('--sharphound-dir', help='Path to directory containing SharpHound .json files', required=True, type=str)

def load_files(sharphound_dir, grouper_input):
    if grouper_input:
        GROUPER_PATH = grouper_input
        print(GROUPER_PATH)

    SHARPHOUND_BASE_PATH = sharphound_dir
    print(os.listdir(SHARPHOUND_BASE_PATH))
    print("Beginning to parse files...")

    fp = file_parser.FileParser(sharphound_dir_path=SHARPHOUND_BASE_PATH, grouper_file_path=GROUPER_PATH)
    res = fp.parse_files()
    print("Producing output:", res)
    with open('./mapped-output.json', 'w') as mapped:
        json.dump(res, mapped)

if __name__ == '__main__':
    load_files()

   