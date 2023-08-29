import click
import json
import jsonlines
import re
import os
from lib import file_parser, policy_assessor

# Just putting these here for global accessibility now, will move into classes later
GROUPER_PATH = ''
SHARPHOUND_BASE_PATH = ''

@click.command()
@click.option('--grouper-input', help='Path to Group3r JSONL input', required=False, type=click.Path())
@click.option('--sharphound-dir', help='Path to directory containing SharpHound .json files', required=True, type=click.Path())
@click.option('--output', default='longdog-out.json', help='Output file', type=str)
@click.option('--findings-output', default='findings_output.js', help='Output file', type=str)
@click.option('--recurse-links', help='Recursively resolve AD relatioinships for Group policy links. May degrade performance.', type=bool, default=False)

def run_longdog(sharphound_dir, grouper_input, output, findings_output, recurse_links):
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
    
    findings = policy_assessor.assess_findings(output_path=output)

    with open(findings_output, 'w') as findings_file:
        findings_file.write(f"results = {findings}")


if __name__ == '__main__':
    run_longdog()

   