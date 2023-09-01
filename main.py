import click
import json
import os
from lib import file_parser, policy_assessor, report_creator
# Just putting these here for global accessibility now, will move into classes later
GROUPER_PATH = ''
sharphound_base_path = ''

@click.command()
@click.option('--grouper-input', help='Path to Group3r JSONL input', required=False, type=click.Path())
@click.option('--sharphound-dir', help='Path to directory containing SharpHound .json files', required=True, type=click.Path())
@click.option('--output', default='longdog-out.json', help='Output file', type=str)
@click.option('--findings-output', default='results', help='Output directory name', type=str)
@click.option('--recurse-links', help='Recursively resolve AD relatioinships for Group policy links. May degrade performance.', type=bool, default=False)

def run_longdog(sharphound_dir, grouper_input, output, findings_output, recurse_links):
    if grouper_input:
        GROUPER_PATH = grouper_input
        print("Loading group3r data from", GROUPER_PATH)
    else:
        GROUPER_PATH = None

    sharphound_base_path = sharphound_dir
    print(os.listdir(sharphound_base_path))
    print("Beginning to parse files...")

    fp = file_parser.FileParser(sharphound_dir_path=sharphound_base_path, grouper_file_path=GROUPER_PATH, recurse=recurse_links)
    res = fp.parse_files()

    # print("Producing output:", res)
    with open(output, 'w') as mapped:
        json.dump(res, mapped)
    
    findings = policy_assessor.assess_findings(parser_result_path=output)

    ld_report = report_creator.LongdogReport(f'./{findings_output}/')

    ld_report.make_report_dir()
    ld_report.write_findings_file(findings)
    ld_report.produce_report()

if __name__ == '__main__':
    run_longdog()

   