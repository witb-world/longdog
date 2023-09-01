"""
Produce a report from some findings output
"""
import bs4
import os
from pathlib import Path
import shutil

from loguru import logger

REPORT_TEMPLATE_PATH = "./out/view/html/report.html"

DEFAULT_OUTPUT_DIR = "./results/"
DEFAULT_HTML_OUTPUT_PATH = "ld_report.html"

FINDINGS_PATHNAME = 'findings_output.js'

class LongdogReport:
    def __init__(self, report_path):
        # n.b.: we'll probably have to parse this path to make sure the formatting works
        # or use another library besides strings.
        self.report_path = Path(report_path)
        self.findings_file_path = self.report_path.joinpath(FINDINGS_PATHNAME)
        self.findings_filename = FINDINGS_PATHNAME


    def make_report_dir(self):
        # os.mkdir(self.report_path)
        shutil.copytree('./out/view/inc-longdog', self.report_path)

    def write_findings_file(self, findings: dict):
        logger.debug(f'Writing findings to {self.findings_file_path}')
        with open(self.findings_file_path, 'w') as findings_file:
            findings_file.write(f'results = {findings}')

    def produce_report(self):
        # shutil.copyfile(findings_file_path, f'{DEFAULT_OUTPUT_DIR}/{findings_file_path}')
        with open(REPORT_TEMPLATE_PATH, 'r') as report_template:
            report_str_data = report_template.read()
            report_soup = bs4.BeautifulSoup(report_str_data)
        
        findings_data_js = report_soup.new_tag("script", src=self.findings_filename)
        report_soup.head.append(findings_data_js)

        # os.mkdir(DEFAULT_OUTPUT_DIR)
        with open(f'{self.report_path}/{DEFAULT_HTML_OUTPUT_PATH}', "w") as output_html:
            output_html.write(str(report_soup))

