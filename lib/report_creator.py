"""
Produce a report from some findings output
"""
import bs4
import os
import shutil

REPORT_TEMPLATE_PATH = "./out/view/html/report.html"

DEFAULT_OUTPUT_DIR = "./results"
DEFAULT_HTML_OUTPUT_PATH = "ld_report.html"

def produce_report(findings_file_path: str):
    shutil.copytree('./out/view/inc-longdog', DEFAULT_OUTPUT_DIR)
    shutil.copyfile(findings_file_path, f'{DEFAULT_OUTPUT_DIR}/{findings_file_path}')
    with open(REPORT_TEMPLATE_PATH, 'r') as report_template:
        report_str_data = report_template.read()
        report_soup = bs4.BeautifulSoup(report_str_data)
    
    findings_data_js = report_soup.new_tag("script", src=findings_file_path)
    report_soup.head.append(findings_data_js)

    # os.mkdir(DEFAULT_OUTPUT_DIR)
    with open(f'{DEFAULT_OUTPUT_DIR}/{DEFAULT_HTML_OUTPUT_PATH}', "w") as output_html:
        output_html.write(str(report_soup))

