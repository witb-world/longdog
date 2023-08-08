# What this is

This tool will analyze the policies enforced by Group Policy in a AD Domain, track which objects inherit those policies, and report on common misconfigurations and potential paths to exploiting the Domain.

# How to run this

Install dependencies:

`python3 -m pip install -r requirements.txt`

Run script:

```
python3 main.py --help
Usage: main.py [OPTIONS]

Options:
  --grouper-input TEXT   Path to Group3r JSONL input
  --sharphound-dir TEXT  Path to directory containing SharpHound .json files
                         [required]
  --help                 Show this message and exit.
```

As noted above, the `--sharphound-dir` flag should be followed by the path to the directory containing your SharpHound output, after unzipping.

`--grouper-input`, if being used, should point to the `jsonl` file produced from Group3r. You will need to run [our fork of Group3r](https://github.com/witb-world/Group3r) so that it produces output in JSONL format in a separate file.

# Development notes

- [x] Parse output from Group3r and Sharphound to map GPOs to affected OUs
- [x] Handle GPO inheritance logic.
- [x] Build methodology to assess policies based on `jq` queries stored with findings.
- [ ] Add affected OUs and GPO identities to misconfigurations in output object.
    - For now, running `python3 lib/policy-assessor.py` will list misconfigurations for each finding, provided that output file name from `main.py` is left at default. 
- [ ] Build a comprehensive list of findings
    - Currently `rules/findings` directory contains just three findings for testing steps listed above.
- [ ] Create HTML/Bootstrap reporting frontend