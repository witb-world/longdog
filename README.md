# What this is

This tool will analyze the policies enforced by Group Policy in a AD Domain, track which objects inherit those policies, and report on common misconfigurations and potential paths to exploiting the Domain. This tool is being developed as a research project with [NCC Group](https://github.com/nccgroup).

# How to run this

Install dependencies:

`python3 -m pip install -r requirements.txt`

Run [Group3r](https://github.com/witb-world/Group3r) and Sharphound, and note paths of their output. 

Run script:

```
python3 main.py --help
Usage: main.py [OPTIONS]

Options:
  --grouper-input PATH     Path to Group3r JSONL input
  --sharphound-dir PATH    Path to directory containing SharpHound .json files
                           [required]
  --output TEXT            Output file for intermediate results
  --findings-output TEXT   Output directory name
  --recurse-links BOOLEAN  Recursively resolve AD relatioinships for Group
                           policy links. May degrade performance.
  --diff-mode BOOLEAN      Produce a JSON diff of an unsecured baseline with
                           the Group3r result provided. Useful for debugging
                           new findings.
  --domain TEXT            Domain name being assessed (required for diff-mode)
  --help                   Show this message and exit.
```

As noted above, the `--sharphound-dir` flag should be followed by the path to the directory containing your SharpHound output, after unzipping.

`--grouper-input`, if being used, should point to the `jsonl` file produced from Group3r. You will need to run [our fork of Group3r](https://github.com/witb-world/Group3r) so that it produces output in JSONL format in a separate file.

# Development notes

### MVP roadmap

- [x] Parse output from Group3r and Sharphound to map GPOs to affected OUs
- [x] Handle GPO inheritance logic.
- [x] Build methodology to assess policies based on `jq` queries stored with findings.
- [x] Add affected OUs and GPO identities to misconfigurations in output object.
    - For large domains, it is recommended to set `--recurse-links` to `off` (default), as the current build of this tool has inefficient processing logic.
    - For now, running `main.py` will print a map of findings and their details to affected linked AD objects to `STDOUT`. The path specified in `--output` contains a map of all Group3r output to affected objects.
- [x] Build a comprehensive list of findings
    - Currently `rules/findings` directory contains about 15+ findings. Added `--diff-mode` option to aid in development of more findings.
- [x] Create HTML/Bootstrap reporting frontend

### Longterm roadmap

- [ ] Add Group Policy Editor path details to individual settings during collection.
- [ ] Connect frontend to neo4j instance with Sharphound/Bloodhound data loaded, allowing users to explore affected AD objects dynamically for each Group Policy finding.
- [ ] Develop and integrate standalone LDAP and SMB ingest tooling to move away from Sharphound/Group3r requirements.
  - [ ] Further GPO parsing capabilities needed: CSV files (for audit settings)
- [ ] Build capability for detecting and assessing additional templates such as "MS Security Guide" ADMX template