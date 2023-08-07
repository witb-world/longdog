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

