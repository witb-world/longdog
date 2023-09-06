import json
import jsondiff

def diff_objs(new_parsed_path: str):
    with open('rules/longdog-baseline.json') as baseline_file:
        baseline_policy = json.load(baseline_file)
    
    with open(new_parsed_path) as new_policy_file:
        new_policy = json.load(new_policy_file)

    return jsondiff.diff(baseline_policy, new_policy)