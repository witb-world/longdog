import json
import jsondiff

TESTING_DOMAIN_NAME = 'urth2.local.com'

def sanitize_policy_to_settings(policies: dict, domain: str) -> dict:
    """
    Takes a policy dictionary and reduces to individual SettingResults.

    Args:
        policy (dict): Policy dictionary
        domain (str): Domain name
    Returns:
        dict: A dictionary mapping the policy's UID to its findings
    """

    policy_map = {}
    for policy in policies:
        gpo_uid = policy['PolicyData']['Attributes']['Uid']
        policy_map[gpo_uid] = []
        for setting in policy['PolicyData']['SettingResults']:
            source_update = setting['Setting']['Source'].replace(f'{domain}\\sysvol\\{domain}', 'SYSVOL')
            setting['Setting']['Source'] = source_update
            policy_map[gpo_uid].append(setting)

    return policy_map


def diff_objs(new_parsed_path: str, domain: str) -> dict:
    with open('rules/longdog-baseline.json') as baseline_file:
        baseline_policy = json.load(baseline_file)
    
    baseline_policy = sanitize_policy_to_settings(baseline_policy, TESTING_DOMAIN_NAME)

    with open(new_parsed_path) as new_policy_file:
        new_policy = json.load(new_policy_file)

    new_policy = sanitize_policy_to_settings(new_policy, domain)

    return jsondiff.diff(baseline_policy, new_policy)