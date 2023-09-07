import json
import jsondiff as jd

import pprint

pp = pprint.PrettyPrinter(indent=4)


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


def build_jq_query(settings) -> str:
    """
    Returns a jq query from some settings produced by jsondiff
    """
    query = '.[].PolicyData.SettingResults[].Setting | .select(%s)'
    setting_res = []

    for setting in settings:
        setting = setting[1]['Setting']
        # pp.pprint(setting)
        setting_vals = {}

        if 'Action' in setting and setting['Action'] == 'Update':
            setting_type = 'registry_update'
            # pp.pprint(setting['Values'] + setting['Key'])
            setting_query = query % f'.Key == "\\\\{setting["Key"]}" and .Values[].ValueName == "{setting["Values"][0]["ValueName"]}" and .Values[].ValueString == "{setting["Values"][0]["ValueString"]}"'
            # print("QUERY:", setting_query)

        

        else:
            setting_type = 'generic_setting'
            # pp.pprint(setting['SettingName'] + setting['ValueString'])
            setting_query = query % f'.SettingName == "{setting["SettingName"]} and .ValueString == "{setting["ValueString"]}"'

        setting_vals['settingType'] = setting_type
        setting_vals['query'] = setting_query
        setting_res.append(setting_vals)

    return setting_res


def diff_objs(new_parsed_path: str, domain: str) -> dict:
    with open('rules/longdog-baseline.json') as baseline_file:
        baseline_policy = json.load(baseline_file)
    
    baseline_policy = sanitize_policy_to_settings(baseline_policy, TESTING_DOMAIN_NAME)

    with open(new_parsed_path) as new_policy_file:
        new_policy = json.load(new_policy_file)

    new_policy = sanitize_policy_to_settings(new_policy, domain)

    diff =  jd.diff(baseline_policy, new_policy)

    for key in diff:
        if jd.insert in diff[key]:
            # print(f'{key}:', json.dumps(diff[key][jd.insert]))
            query_results = build_jq_query(diff[key][jd.insert])

    # print(query_results)
    return query_results