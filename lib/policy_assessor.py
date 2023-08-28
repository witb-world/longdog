# TODO:
# Do we want to use this to create another json file?
# Maybe something that maps GPOs and their findings to affected users

# alternately, we could add yet another field to GPOs to illustrate finding impacts
# If we're not using some kind of DB might be fine to use this

# Note: probably best to use a different JSON file that just specifies information 
# that will be useful in reporting.

# Scoutsuite uses a schema that looks something like:
# a map of findings for each AWS service

"""
 "iam-managed-policy-allows-full-privileges": {
    "checked_items": 11,
    "compliance": [
        {
            "name": "CIS Amazon Web Services Foundations",
            "reference": "1.24",
            "version": "1.1.0"
        },
        {
            "name": "CIS Amazon Web Services Foundations",
            "reference": "1.22",
            "version": "1.2.0"
        }
    ],
    "dashboard_name": "Statements",
    "description": "Managed Policy Allows All Actions",
    "display_path": "iam.policies.id",
    "flagged_items": 1,
    "items": [
        "iam.policies.ANPAIWMBCKSKIEE64ZLYK.PolicyDocument.Statement.0"
    ],
    "level": "danger",
    "path": "iam.policies.id.PolicyDocument.Statement.id",
    "rationale": "Providing full privileges instead of restricting to the minimum set of permissions that the principal requires exposes the resources to potentially unwanted actions.",
    "references": [
        "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",
        "https://aws.amazon.com/blogs/security/back-to-school-understanding-the-iam-policy-grammar/"
    ],
    "remediation": "Ensure no managed policies are configured with <samp>Effect: Allow</samp>, <samp>Action: *</samp> and <samp>Resource: *</samp>",
    "service": "IAM"
},
"""

# Similarly, we can map findings (potentially across categories), then set up a map of findings
# to each of these along a similar schema.

# This would probably involve iterating over each finding and doing a query over our data
# to see if it's present (TODO: check how scoutsuite does this, see if there's some better algorithm)

# ---- 
# 
# ScoutSuite collects findings as a directory of JSON files, iterates over each of them as applicable
# Performance may not be a huge issue here

# it would be nice if we had a JQ query we could run for each of these...
import jq
import json
import os

from loguru import logger

FINDINGS_DIR = 'rules/findings'

# open intermediate output file 
# 
# For finding in ../rules/findings
finding_paths = os.listdir(FINDINGS_DIR)



findings_list = []

# TODO: create a class for findings

def build_finding_object(finding_obj, query_result, is_neg=False):
    if is_neg:
        logger.debug("NEGATIVE FINDING")
    logger.debug("building finding...")
    
    source_gpo = {}
    source_gpo['name'] = query_result['Properties']['name']
    source_gpo['distinguishedname'] = query_result['Properties']['distinguishedname']

    if query_result.get('gpLinks') == None or len(query_result['gpLinks']) == 0:
        links = 'Domain'
        logger.debug('no links on this finding...')
    elif is_neg:
        # if this is a "negative finding", we don't need to actually return an object if the
        # remediating policy is identified and applies to the whole domain.
        for gp_link in query_result['gpLinks']:
            if gp_link['name'] == gp_link['domain']:
                logger.debug('negative finding applies to domain, discard...')
                return
    else:
        links = query_result['gpLinks'] 
    

    source_gpo['links'] = links
    # finding_obj['source_gpo'] = source_gpo
    if finding_obj.get('flagged_policies') == None:
        finding_obj['flagged_policies'] = []
    finding_obj['flagged_policies'].append(source_gpo)
    return finding_obj

def assess_findings(output_path):
    gp_file = open(output_path, 'r')
    gp_obj = json.load(gp_file)
    for finding_path in finding_paths:
        with open(f'{FINDINGS_DIR}/{finding_path}') as finding_file:
            finding_obj = json.load(finding_file)
            query_string = finding_obj['policy_object_query']
            is_neg = finding_obj.get('negative_finding')
            query_compiled = jq.compile(query_string)
            query_result = query_compiled.input(gp_obj)
            logger.debug(f"Ran query for: {finding_obj['description']}\n~~~")
            result_count = 0
            for res in query_result:
                result_count += 1
                new_finding_obj = build_finding_object(finding_obj=finding_obj, query_result=res, is_neg=is_neg)
                # print(new_finding_obj)
                findings_list.append(new_finding_obj)
                # we can use this to confirm which policies have misconfigs
                # now we want to make sure we can map this back to policy object, affected OUs
                # --- this may mean changing query to return the GPO instead of the individual policy,
                # --- or perhaps adding another query to each finding json file in order to pull this info.
            # TODO: add check for condition where `is_neg=True` and there are no query results.
            if result_count == 0 and is_neg:
                logger.debug("Adding object for non-covered mitigation")
                logger.debug(finding_obj)
                finding_obj['flagged_policies'] = "NA"
                findings_list.append(finding_obj)

   
    gp_file.close()

    return json.dumps(findings_list)


# execute finding.query on output file
# if match, create json file including finding, affected machines/users/OUs