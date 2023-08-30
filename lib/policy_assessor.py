from enum import Enum
import jq
import json
import os

from loguru import logger

class QueryType(Enum):
    """
    Enum used to determine which of two JQ queries in finding schema to run.
    GET_POLICY_OBJECT signifies the entire policy responsible for a finding,
    GET_POLICY_SETTING signifies the specific setting responsible for a finding.
    """
    GET_POLICY_OBJECT = 1
    GET_POLICY_SETTING = 2

FINDINGS_DIR = 'rules/findings'

# open intermediate output file 
# 
# For finding in ../rules/findings
finding_paths = os.listdir(FINDINGS_DIR)

findings_list = []

# TODO: create a class for findings instead of unstructured JSON.
def build_finding_object(finding_obj: dict, gp_obj:dict, is_neg:bool=False):
    """
    Creates a dictionary representing a finding, along with any gpLinks that the GPO
    responsible for it may be connected to and related GPO metadata.

   Args:
        finding_obj (dict): A dictionary representing a finding
        gp_obj (dict): A dictionary representing a group policy object (parsed and updated for gpLinks)
        is_neg (bool): Whether or not this is a "negative finding": a misconfiguration that has not been remediated
    Returns:
        dict: A dicitionary representing a finding "enriched" with gpLinks and GPO metadata.
    """
    if is_neg:
        logger.debug("NEGATIVE FINDING")
    logger.debug("building finding...")
    
    source_gpo = {}
    source_gpo['name'] = gp_obj['Properties']['name']
    source_gpo['distinguishedname'] = gp_obj['Properties']['distinguishedname']

    # TODO: clean up this branching behavior
    if gp_obj.get('gpLinks') == None or len(gp_obj['gpLinks']) == 0:
        links = 'Domain'
        logger.debug('no links on this finding...')
    elif is_neg:
        # if this is a "negative finding", we don't need to actually return an object if the
        # remediating policy is identified and applies to the whole domain.
        for gp_link in gp_obj['gpLinks']:
            if gp_link['name'] == gp_link['domain']:
                logger.debug('negative finding applies to domain, discard...')
                return
        links = gp_obj['gpLinks'] 
    else:
        links = gp_obj['gpLinks'] 
    

    source_gpo['links'] = links
    # finding_obj['source_gpo'] = source_gpo
    if finding_obj.get('flagged_policies') == None:
        finding_obj['flagged_policies'] = []
    finding_obj['flagged_policies'].append(source_gpo)
    logger.debug(f"Finding object contents: {finding_obj}")
    return finding_obj

def make_jq_query(finding_obj: dict, gp_obj: dict, query_type: QueryType):
    """
    Makes a `jq` query from a finding object to a input object.

    Args:
        finding_obj (dict): A dictionary representing a finding
        gp_obj (dict): A dictionary representing a group policy object (parsed and updated for gpLinks)
        query_type (QueryType): enum representing which query to make on GP object.

    Returns:
        jq._ProgramWithInput: iterable jq query result
    """
    if query_type == QueryType.GET_POLICY_OBJECT:
        query_string = finding_obj['policy_object_query']
    elif query_type == QueryType.GET_POLICY_SETTING:
        if finding_obj.get('query') == None or finding_obj.get('query') == "":
            logger.warning(f"No settings query found for finding {finding_obj['description']}")
            return
        query_string = finding_obj['query']
        logger.debug(f"policy setting query: {query_string}")


    query_compiled = jq.compile(query_string)
    query_result = query_compiled.input(gp_obj)
    logger.debug(query_result)
    logger.debug(f"Ran query for: {finding_obj['description']}\n~~~")
    return query_result
        
def add_gp_settings_to_findings_obj(finding_obj: dict, gp_obj: dict):
    """
    Updates `finding_obj` in place to add or update an array of group policy settings.

    Args:
        finding_obj (dict): A dictionary representing a finding
        gp_obj (dict): A dictionary representing a group policy object (parsed and updated for gpLinks)
    """
    if finding_obj is not None:
        setting_result = make_jq_query(finding_obj=finding_obj, gp_obj=gp_obj, query_type=QueryType.GET_POLICY_SETTING)
        if setting_result is not None:
            for setting_res in setting_result:
                if finding_obj.get('gp_setting') == None:
                    finding_obj['gp_setting'] = [setting_res]
                else:
                    finding_obj['gp_setting'].append(setting_result)

def assess_findings(parser_result_path: str):
    """
    Iterate over each finding in `../rules/findings`, and return a JSON blob that contains:
        - The finding details from the original finding file,
        - the metadata of the policy (name, distinguished name, and GPLinks) responsible, and
        - the setting in the policy that is responsible for the finding.

    Args:  
        parser_result_path (str): the path to the result of parse_files produced by the FileParser module
    
    Returns: 
        str: the JSON blob described above
    """
    gp_file = open(parser_result_path, 'r')
    gp_obj = json.load(gp_file)

    for finding_path in finding_paths:
        with open(f'{FINDINGS_DIR}/{finding_path}') as finding_file:
            finding_obj = json.load(finding_file)

            is_neg = finding_obj.get('negative_finding')
            query_result = make_jq_query(finding_obj=finding_obj, gp_obj=gp_obj, query_type=QueryType.GET_POLICY_OBJECT)
            result_count = 0
            for res in query_result:
                result_count += 1
                new_finding_obj = build_finding_object(finding_obj=finding_obj, gp_obj=res, is_neg=is_neg)
             
                add_gp_settings_to_findings_obj(new_finding_obj, gp_obj)
                findings_list.append(new_finding_obj)

            if result_count == 0 and is_neg:
                logger.debug("Adding object for non-covered mitigation")
                finding_obj['flagged_policies'] = "NA"
                # finding_obj['gp_setting'] = make_jq_query(finding_obj=finding_obj, gp_obj=gp_obj, query_type=QueryType.GET_POLICY_SETTING)
                add_gp_settings_to_findings_obj(finding_obj, gp_obj)
                findings_list.append(finding_obj)

    gp_file.close()
    # logger.debug(f"Final findings list: {findings_list}")
    return json.dumps(findings_list)


# execute finding.query on output file
# if match, create json file including finding, affected machines/users/OUs