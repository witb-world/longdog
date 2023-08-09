import json
import jsonlines
import re
import os

class FileParser:

    def _set_file_paths(self):
        sharphound_paths = os.listdir(self.sharphound_dir_path)
        file_endings = ['computers.json', 'containers.json', 'domains.json', 'gpos.json', 'groups.json', 'ous.json', 'users.json']

        for path in sharphound_paths:
            for ending in file_endings:
                if re.match(pattern=r'.*{}$'.format(ending), string=path):
                    self.sharphound_files[ending] = path

    def __init__(self, sharphound_dir_path, grouper_file_path):
        self.sharphound_dir_path = sharphound_dir_path
        self.grouper_file_path = grouper_file_path
        print("Grouper file path set to", self.grouper_file_path)

        self.sharphound_files = {}
        self.grouper_map = {}
        self.ou_map = {}
        self.ou_relationships_map = {}
        self.users_and_computers = {}

        self._set_file_paths()
        self.parse_users_and_computers()

    def parse_users_and_computers(self):
        for file in ['users.json', 'computers.json', 'containers.json', 'groups.json']:
            with open(f"{self.sharphound_dir_path}/{self.sharphound_files[file]}", 'r', encoding='utf-8-sig') as sharphound_data:
                obj_data = json.load(sharphound_data)['data']
                for obj in obj_data:
                    # print("adding", obj['ObjectIdentifier'])
                    self.users_and_computers[obj['ObjectIdentifier']] = obj['Properties']['name']


    def add_link(self, gp_link, ou_map, ou):
        properties = ou['Properties']
        guid_key = gp_link['GUID'].lower()
        properties['IsEnforced'] = gp_link['IsEnforced']
        properties['ObjectIdentifier'] = ou['ObjectIdentifier']
        print("adding link:", guid_key)
        if guid_key not in ou_map:
            ou_map[guid_key] = [properties]
        else:
            ou_map[guid_key].append(properties)

    def add_to_map_from_sharphound_file(self, sharphound_file):
        with open(f"{self.sharphound_dir_path}/{self.sharphound_files[sharphound_file]}", 'r', encoding='utf-8-sig') as sharphound_fp:
            sharphound_data = json.load(sharphound_fp)

            for obj in sharphound_data['data']:
                self.ou_relationships_map[obj['ObjectIdentifier'].lower()] = obj['ChildObjects']
                if obj.get('Links') != None and len(obj['Links']) > 0:
                    for gp_link in obj['Links']:
                        self.add_link(gp_link, self.ou_map, obj)

    # TODO: decompose this, this isn't pretty
    def parse_files(self):
        output = []

        # Create mapping of GUIDs to grouper GPO data
        if self.grouper_file_path:
            with jsonlines.open(self.grouper_file_path) as grouper_data:
                for line in grouper_data:
                    guid_key = re.findall(r'\\{(.*)}$', line['Attributes']['PathInSysvol'])[0]
                    guid_key = guid_key.lower()
                    self.grouper_map[guid_key] = line

        # Create mapping of OU GUIDs to their properties
        # with open(f"{self.sharphound_dir_path}/{self.sharphound_files['ous.json']}", 'r', encoding='utf-8-sig') as bloodhound_ou:
        #     ou_data = json.load(bloodhound_ou)
            
        #     for ou in ou_data['data']:
        #         self.ou_relationships_map[ou['ObjectIdentifier'].lower()] = ou['ChildObjects']
        #         if len(ou['Links']) > 0:
        #             for gp_link in ou['Links']:
        #                 self.add_link(gp_link, self.ou_map, ou)
        # # TODO: parse mappings in `domains` json file and either add to `ou_map` or some other structure

        # with open(f"{self.sharphound_dir_path}/{self.sharphound_files['domains.json']}", 'r', encoding='utf-8-sig') as bloodhound_domain:
        #     domain_data = json.load(bloodhound_domain)

        #     for domain in domain_data['data']:
        #         self.ou_relationships_map[domain['ObjectIdentifier'].lower()] = domain['ChildObjects']
        #         if len(domain['Links']) > 0:
        #             for gp_link in domain['Links']:
        #                 self.add_link(gp_link, self.ou_map, domain)

        self.add_to_map_from_sharphound_file('ous.json')
        self.add_to_map_from_sharphound_file('domains.json')
        self.add_to_map_from_sharphound_file('containers.json')

        # Add grouper GPO info to sharphound's GPO mappings
        with open(f"{self.sharphound_dir_path}/{self.sharphound_files['gpos.json']}", 'r', encoding='utf-8-sig') as bloodhound_gpo:
            gpo_data = json.load(bloodhound_gpo)
            for gpo in gpo_data['data']:
                if self.grouper_file_path:
                    guid_key = re.findall(r'\\{(.*)}$', gpo['Properties']['gpcpath'])[0] 
                    guid_key = guid_key.lower()
                    gpo['PolicyData'] = self.grouper_map[guid_key]

                ou_key = gpo['ObjectIdentifier'].lower()
                print("trying to match", ou_key)
                if ou_key in self.ou_map:
                    print("Found a matching link in OUs file...")
                    gpo['gpLinks'] = self.ou_map[ou_key]
                output.append(gpo)

        # Add OU data/gpLinks to output mapping
        for gpo in output:
            if 'gpLinks' in gpo:
                for gp_link in gpo['gpLinks']:
                    obj_id = gp_link['ObjectIdentifier'].lower() 
                    print(f'Looking at obj {gp_link["ObjectIdentifier"].lower()}')
                    if obj_id in self.ou_relationships_map:
                        # add each of these child objects to end of array, where they'll 
                        # (hopefully) be assessed recursively
                        child_objects = self.ou_relationships_map[obj_id] # list of ChildObjects, by ObjectIdentifier
                        for child in child_objects:
                            print("Enumerating child:", child['ObjectIdentifier'].lower(), child['ObjectType'])
                            if child['ObjectType'] == 'OU': # TODO: see if this can capture childobjects of domains, containers, groups, etc.
                                print("looking for OU match")
                                if child['ObjectIdentifier'].lower() in self.ou_map:
                                    print("found a match in OU map")
                                    child_data = self.ou_map[child['ObjectIdentifier'].lower()]
                                    # skip if this child OU blocks inheritance and GPLink is not enforced
                                    if child_data['blocksinheritance'] and not child_data['isEnforced']:
                                        print('passing one up')
                                        # pass
                                    else:
                                        # not pretty, but we do need to invoke this recursively.
                                        # this will allow us to add child data of this respective OU
                                        gpo['gpLinks'].append(child_data)
                                        print(f'appending obj {child["ObjectIdentifier"].lower()}')    
                                else:
                                    print("No child object mapping found for", child['ObjectIdentifier'].lower())
                            elif child['ObjectType'] == 'Computer' or child['ObjectType'] == 'User':
                                child['name'] = self.users_and_computers[child['ObjectIdentifier']]
                                gpo['gpLinks'].append(child)
                            elif child['ObjectType'] == 'Container':
                                print("Found container", child['ObjectIdentifier'].lower())
                                gpo['gpLinks'].extend(self.ou_relationships_map[child['ObjectIdentifier'].lower()])
                                # print(f"Potential children:", self.ou_relationships_map[child['ObjectIdentifier'].lower()])
                                # add children of this container [to what??]
                                pass
                            else:
                                gpo['gpLinks'].append(child)


        return output