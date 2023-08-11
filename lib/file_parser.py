import json
import jsonlines
import re
import os

# class ADObject:
#     def __init__(self, object_identifier: str, object_type: str, child_objects: []):
#         """
#         An AD object (e.g. an OU, User, Group, Computer, etc.)
#         Use this to collect object attributes to map against a parent object's object_identifier
#         """
#         self.object_identifier = object_identifier
#         self.object_type = object_type
#         self.child_objects = child_objects
SHARPHOUND_FILES = ['computers.json', 'containers.json', 'domains.json', 'gpos.json', 'groups.json', 'ous.json', 'users.json']

class FileParser:

    def _set_file_paths(self):
        sharphound_paths = os.listdir(self.sharphound_dir_path)
        file_endings = SHARPHOUND_FILES

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

        # maps GUID/ObjIdentifier of OU to List of its ChildObjects
        self.obj_relationships_map = {}
        
        # maps GUID/ObjIdentifier of OU to Dict of its Properties
        self.obj_properties_map = {}

        # maps GUIDs of GPOs to List of all linked objects and what they inherit.
        self.gp_link_map = {}

        # maps GUIDs of GPOs to enforcement rule.
        self.gp_enforced_map = {}

        self.top_level_links = {} # direct links from OUs or domains to a group policy.

        self._set_file_paths()

    def add_object_to_relationships_map(self, object_type, obj):
        if object_type != 'groups':
            self.obj_relationships_map[obj['ObjectIdentifier'].lower()] = obj.get('ChildObjects')
        else:
            self.obj_relationships_map[obj['ObjectIdentifier'].lower()] = obj.get('Members')

    def add_object_to_properties_map(self, object_type, obj):
        self.obj_properties_map[obj['ObjectIdentifier'].lower()] = obj['Properties']

    def add_to_map_from_sharphound_file(self, sharphound_file, map_type):
        object_type_key = sharphound_file.split(".")[0] # should convert string `ous.json` to `ous`, for instance
        with open(f"{self.sharphound_dir_path}/{self.sharphound_files[sharphound_file]}", 'r', encoding='utf-8-sig') as sharphound_fp:
            sharphound_data = json.load(sharphound_fp)

            for obj in sharphound_data['data']:
                # if we're only parsing top-level links, skip over any objects that don't have links.
                if map_type == 'relationships':
                    self.add_object_to_relationships_map(object_type_key, obj)
                elif map_type == 'properties':
                    self.add_object_to_properties_map(object_type_key, obj)   
                elif map_type == 'links' and (object_type_key == 'ous' or object_type_key == 'domains'):
                    if obj.get('Links') == None or len(obj['Links']) == 0:
                        continue
                    else:
                        for gp_link in obj['Links']:
                            gp_guid = gp_link['GUID'].lower()
                            if gp_guid not in self.top_level_links:
                                self.top_level_links[gp_guid] = []
                            self.top_level_links[gp_guid].append(obj['ObjectIdentifier'].lower())
                            self.gp_enforced_map[gp_guid] = gp_link['IsEnforced']
                 

    def set_top_level_links(self):
        for file in ['domains.json', 'ous.json']:
            self.add_to_map_from_sharphound_file(file, 'links')

    def build_gplink_list(self, gp_guid):
        for obj_id in self.top_level_links[gp_guid]:
            for child_obj in self.obj_relationships_map[obj_id]:
                # child_obj = self.obj_properties_map[child_obj['ObjectIdentifier'].lower()]
                self.build_gplink_list_recurse(gp_guid, obj_id)
                
    def build_gplink_list_recurse(self, gp_guid, obj_id):
        obj = self.obj_properties_map[obj_id]
        blocks_inheritance = obj.get('blocksinheritance')
        enforced = self.gp_enforced_map[gp_guid]

        if blocks_inheritance and not enforced:
            return
        else:
            if gp_guid not in self.gp_link_map:
                print("adding", gp_guid, "to link map")
                self.gp_link_map[gp_guid] = []
            self.gp_link_map[gp_guid].append(obj)
            if obj_id in self.obj_relationships_map and self.obj_relationships_map[obj_id] is not None:
                for child_obj in self.obj_relationships_map[obj_id]:
                    self.build_gplink_list_recurse(gp_guid, child_obj['ObjectIdentifier'].lower())

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

    def parse_files(self):
        output = []
        # update maps from sharphound files
        for map_type in ['properties', 'relationships']:
            for file in  SHARPHOUND_FILES:
                self.add_to_map_from_sharphound_file(file, map_type)

        self.set_top_level_links()

        for gp_guid in self.gp_enforced_map:
            self.build_gplink_list(gp_guid)

        # Create mapping of GUIDs to grouper GPO data
        if self.grouper_file_path:
            with jsonlines.open(self.grouper_file_path) as grouper_data:
                for line in grouper_data:
                    guid_key = re.findall(r'\\{(.*)}$', line['Attributes']['PathInSysvol'])[0]
                    guid_key = guid_key.lower()
                    self.grouper_map[guid_key] = line

        # Add grouper GPO info to sharphound's GPO mappings
        with open(f"{self.sharphound_dir_path}/{self.sharphound_files['gpos.json']}", 'r', encoding='utf-8-sig') as bloodhound_gpo:
            gpo_data = json.load(bloodhound_gpo)
            for gpo in gpo_data['data']:
                if self.grouper_file_path:
                    guid_key = re.findall(r'\\{(.*)}$', gpo['Properties']['gpcpath'])[0] 
                    guid_key = guid_key.lower()
                    gpo['PolicyData'] = self.grouper_map[guid_key]

                gpo_guid = gpo['ObjectIdentifier'].lower()
                # print("trying to match", ou_key)
                if gpo_guid in self.gp_link_map:
                    print("Found a matching link in OUs file for ", gpo_guid)
                    gpo['gpLinks'] = self.gp_link_map[gpo_guid]
                output.append(gpo)

        return output