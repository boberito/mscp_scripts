#!/usr/bin/env python3

#use just like generate_guidance.py - point to a baseline file. Boom.
import argparse
import sys
import os
import os.path
import yaml
import glob
import warnings
from pathlib import Path

def get_rule_yaml(rule_file, custom=False):
    """ Takes a rule file, checks for a custom version, and returns the yaml for the rule
    """
    resulting_yaml = {}
    names = [os.path.basename(x) for x in glob.glob('../custom/rules/**/*.yaml', recursive=True)]
    file_name = os.path.basename(rule_file)
    
    if custom:
        print(f"Custom settings found for rule: {rule_file}")
        try:
            override_path = glob.glob('../custom/rules/**/{}'.format(file_name), recursive=True)[0]
        except IndexError:
            override_path = glob.glob('../custom/rules/{}'.format(file_name), recursive=True)[0]
        with open(override_path) as r:
            rule_yaml = yaml.load(r, Loader=yaml.SafeLoader)
    else:
        with open(rule_file) as r:
            rule_yaml = yaml.load(r, Loader=yaml.SafeLoader)
    
    try:
        og_rule_path = glob.glob('../rules/**/{}'.format(file_name), recursive=True)[0]
    except IndexError:
        #assume this is a completely new rule
        og_rule_path = glob.glob('../custom/rules/**/{}'.format(file_name), recursive=True)[0]
        resulting_yaml['customized'] = ["customized rule"]
    
    # get original/default rule yaml for comparison
    with open(og_rule_path) as og:
        og_rule_yaml = yaml.load(og, Loader=yaml.SafeLoader)

    for yaml_field in og_rule_yaml:
        #print('processing field {} for rule {}'.format(yaml_field, file_name))
        if yaml_field == "references":
            if not 'references' in resulting_yaml:
                resulting_yaml['references'] = {}
            for ref in og_rule_yaml['references']:
                try:
                    if og_rule_yaml['references'][ref] == rule_yaml['references'][ref]:
                        resulting_yaml['references'][ref] = og_rule_yaml['references'][ref]
                    else:
                        resulting_yaml['references'][ref] = rule_yaml['references'][ref]
                except KeyError:
                    #  reference not found in original rule yaml, trying to use reference from custom rule
                    try:
                        resulting_yaml['references'][ref] = rule_yaml['references'][ref]
                    except KeyError:
                        resulting_yaml['references'][ref] = og_rule_yaml['references'][ref]
                try: 
                    if "custom" in rule_yaml['references']:
                        resulting_yaml['references']['custom'] = rule_yaml['references']['custom']
                        if 'customized' in resulting_yaml:
                            if 'customized references' not in resulting_yaml['customized']:
                                resulting_yaml['customized'].append("customized references")
                        else:
                            resulting_yaml['customized'] = ["customized references"]
                except:
                    pass
            
        else: 
            try:
                if og_rule_yaml[yaml_field] == rule_yaml[yaml_field]:
                    #print("using default data in yaml field {}".format(yaml_field))
                    resulting_yaml[yaml_field] = og_rule_yaml[yaml_field]
                else:
                    #print('using CUSTOM value for yaml field {} in rule {}'.format(yaml_field, file_name))
                    resulting_yaml[yaml_field] = rule_yaml[yaml_field]
                    if 'customized' in resulting_yaml:
                        resulting_yaml['customized'].append("customized {}".format(yaml_field))
                    else:
                        resulting_yaml['customized'] = ["customized {}".format(yaml_field)]
            except KeyError:
                resulting_yaml[yaml_field] = og_rule_yaml[yaml_field]

    return resulting_yaml

def fill_in_odv(resulting_yaml, parent_values):
    fields_to_process = ['title', 'discussion', 'check', 'fix']
    _has_odv = False
    if "odv" in resulting_yaml:
        try:
            if type(resulting_yaml['odv'][parent_values]) == int:
                odv = resulting_yaml['odv'][parent_values]
            else:
                odv = str(resulting_yaml['odv'][parent_values])
            _has_odv = True
        except KeyError:
            try:
                if type(resulting_yaml['odv']['custom']) == int:
                    odv = resulting_yaml['odv']['custom']
                else:
                    odv = str(resulting_yaml['odv']['custom'])
                _has_odv = True
            except KeyError:
                if type(resulting_yaml['odv']['recommended']) == int:
                    odv = resulting_yaml['odv']['recommended']
                else:
                    odv = str(resulting_yaml['odv']['recommended'])
                _has_odv = True
        else:
            pass

    if _has_odv:
        for field in fields_to_process:
            if "$ODV" in resulting_yaml[field]:
                resulting_yaml[field]=resulting_yaml[field].replace("$ODV", str(odv))

        for result_value in resulting_yaml['result']:
            if "$ODV" in str(resulting_yaml['result'][result_value]):
                resulting_yaml['result'][result_value] = odv

        if resulting_yaml['mobileconfig_info']:
            for mobileconfig_type in resulting_yaml['mobileconfig_info']:
                if isinstance(resulting_yaml['mobileconfig_info'][mobileconfig_type], dict):
                    for mobileconfig_value in resulting_yaml['mobileconfig_info'][mobileconfig_type]:
                        if "$ODV" in str(resulting_yaml['mobileconfig_info'][mobileconfig_type][mobileconfig_value]):
                            resulting_yaml['mobileconfig_info'][mobileconfig_type][mobileconfig_value] = odv


def main():
    parser = argparse.ArgumentParser(description='Given a profile, create JSON custom schema to use in Jamf.')
    parser.add_argument("baseline", default=None, help="Baseline YAML file used to create the JSON custom schema.", type=argparse.FileType('rt'))

    results = parser.parse_args()
    try:
        
        output_basename = os.path.basename(results.baseline.name)
        output_filename = os.path.splitext(output_basename)[0]
        baseline_name = os.path.splitext(output_basename)[0]
        file_dir = os.path.dirname(os.path.abspath(__file__))
        parent_dir = os.path.dirname(file_dir)
        # stash current working directory
        original_working_directory = os.getcwd()

        # switch to the scripts directory
        os.chdir(file_dir)
        build_path = os.path.join(parent_dir, 'build', f'{baseline_name}')
        output = build_path + "/" + baseline_name + ".audit"

        if not (os.path.isdir(build_path)):
            try:
                os.makedirs(build_path)
            except OSError:
                print(f"Creation of the directory {build_path} failed")
        print('Profile YAML:', results.baseline.name)
        print('Output path:', output)
        
       
        
    except IOError as msg:
        parser.error(str(msg))


    version_file = "../VERSION.yaml"
    with open(version_file) as r:
        version_yaml = yaml.load(r, Loader=yaml.SafeLoader)


    profile_yaml = yaml.load(results.baseline, Loader=yaml.SafeLoader)
    tenable = '''
    <check_type:"Unix">
<if>
  <condition type:"AND">
    <custom_item>
      type        : CMD_EXEC
      description : "MacOS {} is installed"
      cmd         : "/usr/bin/sw_vers | /usr/bin/grep 'ProductVersion'"
      expect      : "^ProductVersion[\\\s]*:[\\\s]*{}"
    </custom_item>
</condition>
    '''.format(version_yaml['os'],version_yaml['os'].split('"')[0].split('.')[0])
    githubBranch = version_yaml['version'].split(" ")[0].lower()
    tenable = tenable + '''
<then>
    <report type:"PASSED">
      description : "{}"
      see_also    : "https://github.com/usnistgov/macos_security/blob/{}"
</report>
    
    '''.format(profile_yaml['title'],githubBranch)
    # https://github.com/usnistgov/macos_security/blob/ventura/rules/os/os_airdrop_disable.yaml
    for sections in profile_yaml['profile']:
        if sections['section'] == "Supplemental":
            continue
        
        for profile_rule in sections['rules']:
            

            if glob.glob('../custom/rules/**/{}.yaml'.format(profile_rule),recursive=True):
                rule = glob.glob('../custom/rules/**/{}.yaml'.format(profile_rule),recursive=True)[0]
                custom=True
            
            elif glob.glob('../rules/*/{}.yaml'.format(profile_rule)):
                rule = glob.glob('../rules/*/{}.yaml'.format(profile_rule))[0]
                custom=False
            
            rule_yaml = get_rule_yaml(rule, custom)

            
            if "inherent" in rule_yaml['tags'] or "n_a" in rule_yaml['tags'] or "permanent" in rule_yaml['tags']:
                continue

            try:
                parent_values = profile_yaml['parent_values']
            except KeyError:
                parent_values = "recommended"

            fill_in_odv(rule_yaml,parent_values)
            mscp_result = ""
            try:

                for keys,value in rule_yaml['result'].items():
                    mscp_result = value
            
            except:
                mscp_result = ""

            references = ""
            for values in rule_yaml['references']:
                for v in rule_yaml['references'][values]:
                    if v == "N/A":
                        continue
                    elif v == "benchmark":
                        continue
                    elif v == "controls v8":
                        for v8 in rule_yaml['references'][values]["controls v8"]:
                            references = references + "{}|{},".format("cis_v8",v8)
                    else:
                        references = references + "{}|{},".format(values,v)
            references.rstrip()
            if references == "":
                references = "" 
            elif references[-1] == ",":
                references = references.rstrip(references[-1])

            if "inherent" in rule_yaml['tags']:
                tenable = tenable + '''
<report type:"PASSED">
    description : "{0}"
    info        : "{1}"
    reference   : "{2}"
    see_also    : "https://github.com/usnistgov/macos_security/blob/{3}/rules/{4}/{5}.yaml"
</report>'''.format(rule_yaml['title'],rule_yaml['discussion'].replace('"','\\"').rstrip(),references,githubBranch,rule_yaml['id'].split("_")[0],rule_yaml['id'])
    # https://github.com/usnistgov/macos_security/blob/ventura/rules/os/os_airdrop_disable.yaml

            elif "permanent" in rule_yaml['tags']:
                tenable = tenable + '''
<report type:"WARNING">
    description : "{0}"
    info        : "{1}"
    reference   : "{2}"
    see_also    : "https://github.com/usnistgov/macos_security/blob/{3}/rules/{4}/{5}.yaml"
</report>'''.format(rule_yaml['title'],rule_yaml['discussion'].replace('"','\\"').rstrip(),references,githubBranch,rule_yaml['id'].split("_")[0],rule_yaml['id'])
                
            elif "n_a" in rule_yaml['tags']:
                tenable = tenable

            elif "manual" in rule_yaml['tags']:
                tenable = tenable + '''
<report type:"WARNING">
    description : "{0}"
    info        : "{1}"
    reference   : "{2}"
    see_also    : "https://github.com/usnistgov/macos_security/blob/{3}/rules/{4}/{5}.yaml"
</report>'''.format(rule_yaml['title'],rule_yaml['discussion'].replace('"','\\"').rstrip(),references,githubBranch,rule_yaml['id'].split("_")[0],rule_yaml['id'])
            
            else:
                rule_yaml['check'] = rule_yaml['check'].replace('\\','\\\\')
                if "CURRENT_USER" in rule_yaml['check']:
                    rule_yaml['check'] = rule_yaml['check'].replace("$CURRENT_USER","$( /usr/sbin/scutil <<< \"show State:/Users/ConsoleUser\" | /usr/bin/awk '/Name :/ && ! /loginwindow/ { print $3 }' )")

                tenable = tenable + '''
<custom_item>
    system      : "Darwin"
    type        : CMD_EXEC
    description : "{0}"
    info        : "{1}"
    reference   : "{4}"
    see_also    : "https://github.com/usnistgov/macos_security/blob/{5}/rules/{6}/{7}.yaml"
    cmd         : "{2}"
    expect      : "{3}"
</custom_item>'''.format(rule_yaml['title'],rule_yaml['discussion'].replace('"','\\"').rstrip(),rule_yaml['check'].replace('"','\\"').rstrip(),mscp_result,references,githubBranch,rule_yaml['id'].split("_")[0],rule_yaml['id'])
    
    

    tenable = tenable + '''
      </then>

  <else>
    <report type:"WARNING">
      description : "{}"
      info        : "NOTE: Nessus has not identified that the chosen audit applies to the target device."
      see_also    : "https://github.com/usnistgov/macos_security/blob/{}/rules/{}/{}.yaml"
    </report>
  </else>
</if>

</check_type>
'''.format(profile_yaml['title'],githubBranch,rule_yaml['id'].split("_")[0],rule_yaml['id'])
    with open(output,'w') as rite:
            rite.write(tenable)
            rite.close()
    
    os.chdir(original_working_directory)
            
if __name__ == "__main__":
    main()
