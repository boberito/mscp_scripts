#! /usr/bin/env python
#use just like generate_guidance.py - point to a baseline file. Boom.
from mscp import RuleLibrary
from mscp import Macsecurityrule
from mscp import Baseline
import argparse
import sys
import os
import os.path
import warnings
from pathlib import Path

from mscp.classes import baseline, references

def validate_file(arg: str) -> Path | None:
    """`argparse` type validator: ensure `arg` points at an existing file.

    Used as the `type=` argument on flags that take a path. Logs an
    error and calls `sys.exit` if the path doesn't resolve to a file.

    Args:
        arg (str): Raw command-line argument value.

    Returns:
        Path | None: The validated `Path`, or never returns when the file
            is missing (process exits).
    """
    if (file := Path(arg)).is_file():
        return file
    else:
        print(f"File Not found: {arg}")
        sys.exit()


def main():
    parser = argparse.ArgumentParser(description='Generate Tenable custom audit file from a baseline YAML file.')
    parser.add_argument("baseline", default=None, help="Baseline YAML file used to create the Tenable custom audit file.", type=validate_file)

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
    
    baseline = Baseline.from_yaml(results.baseline,"en")    

    
#     version_file = "../VERSION.yaml"
#     with open(version_file) as r:
#         version_yaml = yaml.load(r, Loader=yaml.SafeLoader)


#     profile_yaml = yaml.load(results.baseline, Loader=yaml.SafeLoader)
    tenable = '''<check_type:"Unix">
<if>
  <condition type:"AND">
    <custom_item>
      type        : CMD_EXEC
      description : "{} {} is installed"
      cmd         : "/usr/bin/sw_vers | /usr/bin/grep 'ProductVersion'"      
      expect      : "{}{}"
    </custom_item>
</condition>
    '''.format(baseline.platform['os'],baseline.platform['version'],r'^ProductVersion[\\s]*:[\\s]',baseline.platform['version'])    
    tenable = tenable + '''
<then>
    <report type:"PASSED">
      description : "{}"
      see_also    : "https://github.com/usnistgov/macos_security"
      show_output : YES
</report>
    
    '''.format(baseline.title)
#     # https://github.com/usnistgov/macos_security/blob/ventura/rules/os/os_airdrop_disable.yaml

    for section in baseline.profile:
        if section.section == "Supplemental" or section.section == "Excluded":
            continue
        for rule in section.rules:
                     
            references = ""
            for references, v in rule.references:
                if v == None:
                    continue                
                for ref_name, ref_value in v:
                    if ref_value == None:
                        continue
                    if ref_name == "cce":
                        for values in ref_value:
                            references = references + "{}|{},".format("CCE",values)
                    if ref_name == "nist_800_171r3":
                        for values in ref_value:
                            references = references + "{}|{},".format("800-171r3",values)
                    if ref_name == "nist_800_53r5":
                        for values in ref_value:
                            references = references + "{}|{},".format("800-53r5",values)
                    if ref_name == "disa_stig":
                        for values in ref_value:
                            references = references + "{}|{},".format("STIG-ID",values)
                    if ref_name == "cmmc":
                        for values in ref_value:
                            references = references + "{}|{},".format("CMMC",values)
                    if ref_name == "cci":
                        for values in ref_value:
                            references = references + "{}|{},".format("CCI",values)
                    if ref_name == "srg":
                        for values in ref_value:
                            references = references + "{}|{},".format("SRG",values)
                    if ref_name == "bio":
                        for values in ref_value:
                            references = references + "{}|{},".format("BIO",values)
                    if ref_name == "hicp":
                        for values in ref_value:
                            references = references + "{}|{},".format("HICP",values)
                    if ref_name == "benchmark":
                        for values in ref_value:
                            references = references + "{}|{},".format("CIS_Benchmark",values)
                    if ref_name == "controls_v8":
                        for values in ref_value:
                            references = references + "{}|{},".format("CIS_V8",values)
                    references = references + ","
            references.rstrip()

            #   reference   : "800-171|3.4.1,800-171|3.4.2,800-171|3.4.6,800-171|3.4.7,800-171|3.13.1,800-171|3.13.2,800-171r3|03.04.01,800-171r3|03.04.02,800-171r3|03.04.06,800-171r3|03.16.01,800-53|CM-2,800-53|CM-6,800-53|CM-7,800-53|CM-7(1),800-53|CM-9,800-53|SA-3,80OTH-53|SA-8,800-53|SA-10,8００－５３ｒ５｜ＣＭ－１，８００－５３ｒ５｜ＣＭ－２，８００－５３ｒ５｜ＣＭ－６，８００－５３ｒ５｜ＣＭ－７，８００－５３ｒ５｜ＣＭ－７（１），８００－５３ｒ５｜ＣＭ－９，８００－５３ｒ５｜ＳＡ－３，８００－５３ｒ５｜ＳＡ－８，８００－５３ｒ５｜ＳＡ－１０，ＣＳＣｖ７｜１６．１１，ＣＳＣｖ８｜４．１，ＣＳＦ｜ＤＥ．ＡＥ－１，ＣＳＦ｜ＰＲ．ＤＳ－７，ＣＳＦ｜ＰＲ．ＩＰ－１，ＣＳＦ｜ＰＲ．ＩＰ－２，ＣＳＦ｜ＰＲ．ＩＰ－３，ＣＳＦ｜ＰＲ．ＰＴ－３，ＣＳＦ２．０｜ＤＥ．ＣＭ－０９，ＣＳＦ２．０｜ＩＤ．ＡＭ－０８，ＣＳＦ２．０｜ＩＤ．ＩＭ－０１，ＣＳＦ２．０｜ＩＤ．ＩＭ－０２，ＣＳＦ２．０｜ＩＤ．ＩＭ－０３，ＣＳＦ２．０｜ＩＤ．ＲＡ－Ｏ９，ＣＳＦ２．Ｏ｜ＰＲ．ＤＳ－１Ｏ，ＣＳＦ２．Ｏ｜ＰＲ．ＩＲ－Ｏ３，ＣＳＦ２．Ｏ｜ＰＲ．ＰＳ－Ｏ１，ＣＳＦ２．Ｏ｜ＰＲ．ＰＳ－Ｏ６，ＧＤＰＲ｜３２．１ｂ，ＨＩＰＡＡ｜１６４．３０６（ａ）（１），ＩＳＯ＿２７００１＿２₀₂₂｜Ａ．５．２，ＩＳＯ＿２７₀₀₁＿₂₀₂₂｜Ａ．５．８，ＩＳＯ＿２７₀₀₁＿₂₀₂₂｜Ａ．８．９，ＩＳＯ＿２７₀₀₁＿₂₀₂₂｜Ａ．８．２５，ＩＳＯ＿２７₀₀₁＿₂₀₂₂｜Ａ．８．２６，ＩＳＯ＿２７₀₀₁＿₂₀₂₂｜Ａ．８．２７，ＩＳＯ＿２７₀₀₁＿₂₀₂₂｜Ａ．８．２８，ＩＳＯ＿２７₀₀₁＿₂₀₂₂｜Ａ．８．３０，Ｉ🇸🇴＿𝟐𝟕𝟎𝟎𝟏＿𝟐𝟎𝟐𝟐｜𝑨。𝟖。𝟑𝟏، 𝑰𝑺𝑶＿𝟐𝟕𝟎𝟎𝟏＿𝟐𝟎𝟐𝟐}|𝑨。 𝒃。  𝒃。  𝒃。  𝒃。  𝒃。  𝒃。  𝒃。  𝒃。  𝒃。  𝒃。  𝒃。  𝒃。  𝒃。  𝒃。  𝒃。  𝒃。  𝒃。  𝒃。  𝒃。  𝒃。
            #                                                       
              
           

            if "inherent" in rule.tags:
                tenable = tenable + '''
<report type:"PASSED">
    description : "{0}"
    info        : "{1}"
    reference   : "{2}"
    see_also    : "https://github.com/usnistgov/macos_security/blob/main/src/mscp/data/rules/{3}/{4}.yaml"
</report>'''.format(rule.title,rule.discussion.replace('"','\\"').rstrip(),references,rule.rule_id.split("_")[0],rule.rule_id)
    # https://github.com/usnistgov/macos_security/blob/ventura/rules/os/os_airdrop_disable.yaml

            elif "permanent" in rule['tags']:
                tenable = tenable + '''
<report type:"WARNING">
    description : "{0}"
    info        : "{1}"
    reference   : "{2}"
    see_also    : "https://github.com/usnistgov/macos_security/blob/main/src/mscp/data/rules/{3}/{4}.yaml"
</report>'''.format(rule.title,rule.discussion.replace('"','\\"').rstrip(),references,rule.rule_id.split("_")[0],rule.rule_id)
                
            elif "n_a" in rule['tags']:
                tenable = tenable

            elif "manual" in rule['tags']:
                tenable = tenable + '''
<report type:"WARNING">
    description : "{0}"
    info        : "{1}"
    reference   : "{2}"
    see_also    : "https://github.com/usnistgov/macos_security/blob/main/src/mscp/data/rules/{3}/{4}.yaml"
    </report>'''.format(rule.title,rule.discussion.replace('"','\\"').rstrip(),references,rule.rule_id.split("_")[0],rule.rule_id)
            
            else:
                rule.check = rule.check.replace('\\','\\\\')
                if "CURRENT_USER" in rule.check:
                    rule.check = rule.check.replace("$CURRENT_USER","$( /usr/sbin/scutil <<< \"show State:/Users/ConsoleUser\" | /usr/bin/awk '/Name :/ && ! /loginwindow/ { print $3 }' )")

                tenable = tenable + '''
<custom_item>
    system      : "Darwin"
    type        : CMD_EXEC
    description : "{0}"
    info        : "{1}"
    reference   : "{4}"
    see_also    : "https://github.com/usnistgov/macos_security/blob/main/src/mscp/data/rules/{5}/{6}.yaml"
    cmd         : "{2}"
    expect      : "{3}"
</custom_item>'''.format(rule.title,rule.discussion.replace('"','\\"').rstrip(),rule.check.replace('"','\\"').rstrip(),rule.result_value,references,rule.rule_id.split("_")[0],rule.rule_id)
    
    

    tenable = tenable + '''
      </then>

  <else>
    <report type:"WARNING">
      description : "{}"
      info        : "NOTE: Nessus has not identified that the chosen audit applies to the target device."
      see_also    : "https://pages.nist.gov/macos_security"
    </report>
  </else>
</if>

</check_type>
'''.format(baseline.title)
    with open(output,'w') as rite:
            rite.write(tenable)
            rite.close()
    
    os.chdir(original_working_directory)
            
if __name__ == "__main__":
    main()