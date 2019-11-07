import sqlite3

""" Input: Identified Threats List for the archetype; With threat format [threat, stage]
    Input: meta_data of the archetype layout; with format [data type, data volume, party_num]
"""


"""Input the identified_threats and meta-data """
identified_threats = [['DD', 'I'], ['DD', 'II']]
app_meta_data = ["r", "s", 's']


def check_feasibility(cm_limitation, app_data):

    """
    Check whether a single supported countermeasure is feasible for a scenario;
    INPUT: cm_limitation = [countermeasure, data_type, data_volumn, party_num];
           app_data = [data_type, data_volumn, party_num], parsing result from input application json file
    """
    cm_limitation = cm_limitation[1:]
    tag_list = []
    for idx, val in enumerate(cm_limitation):
        if val.lower() == 'N'.lower():
            tag_list.append(True)
            continue
        else:
            print(app_data[idx].lower())
            if  app_data[idx].lower() in val.lower():
                tag_list.append(True)
            else:
                tag_list.append(False)
    return all(tag_list)


def map_threat_countermeasures(conn, threat_list, data_type ='C', data_volumn='L'):

    """Check the feasibility and necessity of the countermeasures;
    input database from a DMP provider, Identified threat
    list and data_type and data_volume from the application"""

    c = conn.cursor()
    output_handling_states = ["missing", "available", "duplicate"]
    countermeasures_valid = []
    for threat in threat_list:

        countermeasures_valid_T = []

        # print("Threat", threat)
        c.execute("SELECT Countermeasure, DataType, DataVolume, PartyNum FROM countermeasures WHERE Threat = ? AND Stage =?",
                  (threat[0], threat[1]))
        countermeasures = c.fetchall()
        # print("Countermeasures for individual threat")
        # print(countermeasures)

        # Check Feasibility for each threat
        for countermeasure in countermeasures:
            feasibility_tag = check_feasibility(countermeasure, app_meta_data)
            # print("Feasibility_tag:", feasibility_tag)
            if feasibility_tag:
                countermeasures_valid_T.append(countermeasure)
        # print("Countermeasrue_valid", countermeasures_valid_T)
        countermeasures_valid.append(countermeasures_valid_T)

    print(countermeasures_valid[0])
    print(countermeasures_valid[1])

    num_cm = len(countermeasures_valid)
    if num_cm == 0:
        threat.append(output_handling_states[0])
        print(threat)
    elif num_cm == 1:
        threat.append(output_handling_states[1])
        print(threat)
    else:
        threat.append(output_handling_states[2])
        print(threat)

        # print(countermeasures)
        # if no corresponding countermeasures in the DMP data base
        # if not rows:
        #     print("An threat is open")
        #     threats_open.extend(threat[0])
        # else:
        #     print("solved")
        #     # for row in rows:
        #     #     print(row)
        #     threats_mitigated.extend(rows)

    # return threats_open, threats_mitigated

# def security_level_assessment(threats_o, threats_m):
#     # This function inputs the open threats threats_o and mitigated threats threats_m and output the final security
#     # level
#     if not threats_o:
#         security_level = 'low'
#     else:
#
#
#     return security_level


def main():
    conn = sqlite3.connect('threats_countermeasures.db')
    map_threat_countermeasures(conn, identified_threats)
    # cm_limitation = ["encryption", 'N', 'S M', 'N']
    # app_data = ["s", "h", 's']
    # flag = check_feasibility(cm_limitation, app_data)
    # print(flag)


if __name__ == "__main__":
    main()

