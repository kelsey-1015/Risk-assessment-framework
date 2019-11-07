import math


# risk ratio of individual threat
threat_risk_ratio = [16.7, 15.03, 14.03, 14.03, 10.53, 8.52, 7.12]

""" Impact factor of each threat category --> Input by DDM customer"""
# impact_factors = [0.75, 1, 0.75, 1, 1, 0.75, 0.5]
""" Risk factor of each threat -- predefined
[Damage Potential, Accessibility, Skill Level, Affected Users, Intrusion Detectability]"""


""" Changing the scale fo the likelihood parameters: PARAMETER_SET_1"""
# threat_information = {"Data loss": ['NaN', 10, 5, 1, 1],
#                       "Eavesdropping": ['NaN', 10, 5, 1, 10],
#                       "Man-in-the-middle": ['NaN', 10, 5, 5, 5],
#                       "Malicious code: high result correlation": ['NaN', 1, 10, 5, 10],
#                       "Not-trustable computing env": ['NaN', 5, 5, 10, 10],
#                       "Container runtime escape": ['NaN', 1, 1, 10, 5],
#                       "Dos on other containers": ['NaN', 1, 10, 10, 1]}
#
# """ PARAMETER SET II"""
# threat_information = {"Data loss": [3, 10, 5, 1, 1],
#                       "Eavesdropping": [5, 10, 5, 1, 10],
#                       "Man-in-the-middle": [5, 10, 5, 5, 5],
#                       "Malicious code: high result correlation": [3, 1, 10, 5, 10],
#                       "Not-trustable computing env": [5, 5, 5, 10, 10],
#                       "Container runtime escape": ['NaN', 1, 1, 10, 5],
#                       "Dos on other containers": ['NaN', 1, 10, 10, 1]}

""" PARAMETER SET III: change[1, 5, 10] --> [1, 2, 3] From parameter set I"""
threat_information = {"Data loss": ['NaN', 3, 2, 1, 1],
                      "Eavesdropping": ['NaN', 3, 2, 1, 3],
                      "Man-in-the-middle": ['NaN', 3, 2, 2, 2],
                      "Malicious code: high result correlation": ['NaN', 1, 3, 2, 3],
                      "Not-trustable computing env": ['NaN', 2, 2, 3, 3],
                      "Container runtime escape": ['NaN', 1, 1, 3, 2],
                      "Dos on other containers": ['NaN', 1, 3, 3, 1]}

impact_factors = {"Data loss": 0.75,
                      "Eavesdropping": 1,
                      "Man-in-the-middle": 0.75,
                      "Malicious code: high result correlation": 1,
                      "Not-trustable computing env": 1,
                      "Container runtime escape": 0.75,
                      "Dos on other containers": 0.75}
# Identified threat list
threat_list = ["Data loss", "Eavesdropping", "Man-in-the-middle", "Malicious code: high result correlation",
               "Not-trustable computing env", "Container runtime escape", "Dos on other containers"]

""" Mitigation level of each DDM for the identified threats; Should be output of Threat Handling System
    P --> Prevent; D --> Detect;  O--> Open
    """
mitigation_level_dmp_1 = ["D", 'P', 'O', 'P', 'O', 'P', 'D']
mitigation_level_dmp_2 = ["O", 'P', 'D', 'P', 'D', 'P', 'D']


# def threat_risk_value_calculation(risk_factors, impact_factor):
#     """This function calculates the risk value of each single threat, using the magnitude of vector"""
#
#     risk_factors = [x for x in risk_factors if str(x) != 'NaN']
#
#     # print("Risk_factors:", risk_factors)
#     risk_value_tmp = []
#     for risk_factor in risk_factors:
#         risk_value_tmp.append(risk_factor**2)
#
#     risk_value = math.sqrt(sum(risk_value_tmp)) * impact_factor
#     return risk_value


def threat_risk_value_calculation(risk_factors, impact_factor):
    """This function calculates the risk value of each single threat, using the MEAN AVERAGE"""

    risk_factors = [x for x in risk_factors if str(x) != 'NaN']

    # print("Risk_factors:", risk_factors)

    risk_value = sum(risk_factors)/len(risk_factors)
    return risk_value



def threats_risk_value_dic(threat_list, impact_factors, threat_information):
    """ Generate a dictionary of [threat: risk_value]"""
    risk_values = []
    for k, v in threat_information.items():
        risk_value = threat_risk_value_calculation(v, impact_factors[k])
        risk_values.append(risk_value)

    print("Risk values:", risk_values)
    # risk_value_dic = dict(zip(threat_list, risk_values))
    # return risk_value_dic
    return risk_values


def threat_risk_ratio_cal(threat_risk_values):
    threat_risk_ratios = []
    for i in threat_risk_values:
        ratio_tmp = i/sum(threat_risk_values)*100
        threat_risk_ratios.append(ratio_tmp)
    return threat_risk_ratios


def risk_estimation(risk_ratio, mitigation_level):
    risk_ratio_handle = [100, 100, 100, 100, 100, 100, 100]
    for inx, state in enumerate(mitigation_level):
        # print(inx, state)
        if state == "P":
            risk_ratio_handle[inx] = 0
        elif state == 'D':
            risk_ratio_handle[inx] = 0.2 * risk_ratio[inx]
        elif state == 'O':
            risk_ratio_handle[inx] = risk_ratio[inx]
    # print(risk_ratio_handle)
    return sum(risk_ratio_handle)


# def threat_risk_calculation(impact_factor, threat_information, threat_list):
#     """ Calculate the risk value of each threat
#     Generate a dictionary of [threat: risk_value]"""
#
#     likelihood = []
#     for k, v in threat_information.items():
#         print("v: ",v)
#         while "NaN" in v:
#             v.remove("NaN")
#         likelihood_tmp = sum(v)/len(v)
#         likelihood.append(likelihood_tmp)
#     threat_risk_value = [a * b for a, b in zip(impact_factor, likelihood)]
#
#     threat_risk = dict(zip(threat_list, threat_risk_value))
#     # print(threat_risk)
#
#     sorted_threat_risk = sorted(threat_risk.items(), key=lambda kv: kv[1])
#     # print(sorted_threat_risk)
#     threat_risk_value.sort()
#     print(threat_risk_value)
#     return sorted_threat_risk, threat_risk_value


def main():
    ### Test 1
    # risk_factors = [1, 10, 1, "NaN", "NaN"]
    # impact_factor = 1
    # print(risk_value_calculation(risk_factors, impact_factor))

    ### Test 2
    threat_risk_values = threats_risk_value_dic(threat_list, impact_factors, threat_information)
    print("Threat_risk_values", threat_risk_values)

    threat_ratios = threat_risk_ratio_cal(threat_risk_values)
    print("Ratios", threat_ratios)

    risk_1 = risk_estimation(threat_ratios, mitigation_level_dmp_1)
    print(risk_1)

    risk_2 = risk_estimation(threat_ratios, mitigation_level_dmp_2)
    print(risk_2)


    # dic, val = threat_risk_calculation(impact_factor, threat_information, threat_list)
    # ratio = threat_risk_ratio_cal(val)
    # print(ratio)



if __name__ == "__main__":
    main()
