import itertools
import matplotlib.pyplot as plt
import sqlite3
import scipy.stats as sci
import ranking

ROUND_DIGIT = 5
IMPACT_FACTOR = [0, 0.25, 0.5, 0.75, 1]
NUM_PARAMETERS = 5
THREAT_DATABASE = 'threats_database.db'
POSITION_DIC = {'L': 0, 'M': 1, 'H': 2}

INCREASE = 3
EQUAL = 2
DECREASE = 1

value_vector_list = [[0, 1, 2], [1, 2, 4], [1, 3, 8]]
baseline_value_vector = [0, 5, 10]


def box_plot(data_to_plot, x_labels=['0', '0.25', '0.5', '0.75', '1']):
    fig = plt.figure()
    ax = fig.add_subplot(111)
    ax.set_xticklabels(x_labels)
    ax.set_title('Parameter_Scales = [0, 15, 30]')
    ax.set_xlabel('Impact Factor')
    ax.set_ylabel('Risk Value')
    bp = ax.boxplot(data_to_plot)
    plt.show()


def bar_plot(data, value_vector, threatSpace):
    """This function takes the distribution dictionary as an input"""
    title = "Risk values with value vector = {}, threat space {}".format(str(value_vector), threatSpace)
    risk_values = list(data.keys())
    y_pos = range(len(risk_values))
    y_value = list(data.values())
    x_label = []
    for x_label_in in risk_values:
        if x_label_in - int(x_label_in) == 0:
            x_label_in = int(x_label_in)
        x_label_in = str(x_label_in)
        x_label.append(x_label_in)
    plt.bar(y_pos, y_value, align='center', width=0.5)
    plt.xticks(y_pos, x_label)
    plt.xlabel("Unique risk value")
    plt.ylabel("Count")
    plt.title(title)
    plt.show()


def threatSpace_generation(value_vector):
    """Generate threat space 0
    INPUT --> value_vector
    OUTPUT --> A nested list, each threat is represented by its corresponding risk parameters
    """
    threatSpace = list(itertools.product(value_vector, repeat=NUM_PARAMETERS))
    return threatSpace


def database_process(threat_database, value_vector, table_name="ThreatDatabase"):
    """ Usage: Generate threat space 1
    Input:--> threat database
          --> value_vector
          --> table_name
    Output: --> A nested list, each threat is represented by its corresponding risk parameters
    """
    try:
        conn = sqlite3.connect(threat_database)
    except IOError as e:
        print(e)
    cur = conn.cursor()
    cur.execute("SELECT DP, AC, SL, AU, D FROM ThreatDatabase")

    threatSpace = []
    for row in cur:
        risk_parameters = parse_row(row, value_vector)
        # print(risk_parameters)
        threatSpace.append(risk_parameters)
    return threatSpace


def parse_row(row, value_vector):
    """ Usage: Generate threat space
    This function changes values of [L, M, H] into corresponding values"""
    DP = row[0]
    if DP == 'TOP':
        dp_parameter = value_vector[-1]
    else:
        dp_parameter = value_vector[1]
    risk_parameters = [dp_parameter]
    for l in row[1:]:
        index = POSITION_DIC[l]
        risk_parameter = value_vector[index]
        risk_parameters.append(risk_parameter)
    return risk_parameters


def risk_value_calculation(likelyhoodVector, impact=1):

    """ Usage: Calculate the risk value of single threat
        Input: --> likelyhoodVector: [DP, AC, SL, AU, D]
               --> impact factor: a scalar value indicating the impact factor; set default as 1
        Output:--> risk value per threat, round to a fixed digits
                """

    likelyhood = float(sum(list(likelyhoodVector)) / len(likelyhoodVector))
    riskValue = float(impact * likelyhood)
    riskValue = round(riskValue, ROUND_DIGIT)
    return riskValue


def rv_rr_ranking_dict_generation(threatSpace):

    """Usage: Generate various dictionaries regarding to variables as rank, risk values, risk ratios
    Input:  --> Threat Space: a nested list
    Output: --> risk_ratio_dict: a dictionary [threat index: risk ratios]
            --> rank_dict: a dictionary [threat index: rank]"""

    threat_index = range(len(threatSpace))
    # threatSpace_dict: [threat index: risk parameter vectors]
    threatSpace_dict = dict(zip(threat_index, threatSpace))
    # risk_values_dict: [threat index: risk value]
    risk_values_dict = dict()
    # rv_ranking_dict: [risk values: ranking of the threat according to risk values]
    rv_ranking_dict = dict()
    # threat_index_rank: [threat index: ranking of the threat according to risk values]
    rank_dict = dict()
    # risk_ratio_dict: [threat index: risk ratio]
    risk_ratio_dict = dict()

    for threat_index, vector in threatSpace_dict.items():
        risk = risk_value_calculation(vector)
        risk_values_dict[threat_index] = risk
    # print("Risk Value Dict:", risk_values_dict)

    rv_sum = sum(risk_values_dict.values())

    for threat_index, rv in risk_values_dict.items():
        rv_ratio = rv/rv_sum
        rv_ratio = round(rv_ratio, ROUND_DIGIT)
        risk_ratio_dict[threat_index] = rv_ratio

    # print("risk_ratio_dict:", risk_ratio_dict)

    risk_values = list(risk_values_dict.values())
    risk_values.sort(reverse=True)

    risk_values_rankings = list(ranking.Ranking(risk_values))
    for rv_ranking_pair in risk_values_rankings:
        # print("rv rank:", rv_ranking_pair)
        rv = rv_ranking_pair[1]
        rank = rv_ranking_pair[0]
        rv_ranking_dict[rv] = rank

    # print("RV ranking dict:", rv_ranking_dict)

    for threat_index, risk_value in risk_values_dict.items():
        rank =rv_ranking_dict[risk_value]
        rank_dict[threat_index] = rank

    return risk_ratio_dict, rank_dict


def pairwise_ranking(rank):
    """ Usage: For calculating rank correlations
        Calculate the ranking relationships of two positions for all possible position combinations
    --> INPUT: a list of ranking positions of all threats from T0 to TN; The order is very important
    --> OUTPUT: A dictionary of pair-wise relationships. Key: position pair (threat pair); Value: whether the rankings
    of the position is DECREASE, INCREASE or EQUAL"""

    pairwise_ranking = dict()
    for index_pair in itertools.combinations(range(len(rank)), 2):
        stat = 0
        i = index_pair[0]
        j = index_pair[1]
        if rank[i] > rank[j]:
            stat = DECREASE
        elif rank[i] == rank[j]:
            stat = EQUAL
        elif rank[i] < rank[j]:
            stat = INCREASE
        pairwise_ranking[str(index_pair)] = stat

    return pairwise_ranking


def pair_dic_comparison(pairwise_1, pairwise_2, classic_mode=True):
    """ Usage: For calculating rank correlations
        Calculate the coordantant number and disordant numbers of two rankings
        INPUT: --> pairwise_1/pairwise_2: A dictionary. Keys are pairs and values are the corresponding relationships. [IN, DE, EQ]
               --> Mode: [Classic] --> Equal are traded as different orders from INCREASE or DECREASE
                   [GENERAL]--> EQUAL are traded as same orders from INCREASE or DECREASE
        OUTPUT: corder_num: Number of conordantant pairs of two rankings
                disorder_num: Number of disorder pairs of two rankings
    """

    if len(pairwise_1) == len(pairwise_2):
        n = len(pairwise_1)
    else:
        print("Error: the length of two rankings must be identical!")
        return -1

    corder_num = 0
    disorder_num = 0

    # classic_mode: EQUAL is traded as a different order
    if classic_mode:
        for k, v in pairwise_1.items():
            if v == pairwise_2[k]:
                corder_num += 1
            else:
                disorder_num += 1
    else:
        # print("Non classic mode")
        for k, v in pairwise_1.items():
            if v == 2 or pairwise_2[k] == 2:
                corder_num += 1
            elif v == pairwise_2[k]:
                corder_num += 1
            else:
                disorder_num += 1

    if corder_num + disorder_num != n:
        raise ValueError

    return corder_num, disorder_num


def KendallTau(rank_1, rank_2):
    """This function calculates the rank correlation parameter Kendalls'Tau
       INPUT: rank_1/rank_2: a list of ranking positions of all threats from T0 to TN; The order is very important
       OUTPUT: Rank correlation -- KendallTau"""

    if len(rank_1) != len(rank_2):
        print("Error: the length of two rankings must be identical!")
        return -1

    pairwise_1 = pairwise_ranking(rank_1)
    pairwise_2 = pairwise_ranking(rank_2)

    pair_num = len(pairwise_1)

    corder_num, disorder_num = pair_dic_comparison(pairwise_1, pairwise_2, False)

    KendallTau = (corder_num - disorder_num)/pair_num
    return KendallTau


def rank_correlation(value_vector_list, threatSpace0, baseline=baseline_value_vector):
    """ Usage: Calculate the ranking variance under different value_vectors
        INPUT: --> value_vector_list: a list of two different value vector;
                   input "ALL" if you want to loop over all possible combinations
               --> threatSpace0: A boolean variable: whether the threat space is T0
    """
    vv_tau_dict = dict()

    # Generate the rank list for base line vector
    threatSpace = database_process(THREAT_DATABASE, baseline)
    bl_rv_dict, bl_rank_dict = rv_rr_ranking_dict_generation(threatSpace)
    baseline_rank = list(bl_rank_dict.values())

    # if we loop over all possible combinations of value vectors within a certain range
    if value_vector_list == "ALL":
        value_vector_list_all = list(itertools.combinations(range(11), 3))
        for value_vector in value_vector_list_all:
            value_vector = list(value_vector)
            # check if the condition [x1< x2 < x3] satisfies
            if min(value_vector) != value_vector[0] or max(value_vector) != value_vector[-1]:
                raise ValueError
            else:
                if value_vector == baseline:
                    continue
                else:
                    if not threatSpace0:
                        threatSpace = database_process(THREAT_DATABASE, value_vector)
                    else:
                        threatSpace = threatSpace_generation(value_vector)
                    rv_dict, threat_rank_dict = rv_rr_ranking_dict_generation(threatSpace)
                    rank = list(threat_rank_dict.values())
                    tau = KendallTau(baseline_rank, rank)
                    vv_tau_dict[str(value_vector)] = tau


    # for a selected list of value vectors
    else:
        for value_vector in value_vector_list:
            if not threatSpace0:
                threatSpace = database_process(THREAT_DATABASE, value_vector)
            else:
                threatSpace = threatSpace_generation(value_vector)

            rv_dict, threat_rank_dict = rv_rr_ranking_dict_generation(threatSpace)
            rank = list(threat_rank_dict.values())
            tau = KendallTau(baseline_rank, rank)
            vv_tau_dict[str(value_vector)] = tau

    return vv_tau_dict


def granularity_gain(value_vector_list, threatSpace0, baseline=baseline_value_vector):
    """ Usage: Calculate the granularity gain under different value_vectors
            INPUT:  --> value_vector_list: a list of two different value vector;
                       input "ALL" if you want to loop over all possible combinations
                    --> threatSpace0: A boolean variable: whether the threat space is T0
            OUTPUT: --> vv_granularity_dict: A dictionary [value vector: granularity]
                    --> vv_granularityGain_dict: A dictionary [value vector: granularity_gain]
        """
    vv_granularityGain_dict = dict()
    vv_granularity_dict = dict()

    # calculate the granularity fo baseline vector
    threatSpace = database_process(THREAT_DATABASE, baseline)
    _, granularity_baseline = Granularity(threatSpace)
    print(granularity_baseline)

    if value_vector_list == "ALL":
        value_vector_list_all = list(itertools.combinations(range(11), 3))
        for value_vector in value_vector_list_all:
            value_vector = list(value_vector)
            # check if the condition [x1< x2 < x3] satisfies
            if min(value_vector) != value_vector[0] or max(value_vector) != value_vector[-1]:
                raise ValueError
            else:
                if value_vector == baseline:
                    continue
                else:
                    if not threatSpace0:
                        threatSpace = database_process(THREAT_DATABASE, value_vector)
                    else:
                        threatSpace = threatSpace_generation(value_vector)

                    _, granularity = Granularity(threatSpace)
                    vv_granularity_dict[str(value_vector)] = granularity
                    granularityGain = granularity/granularity_baseline
                    vv_granularityGain_dict[str(value_vector)] = granularityGain

    # for a selected list of value vectors
    else:
        for value_vector in value_vector_list:
            if not threatSpace0:
                threatSpace = database_process(THREAT_DATABASE, value_vector)
            else:
                threatSpace = threatSpace_generation(value_vector)
            _, granularity = Granularity(threatSpace)
            granularityGain = granularity / granularity_baseline
            vv_granularity_dict[str(value_vector)] = granularity
            vv_granularityGain_dict[str(value_vector)] = granularityGain

    return vv_granularity_dict, vv_granularityGain_dict


def NMSE(value_vector_list, threatSpace0, baseline=baseline_value_vector):

    """Calculate the normalized mean squared error of two sets of risk values
        --> INPUT: a list of two different value vectors
        --> A boolean variable: whether the threatspace is T0"""
    rv_list = list()
    vv_nmse_dict = dict()

    # generate the risk ratio lists for baseline value vector, number of rr, and rr_mean
    threatSpace = database_process(THREAT_DATABASE, baseline)
    bl_rr_dict, bl_rank_dict =rv_rr_ranking_dict_generation(threatSpace)
    rr_baseline = list(bl_rr_dict.values())
    # print(rr_baseline)

    if value_vector_list == "ALL":
        value_vector_list_all = list(itertools.combinations(range(11), 3))
        for value_vector in value_vector_list_all:
            value_vector = list(value_vector)
            # check if the condition [x1< x2 < x3] satisfies
            if min(value_vector) != value_vector[0] or max(value_vector) != value_vector[-1]:
                raise ValueError
            else:
                if value_vector == baseline:
                    continue
                else:
                    if not threatSpace0:
                        threatSpace = database_process(THREAT_DATABASE, value_vector)
                    else:
                        threatSpace = threatSpace_generation(value_vector)

                    rr_dict, threat_rank_dict = rv_rr_ranking_dict_generation(threatSpace)
                    rr = list(rr_dict.values())

                    nmse = nmse_individual(rr_baseline, rr)
                    vv_nmse_dict[str(value_vector)] = nmse

    # for a selected list of value vectors
    else:
        for value_vector in value_vector_list:
            if not threatSpace0:
                threatSpace = database_process(THREAT_DATABASE, value_vector)
            else:
                threatSpace = threatSpace_generation(value_vector)

            rr_dict, threat_rank_dict = rv_rr_ranking_dict_generation(threatSpace)
            rr = list(rr_dict.values())

            nmse = nmse_individual(rr_baseline, rr)
            vv_nmse_dict[str(value_vector)] = nmse

    return vv_nmse_dict


def statistics(value_vector_list, threatSpace0):
    vv_average_dict = dict()
    vv_mad_dict = dict()
    if value_vector_list == "ALL":
        value_vector_list_all = list(itertools.combinations(range(11), 3))
        for value_vector in value_vector_list_all:
            value_vector = list(value_vector)
            # check if the condition [x1< x2 < x3] satisfies
            if min(value_vector) != value_vector[0] or max(value_vector) != value_vector[-1]:
                raise ValueError
            else:
                if not threatSpace0:
                    threatSpace = database_process(THREAT_DATABASE, value_vector)
                else:
                    threatSpace = threatSpace_generation(value_vector)

                rr_dict, _ = rv_rr_ranking_dict_generation(threatSpace)
                rr_list = list(rr_dict.values())
                average, mad = statistic_property_individual(rr_list)
                vv_average_dict[str(value_vector)] = average
                vv_mad_dict[str(value_vector)] = mad
    # for a selected list of value vectors
    else:
        for value_vector in value_vector_list:
            if not threatSpace0:
                threatSpace = database_process(THREAT_DATABASE, value_vector)
            else:
                threatSpace = threatSpace_generation(value_vector)
            rr_dict, _ = rv_rr_ranking_dict_generation(threatSpace)
            rr_list = list(rr_dict.values())
            average, mad = statistic_property_individual(rr_list)
            vv_average_dict[str(value_vector)] = average
            vv_mad_dict[str(value_vector)] = mad

    return vv_average_dict, vv_mad_dict


def nmse_individual(list1, list2):
    """ Calculate the nmse for two inputs: list1 and list2"""
    num_1 = len(list1)
    num_2 = len(list2)

    if num_1 != num_2:
        raise ValueError
    else:
        mean_1 = sum(list1)/num_1
        mean_2 = sum(list2)/num_2

        square_error_list = [(v1 - v2) ** 2 / (mean_1 * mean_2) for v1, v2 in zip(list1, list2)]
        if len(square_error_list) != num_1:
            print("There is sth wrong in function nmse")
        nmse = sum(square_error_list)/len(square_error_list)

    return nmse


def Granularity(threatSpace):
    """This function calculates the granularity of the output RiskParameters
    INPUT--> Steps of risk parameters with default value 5
    OUTPUT --> distribution: A dictionary with key-value pair: [Risk_value, count]
           --> gradularity

    Starting from Threat space T0
    """
    # riskParameters = [0, delta, 2*delta]
    distribution = dict()
    for impact in IMPACT_FACTOR:
        for likelyhoodVector in threatSpace:
            # print(likelyhoodVector)
            riskValue = risk_value_calculation(likelyhoodVector, impact)
            if riskValue not in distribution:
                distribution[riskValue] = 1
            else:
                distribution[riskValue] += 1
    gradularity = len(distribution)
    return distribution, gradularity


def Granularity_comparison(delta_list=range(1, 1000)):
    """ This function compares the resulting granularity with different step delta
    INPUT --> Delta range
    Output --> gradularity_comparision: a dictionary with delta and its corresponding granularity
           --> identical_flag: A boolean indicates whether all the granularies are equal with the delta list"""
    gradularity_comparison = dict()
    distribution_tmp = list()
    identical_flag = False
    for delta in delta_list:
        distribution, gradularity = Granularity(delta)
        distribution_values = list(distribution.values())
        distribution_values.sort()
        if distribution_tmp:
            print(distribution_values == distribution_tmp)
        distribution_tmp = distribution_values
        # print("Delta: {}\n".format(delta), gradularity)
        gradularity_comparison[delta] = gradularity
        gradularity_list = list(gradularity_comparison.values())
        # print(gradularity_list)
        identical_flag = all(x == gradularity_list[0] for x in gradularity_list)

    return gradularity_comparison, identical_flag


def statistic_property_individual(list):
    """Calculate the average and average absolute deviation of input list """
    average = sum(list)/len(list)
    variance_vector = [abs(i - average) for i in list]
    mad = sum(variance_vector)/len(variance_vector)
    return average, mad



def plot_experiment_1(data_to_plot, x_label_len):
    x_labels = list()
    for i in range(1, x_label_len + 1):
        x_label = "V{}_Vb".format(str(i))
        x_labels.append(x_label)

    y_pos = range(len(data_to_plot))
    y_value = data_to_plot
    title = "NMSE with various value vectors in threatSpace T1"
    plt.bar(y_pos, y_value, align='center', width=0.3, color=(0.2, 0.6, 0.9))
    plt.xticks(y_pos, x_labels)
    plt.xlabel("value vector")
    plt.ylabel("NMSE")
    plt.title(title)
    plt.grid()
    plt.show()


def plot_experiment_2(data_to_plot):
    title = "NMSE with all possible value vectors within range [0, 10] in T1"
    x_pos = range(len(data_to_plot))
    y_value = data_to_plot
    plt.title(title)

    ax1 = plt.subplot("211")
    ax1.scatter(x_pos, y_value, s=50, marker='+', color=(0.2, 0.6, 0.9))
    ax1.set_xlabel("value vector")
    ax1.set_ylabel("Kendall's Tau")
    ax1.grid()

    ax2 = plt.subplot("212")
    # ax2.title.set_text("Histogram")
    ax2.hist(y_value, bins='auto', rwidth=0.75, color=(0.2, 0.6, 0.9), orientation="horizontal")
    ax2.set_xlabel("Counts")
    ax2.set_ylabel("Kendall's Tau")
    ax2.grid()
    plt.show()


def plot_experiment_3(data_to_plot_dict):
    data_to_plot = list(data_to_plot_dict.values())
    x_pos = range(len(data_to_plot))
    y_value = data_to_plot

    inverse = [(value, key) for key, value in data_to_plot_dict.items()]
    vv_max_mad = max(inverse)[1]
    vv_min_mad = min(inverse)[1]
    s_max = "value vector {} contributes to maximum deviation".format(str(vv_max_mad))
    s_min = "value vector {} contributes to minimum deviation".format(str(vv_min_mad))


    plt.scatter(x_pos, y_value, s=50, marker='+', color=(0.2, 0.6, 0.9))
    plt.xlabel("value vectors")
    plt.ylabel("mean absolute deviations of risk ratios")
    plt.text(13, 0.013, s_min)
    plt.text(13, 0.015, s_max)
    plt.grid()
    plt.show()



def pre_plot_gain_correlation(gain_dict, correlation_dict, y_label):
    """ This function servers for preprocessing the data before plot"""
    vv_list1 = list(gain_dict.keys())
    print(vv_list1)

    vv_list2 = list(correlation_dict.keys())
    print(vv_list2)

    if vv_list1 == vv_list2:
        gain_list = list(gain_dict.values())
        correlation_list = list(correlation_dict.values())
    print(len(gain_list), len(correlation_list))
    plt.scatter(gain_list, correlation_list, s=50, marker='+', color=(0.2, 0.6, 0.9))
    plt.xlabel("Granularity Gain")
    plt.ylabel(y_label)
    plt.text(1.3, 0.06, "base vector = [0, 5, 10]")
    plt.grid()
    plt.show()


def main():
    # granularity_dict, granularity_gain_dict = granularity_gain(value_vector_list, False)
    # granularity_gain_list = list(granularity_gain_dict.values())
    # plot_experiment_5(granularity_gain_list)

    # tau_dict =rank_correlation("ALL", False)
    # tau_list = list(tau_dict.values())
    # plot_experiment_5_2(tau_list)

    # NMSE_dict =NMSE("ALL", False)
    # NMSE_list = list(NMSE_dict.values())
    # plot_experiment_5_2(NMSE_list)

    # granularity_dict, granularity_gain_dict = granularity_gain("ALL", False)
    # NMSE_dict =NMSE("ALL", False)

    # tau_dict =rank_correlation("ALL", False)
    # print("Granularity gain:", granularity_gain_dict)
    # print("Tau:", tau_dict)
    # pre_plot_gain_correlation(granularity_gain_dict, NMSE_dict, "NMSE")

    vv_average, vv_mad = statistics("ALL", False)
    plot_experiment_3(vv_mad)

if __name__ == "__main__":
    main()