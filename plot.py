""" This script contains all plot functions"""

import matplotlib.pyplot as plt

IMPACT_FACTOR_LABELS = ['0', '0.25', '0.5', '0.75', '1']
PARAMETER_LABELS = ['granularity gain', 'kendall tau', 'NMSE']
SCATTER_PLOT_TITLE = "{} with various value vectors in threatSpace T1".format(PARAMETER_LABELS[2])
HIST_PLOT_TITLE = "Histogram of {} with various value vectors in threatSpace T1".format(PARAMETER_LABELS[2])


# def bar_plot(data, value_vector, threatSpace):
#     """This function takes the distribution dictionary as an inpt"""
#     title = "Risk values with value vector = {}, threat space {}".format(str(value_vector), threatSpace)
#     risk_values = list(data.keys())
#     y_pos = range(len(risk_values))
#     y_value = list(data.values())
#     x_label = []
#     for x_label_in in risk_values:
#         if x_label_in - int(x_label_in) == 0:
#             x_label_in = int(x_label_in)
#         x_label_in = str(x_label_in)
#         x_label.append(x_label_in)
#     plt.bar(y_pos, y_value, align='center', width=0.5)
#     plt.xticks(y_pos, x_label)
#     plt.xlabel("Unique risk value")
#     plt.ylabel("Count")
#     plt.title(title)
#     plt.show()

def box_plot(data_to_plot, y_label, title, x_labels, x_label="Granularity Gain"):
    """Plot the boxplot
    Input: data_to_plot: a nested list
    x_label, y_label: str, axis labels
    x_labels: a list of str variables indicating names of each box"""
    fig = plt.figure()
    ax = fig.add_subplot(111)
    ax.set_xticklabels(x_labels, fontsize=8)
    ax.set_title(title)
    ax.set_xlabel(x_label)
    ax.set_ylabel(y_label)
    bp = ax.boxplot(data_to_plot, patch_artist=True)
    plt.grid()
    plt.show()


def bar_plot(data_to_plot, x_label_len, title, x_label, y_label):
    """This script is normally used to bar plot the evaluating parameters
    with specific value vectors
    """

    x_labels = list()
    for i in range(1, x_label_len + 1):
        x_label = "V{}_Vb".format(str(i))
        x_labels.append(x_label)

    y_pos = range(len(data_to_plot))
    y_value = data_to_plot

    plt.bar(y_pos, y_value, align='center', width=0.3, color=(0.2, 0.6, 0.9))
    plt.xticks(y_pos, x_labels)
    plt.xlabel(x_label)
    plt.ylabel(y_label)
    plt.title(title)
    plt.grid()
    plt.show()


def scatter_plot(data_to_plot, title, y_label, x_label= "Value Vectors"):
    """This script is normally used to scatter plot the evaluating parameters (NMSE, Tau, Granularity Gain)
    all possible value vectors combinations
    """
    x_pos = range(len(data_to_plot))
    y_value = data_to_plot

    plt.scatter(x_pos, y_value, s=50, marker='+', color=(0.2, 0.6, 0.9))
    plt.xlabel(x_label)
    plt.ylabel(y_label)
    plt.title(title)
    plt.grid()
    plt.show()


def histogram_plot(data_to_plot, title, x_label, y_label="Counts"):
    """This script is normally used to plot histogram distribution evaluating parameters (NMSE, Tau, Granularity Gain)
    all possible value vectors combinations
    """
    # x_pos = range(len(data_to_plot))
    y_value = data_to_plot

    # plt.hist(y_value, bins='auto', rwidth=0.9, color=(0.2, 0.6, 0.9), histtype='stepfilled')
    plt.hist(y_value, bins='auto', color=(0.2, 0.6, 0.9), edgecolor='azure')
    plt.xlabel(x_label)
    plt.ylabel(y_label)
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


