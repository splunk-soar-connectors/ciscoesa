# --
# File: ciscoesa/ciscoesa_view.py
#
# Copyright (c) Phantom Cyber Corporation, 2017-2018
#
# This unpublished material is proprietary to Phantom Cyber.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Phantom Cyber Corporation.
#
# --


def _get_key_data(report_data):
    """ Function to get key data to fetch data from report data

    :param report_data: Object containing report data
    :return parsed report
    """

    report = dict()
    # Iterating over data for each report
    for key, data in report_data.iteritems():
        report[key] = dict()
        # Iterating over keys in report data, to get only non-empty values
        for report_key, value in data.get("data", {}).iteritems():
            if not value:
                continue
            elif isinstance(value, list):
                for recipient_data in data["data"][report_key]:
                    if recipient_data["recipient"] not in report[key]:
                        report[key][recipient_data["recipient"]] = dict()

                    report[key][recipient_data["recipient"]][report_key] = recipient_data["count"]

    return report


def get_ctx_result(result):
    """ Function to collect information to be rendered for "get report" action

    :param result: report data
    :return result containing summary, data and parameter values
    """

    ctx_result = {}

    param = result.get_param()
    summary = result.get_summary()
    data = result.get_data()

    ctx_result["param"] = param

    if summary:
        ctx_result["summary"] = summary

    if not data:
        ctx_result["data"] = dict()
        return ctx_result

    ctx_result["data"] = _get_key_data(data[0])

    return ctx_result


def display_reports(provides, all_app_runs, context):
    """ Function to render HTML file to display report generated

    :param provides: Action name
    :param all_app_runs: Object containing summary and action_result data
    :param context: Object containing container details
    :return return HTML file name
    """

    context["results"] = results = []

    for summary, action_results in all_app_runs:
        for result in action_results:
            ctx_result = get_ctx_result(result)
            if not ctx_result:
                continue

            results.append(ctx_result)

    return "ciscoesa_display_reports.html"
