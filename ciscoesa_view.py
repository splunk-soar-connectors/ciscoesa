# File: ciscoesa_view.py
#
# Copyright (c) 2017-2022 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.

def _get_key_data(report_data):
    """ Function to get key data to fetch data from report data

    :param report_data: Object containing report data
    :return parsed report
    """

    report = dict()
    # Iterating over data for each report
    for key, data in report_data.items():
        report[key] = dict()
        # Iterating over keys in report data, to get only non-empty values
        for report_key, value in data.get("data", {}).items():
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
