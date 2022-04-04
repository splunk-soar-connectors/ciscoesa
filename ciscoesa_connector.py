# File: ciscoesa_connector.py
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
#
#
# Standard library imports
import base64
import datetime
import json
import re
import socket
import urllib

# Phantom imports
import phantom.app as phantom
import requests
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector

# Local imports
import ciscoesa_consts as consts

# Dictionary that maps each error code with its corresponding message
ERROR_RESPONSE_DICT = {
    consts.CISCOESA_REST_RESP_BAD_REQUEST: consts.CISCOESA_REST_RESP_BAD_REQUEST_MSG,
    consts.CISCOESA_REST_RESP_UNAUTHORIZED: consts.CISCOESA_REST_RESP_UNAUTHORIZED_MSG,
    consts.CISCOESA_REST_RESP_FORBIDDEN: consts.CISCOESA_REST_RESP_FORBIDDEN_MSG,
    consts.CISCOESA_REST_RESP_NOT_FOUND: consts.CISCOESA_REST_RESP_NOT_FOUND_MSG,
    consts.CISCOESA_REST_RESP_INTERNAL_SERVER_ERROR: consts.CISCOESA_REST_RESP_INTERNAL_SERVER_ERROR_MSG,
    consts.CISCOESA_REST_RESP_NOT_ACCEPTABLE: consts.CISCOESA_REST_RESP_NOT_ACCEPTABLE_MSG,
    consts.CISCOESA_REST_RESP_ENTITY_TOO_LARGE: consts.CISCOESA_REST_RESP_ENTITY_TOO_LARGE_MSG,
    consts.CISCOESA_REST_RESP_URI_TOO_LONG: consts.CISCOESA_REST_RESP_URI_TOO_LONG_MSG,
    consts.CISCOESA_REST_RESP_NOT_IMPLEMENTED: consts.CISCOESA_REST_RESP_NOT_IMPLEMENTED_MSG,
    consts.CISCOESA_REST_RESP_BAD_GATEWAY: consts.CISCOESA_REST_RESP_BAD_GATEWAY_MSG
}

# Object that maps report title with its corresponding endpoint
# key: report title
# value: report endpoint
REPORT_TITLE_TO_NAME_AND_FILTER_MAPPING = {
    consts.CISCOESA_MAIL_USER_DETAILS_REPORT_TITLE: consts.CISCOESA_MAIL_USER_DETAILS_REPORT_NAME,
    consts.CISCOESA_MAIL_INCOMING_DOMAIN_DETAILS_REPORT_TITLE: consts.CISCOESA_MAIL_INCOMING_DOMAIN_DETAILS_REPORT_NAME,
    consts.CISCOESA_MAIL_INCOMING_IP_HOSTNAME_DETAILS_REPORT_TITLE:
        consts.CISCOESA_MAIL_INCOMING_IP_HOSTNAME_DETAILS_REPORT_NAME,

    consts.CISCOESA_MAIL_INCOMING_NETWORK_OWNER_DETAILS_REPORT_TITLE:
        consts.CISCOESA_MAIL_INCOMING_NETWORK_OWNER_DETAILS_REPORT_NAME,

    consts.CISCOESA_OUTGOING_SENDERS_DOMAIN_DETAILS_REPORT_TITLE:
        consts.CISCOESA_OUTGOING_SENDERS_DOMAIN_DETAILS_REPORT_NAME,

    consts.CISCOESA_MAIL_OUTGOING_SENDERS_IP_HOSTNAME_DETAILS_REPORT_TITLE:
        consts.CISCOESA_MAIL_OUTGOING_SENDERS_IP_HOSTNAME_DETAILS_REPORT_NAME,

    consts.CISCOESA_OUTGOING_CONTENT_FILTERS_REPORT_TITLE: consts.CISCOESA_OUTGOING_CONTENT_FILTERS_REPORT_NAME,
    consts.CISCOESA_OUTGOING_DESTINATIONS_REPORT_TITLE: consts.CISCOESA_OUTGOING_DESTINATIONS_REPORT_NAME,
    consts.CISCOESA_VIRUS_TYPES_REPORT_TITLE: consts.CISCOESA_VIRUS_TYPES_REPORT_NAME,
    consts.CISCOESA_INBOUND_SMTP_AUTH_REPORT_TITLE: consts.CISCOESA_INBOUND_SMTP_AUTH_REPORT_NAME,
    consts.CISCOESA_DLP_OUTGOING_POLICY_REPORT_TITLE: consts.CISCOESA_DLP_OUTGOING_POLICY_REPORT_NAME
}


def _is_ip(ip_address):
    """ Function that validates IP address (IPv4 or IPv6).

    :param ip_address: IP address to verify
    :return: True or False
    """

    # Validate IP address
    if not phantom.is_ip(ip_address):
        try:
            socket.inet_pton(socket.AF_INET6, ip_address)
        except socket.error:
            return False

    return True


class CiscoesaConnector(BaseConnector):
    """ This is an AppConnector class that inherits the BaseConnector class. It implements various actions supported by
    Cisco ESA and helper methods required to run the actions.
    """

    def __init__(self):

        # Calling the BaseConnector's init function
        super(CiscoesaConnector, self).__init__()

        self._url = None
        self._username = None
        self._password = None
        self._verify_server_cert = False

        return

    def initialize(self):
        """ This is an optional function that can be implemented by the AppConnector derived class. Since the
        configuration dictionary is already validated by the time this function is called, it's a good place to do any
        extra initialization of any internal modules. This function MUST return a value of either phantom.APP_SUCCESS or
        phantom.APP_ERROR. If this function returns phantom.APP_ERROR, then AppConnector::handle_action will not get
        called.
        """

        config = self.get_config()
        self._url = config[consts.CISCOESA_CONFIG_URL].strip("/")
        self._username = config[consts.CISCOESA_CONFIG_USERNAME]
        self._password = config[consts.CISCOESA_CONFIG_PASSWORD]
        self._verify_server_cert = config.get(consts.CISCOESA_CONFIG_VERIFY_SSL, False)

        # In "get report" action, if "starts_with" parameter is set, validate IP and email
        self.set_validator(consts.CISCOESA_CONTAINS_IP, None)
        self.set_validator(consts.CISCOESA_CONTAINS_EMAIL, None)

        return phantom.APP_SUCCESS

    def _parse_report_data(self, report_data, action_result):
        """ Function to parse report data by converting its value from object to list format to make output of all
        reports consistent.

        :param report_data: report data
        :param action_result: Object of ActionResult class
        :return: status success/failure and (parsed report data or None)
        """

        # Parsing values of report data by assigning report_key value to "recipient" key and its count to "count" key
        for report_key, report_value in report_data[consts.CISCOESA_GET_REPORT_PARAM_DATA].items():
            # List that will contain parsed values of report data that will be assigned to corresponding keys of report
            parsed_result = []
            # If report value is there, then value will be parsed
            if report_value:
                try:
                    for recipient, count in report_data[consts.CISCOESA_GET_REPORT_PARAM_DATA][report_key].items():
                        parsed_result.append({
                            consts.CISCOESA_GET_REPORT_PARAM_RECIPIENT: recipient,
                            consts.CISCOESA_GET_REPORT_PARAM_COUNT: count
                        })
                except Exception as error:
                    self.debug_print(consts.CISCOESA_GET_REPORT_PARSE_ERROR.format(error))
                    # set the action_result status to error, the handler function will most probably return as is
                    return action_result.set_status(phantom.APP_ERROR, consts.CISCOESA_GET_REPORT_PARSE_ERROR.format(
                        error
                    )), None

                report_data[consts.CISCOESA_GET_REPORT_PARAM_DATA][report_key] = parsed_result

        return phantom.APP_SUCCESS, report_data

    def _validate_date_time(self, date_time_value, action_result):
        """ Function used to validate date and time format. As per the app configuration, date and time must be provided
        in YYYY-MM-DDTHH:00 format.

        :param date_time_value: date and time value that needs to be split and validated
        :param action_result: Object of ActionResult class
        :return: status success/failure and (parsed datetime or None)
        """

        date_time = date_time_value.split("T")

        # If given datetime not in expected format
        if len(date_time) <= 1:
            self.debug_print(consts.CISCOESA_DATE_TIME_FORMAT_ERROR)
            return action_result.set_status(phantom.APP_ERROR, consts.CISCOESA_DATE_TIME_FORMAT_ERROR), None

        if len(date_time[1].split(":")) != 2:
            self.debug_print(consts.CISCOESA_DATE_TIME_FORMAT_ERROR)
            return action_result.set_status(phantom.APP_ERROR, consts.CISCOESA_DATE_TIME_FORMAT_ERROR), None

        date = date_time[0].split("-")
        hour = date_time[1].split(":")[0]

        if len(date) != 3:
            self.debug_print(consts.CISCOESA_DATE_TIME_FORMAT_ERROR)
            return action_result.set_status(phantom.APP_ERROR, consts.CISCOESA_DATE_TIME_FORMAT_ERROR), None

        try:
            parsed_date_time = datetime.datetime(
                year=int(date[0]), month=int(date[1]), day=int(date[2]), hour=int(hour)
            )
        except:
            self.debug_print(consts.CISCOESA_DATE_TIME_VALIDATION_ERROR)
            return action_result.set_status(phantom.APP_ERROR, consts.CISCOESA_DATE_TIME_VALIDATION_ERROR), None

        return phantom.APP_SUCCESS, parsed_date_time

    def _make_rest_call(self, endpoint, action_result, params=None, method="get", timeout=None):
        """ Function that makes the REST call to the device. It is a generic function that can be called from various
        action handlers.

        :param endpoint: REST endpoint that needs to be appended to the service address
        :param action_result: object of ActionResult class
        :param params: request parameters if method is get
        :param method: get/post/put/delete ( Default method will be "get" )
        :param timeout: request timeout in seconds
        :return: status success/failure(along with appropriate message), response obtained by making an API call
        """

        response_data = None

        try:
            request_func = getattr(requests, method)

        except AttributeError:
            self.debug_print(consts.CISCOESA_ERR_API_UNSUPPORTED_METHOD.format(method=method))
            # set the action_result status to error, the handler function will most probably return as is
            return action_result.set_status(
                phantom.APP_ERROR, consts.CISCOESA_ERR_API_UNSUPPORTED_METHOD
            ), response_data

        except Exception as e:
            self.debug_print(consts.CISCOESA_EXCEPTION_OCCURRED, e)
            # set the action_result status to error, the handler function will most probably return as is
            return action_result.set_status(phantom.APP_ERROR, consts.CISCOESA_EXCEPTION_OCCURRED, e), response_data

        auth_string = "{username}:{password}".format(username=self._username, password=self._password)

        credentials = base64.b64encode(auth_string.encode('utf-8')).decode()

        headers = {
            "Accept": "application/json",
            "Authorization": "Basic {credentials}".format(credentials=credentials)
        }

        try:
            response = request_func("{base_url}{endpoint}".format(base_url=self._url, endpoint=endpoint),
                                    params=params, headers=headers, timeout=timeout, verify=self._verify_server_cert)
        except Exception as e:
            self.debug_print(consts.CISCOESA_ERR_SERVER_CONNECTION, e)
            # set the action_result status to error, the handler function will most probably return as is
            return action_result.set_status(phantom.APP_ERROR, consts.CISCOESA_ERR_SERVER_CONNECTION, e), response_data

        # Try parsing the json
        try:
            content_type = response.headers.get("content-type")
            if content_type and content_type.find("json") != -1:
                response_data = response.json()
            else:
                response_data = response.text

        except Exception as e:
            # r.text is guaranteed to be NON None, it will be empty, but not None
            msg_string = consts.CISCOESA_ERR_JSON_PARSE.format(raw_text=response.text)
            self.debug_print(msg_string, e)
            # set the action_result status to error, the handler function will most probably return as is
            return action_result.set_status(phantom.APP_ERROR, msg_string, e), response_data

        if response.status_code in ERROR_RESPONSE_DICT:
            message = ERROR_RESPONSE_DICT[response.status_code]

            # overriding message if available in response
            if isinstance(response_data, dict):
                message = response_data.get("error", {}).get("message", message)

            self.debug_print(consts.CISCOESA_ERR_FROM_SERVER.format(status=response.status_code, detail=message))
            # set the action_result status to error, the handler function will most probably return as is
            return action_result.set_status(phantom.APP_ERROR, consts.CISCOESA_ERR_FROM_SERVER,
                                            status=response.status_code, detail=message), response_data

        # In case of success scenario
        if response.status_code == consts.CISCOESA_REST_RESP_SUCCESS:
            # If response obtained is not in object format
            if not isinstance(response_data, dict):
                self.debug_print(consts.CISCOESA_UNEXPECTED_RESPONSE.format(report_name=response_data))
                return action_result.set_status(phantom.APP_ERROR, consts.CISCOESA_UNEXPECTED_RESPONSE.format(
                    report_name=response_data
                )), response_data

            return phantom.APP_SUCCESS, response_data

        # If response code is unknown
        message = consts.CISCOESA_REST_RESP_OTHER_ERROR_MSG

        if isinstance(response_data, dict):
            message = response_data.get("error", {}).get("message", message)

        self.debug_print(consts.CISCOESA_ERR_FROM_SERVER.format(status=response.status_code, detail=message))

        # All other response codes from REST call
        # Set the action_result status to error, the handler function will most probably return as is
        return action_result.set_status(phantom.APP_ERROR, consts.CISCOESA_ERR_FROM_SERVER,
                                        status=response.status_code,
                                        detail=message), response_data

    def _decode_url(self, param):
        """ Process URL and return it stripped
        of the 'secure-web.cisco.com' portion and unquoted

        :param param: dictionary of input parameters
        :return: status success/failure
        """

        action_result = self.add_action_result(ActionResult(dict(param)))

        encoded_url = param['encoded_url']
        sw_match = re.match(r'^(https?://)?secure-web\.cisco\.com/.+/(?P<quoted>.+)$', encoded_url)

        # Parse the URL if it looks like what we are expecting otherwise return the whole URL unquoted.
        if sw_match:
            message = 'Parsed from secure-web.cisco.com URL and decoded'
            if sw_match.group('quoted'):
                decode_me = sw_match.group('quoted')
            else:
                decode_me = encoded_url.split('/')[-1]
        else:
            message = 'Decoded entire URL'
            decode_me = encoded_url

        action_result.add_data({'decoded_url': urllib.parse.unquote(decode_me)})

        return action_result.set_status(phantom.APP_SUCCESS, message)

    def _get_report(self, param):
        """ Function to retrieve statistical report from the Email Security appliance.

        :param param: dictionary of input parameters
        :return: status success/failure
        """

        action_result = self.add_action_result(ActionResult(dict(param)))
        result_data = dict()
        api_params = dict()

        # Getting mandatory parameters
        report_title = param[consts.CISCOESA_GET_REPORT_JSON_REPORT_TITLE]

        # Getting optional parameters
        start_time = param.get(consts.CISCOESA_GET_REPORT_JSON_START_TIME)
        end_time = param.get(consts.CISCOESA_GET_REPORT_JSON_END_TIME)
        search_value = param.get(consts.CISCOESA_GET_REPORT_JSON_SEARCH_VALUE)
        limit = int(param.get(consts.CISCOESA_GET_REPORT_JSON_LIMIT, consts.CISCOESA_DEFAULT_LIMIT))
        starts_with = param.get(consts.CISCOESA_GET_REPORT_JSON_STARTS_WITH)

        # If both start_time and end_time is not given, then by default, API will query report for last 250 days
        if not start_time and not end_time:
            start_time = (datetime.datetime.now() - datetime.timedelta(
                days=consts.CISCOESA_DEFAULT_SPAN_DAYS
            )).strftime(consts.CISCOESA_INPUT_TIME_FORMAT)

            end_time = datetime.datetime.now().strftime(consts.CISCOESA_INPUT_TIME_FORMAT)

        # If start_time is given, but end_time is not given
        elif not end_time:
            try:
                # end_time will be calculated equivalent to given start_time
                end_time = datetime.datetime.strptime(start_time, consts.CISCOESA_INPUT_TIME_FORMAT) + \
                           datetime.timedelta(days=consts.CISCOESA_DEFAULT_SPAN_DAYS)
                # If calculated end_time is a future date, then it will be replaced by current date
                if datetime.datetime.strptime(start_time, consts.CISCOESA_INPUT_TIME_FORMAT) + datetime.timedelta(
                        days=consts.CISCOESA_DEFAULT_SPAN_DAYS) >= datetime.datetime.now():
                    end_time = datetime.datetime.now()
            except:
                self.debug_print(consts.CISCOESA_DATE_TIME_FORMAT_ERROR)
                return action_result.set_status(phantom.APP_ERROR, consts.CISCOESA_DATE_TIME_FORMAT_ERROR)

            # Converting date in string format
            end_time = end_time.strftime(consts.CISCOESA_INPUT_TIME_FORMAT)

        # If start_time is not given, but end_time is given
        elif not start_time:
            try:
                # start_time will be calculated equivalent to given end_time
                temp_time1 = datetime.datetime.strptime(end_time, consts.CISCOESA_INPUT_TIME_FORMAT)
                temp_time2 = datetime.timedelta(days=consts.CISCOESA_DEFAULT_SPAN_DAYS)
                start_time = ( temp_time1 - temp_time2 ).strftime(consts.CISCOESA_INPUT_TIME_FORMAT)
            except:
                self.debug_print(consts.CISCOESA_DATE_TIME_FORMAT_ERROR)
                return action_result.set_status(phantom.APP_ERROR, consts.CISCOESA_DATE_TIME_FORMAT_ERROR)

        # Validating start_time
        validate_status, parsed_start_time = self._validate_date_time(start_time, action_result)

        # Something went wrong while validating start_time
        if phantom.is_fail(validate_status):
            return action_result.get_status()

        # Validating end_time
        validate_status, parsed_end_time = self._validate_date_time(end_time, action_result)

        # Something went wrong while validating end_time
        if phantom.is_fail(validate_status):
            return action_result.get_status()

        # Comparing start time and end time
        if parsed_start_time >= parsed_end_time:
            self.debug_print(consts.CISCOESA_START_TIME_GREATER_THEN_END_TIME)
            return action_result.set_status(phantom.APP_ERROR, consts.CISCOESA_START_TIME_GREATER_THEN_END_TIME)

        # if starts_with parameter is not set, then IP and email must be validated
        if not starts_with and search_value and report_title in \
                [consts.CISCOESA_MAIL_INCOMING_IP_HOSTNAME_DETAILS_REPORT_TITLE,
                 consts.CISCOESA_MAIL_OUTGOING_SENDERS_IP_HOSTNAME_DETAILS_REPORT_TITLE,
                 consts.CISCOESA_MAIL_USER_DETAILS_REPORT_TITLE]:
            # Search value should be validated to be either an IP address or an email, if report title is
            # "Incoming Mail: IP Addresses", "Outgoing Senders: IP Addresses" or "Internal Users"
            if not _is_ip(search_value) and not phantom.is_email(search_value):
                self.debug_print(consts.CISCOESA_SEARCH_VALUE_VALIDATION_FAIL)
                return action_result.set_status(phantom.APP_ERROR, consts.CISCOESA_SEARCH_VALUE_VALIDATION_FAIL)

        # Report will be queried for last given duration period
        # Time zone that will be considered for calculating time and date will be GMT having 00:00 offset from UTC
        # Time to query the report supports only 00 minutes
        try:
            start_time = parsed_start_time.strftime(consts.CISCOESA_API_TIME_FORMAT)
            end_time = parsed_end_time.strftime(consts.CISCOESA_API_TIME_FORMAT)
        except Exception as error:
            self.debug_print(error)
            return action_result.set_status(phantom.APP_ERROR, error)

        api_params[consts.CISCOESA_GET_REPORT_PARAM_DURATION] = consts.CISCOESA_DURATION_FORMAT.format(
            start_time=start_time, end_time=end_time
        )

        # Obtain report name
        report_name = REPORT_TITLE_TO_NAME_AND_FILTER_MAPPING[report_title]

        # You cannot use the entity and max=n attributes in the same request.
        # If entity is given to filter a report, then limit will not be provided while making REST call
        if search_value:
            api_params[consts.CISCOESA_GET_REPORT_PARAM_ENTITY] = search_value
            api_params.pop(consts.CISCOESA_GET_REPORT_PARAM_MAX, None)
            # If entity is given to filter the result and "starts_with" is set, then only "starts_with" parameter will
            # be set in api_params
            if starts_with:
                api_params[consts.CISCOESA_GET_REPORT_JSON_STARTS_WITH] = starts_with

        # If limit is given and entity is not provided to filter the report data, then "entity" and "starts_with"
        # keys will be removed from api_params object
        elif limit or limit == 0:
            api_params[consts.CISCOESA_GET_REPORT_PARAM_MAX] = int(limit)
            api_params.pop(consts.CISCOESA_GET_REPORT_PARAM_ENTITY, None)
            api_params.pop(consts.CISCOESA_GET_REPORT_JSON_STARTS_WITH, None)

        report_endpoint = consts.CISCOESA_GET_REPORT_ENDPOINT.format(report_name=report_name)
        self.send_progress(consts.CISCOESA_GET_REPORT_INTERMEDIATE_MSG.format(report_title=report_title))

        # Making REST call to get report data
        response_status, report_data = self._make_rest_call(report_endpoint, action_result, params=api_params)

        # Something went wrong while querying a report
        if phantom.is_fail(response_status):
            self.debug_print(consts.CISCOESA_GET_REPORT_ERROR.format(report_title=report_title))
            return action_result.get_status()

        # If report is queried by providing an entity to filter results, then its response data needs to be
        # formatted in generic format
        if search_value and report_data.get(consts.CISCOESA_GET_REPORT_PARAM_DATA, {}):
            parsed_dict = dict()
            for matching_key in report_data[consts.CISCOESA_GET_REPORT_PARAM_DATA].keys():
                for key, value in report_data[consts.CISCOESA_GET_REPORT_PARAM_DATA][matching_key].items():
                    if key not in parsed_dict:
                        parsed_dict[key] = dict()
                    parsed_dict[key][matching_key] = value

            report_data[consts.CISCOESA_GET_REPORT_PARAM_DATA] = parsed_dict

        # Parsing report data
        if report_data.get(consts.CISCOESA_GET_REPORT_PARAM_DATA):
            parse_data_status, report_data = self._parse_report_data(report_data, action_result)

            if phantom.is_fail(parse_data_status):
                return action_result.get_status()

        result_data[report_name] = report_data

        action_result.add_data(result_data)

        return action_result.set_status(phantom.APP_SUCCESS, consts.CISCOESA_REPORTS_QUERIED_SUCCESS_MSG)

    def _test_asset_connectivity(self, param):
        """ This function tests the connectivity of an asset with given credentials.

        :param param: (not used in this method)
        :return: status success/failure
        """

        action_result = ActionResult()

        self.save_progress(consts.CISCOESA_CONNECTION_TEST_MSG)
        self.save_progress("Configured URL: {url}".format(url=self._url))

        ret_value, response = self._make_rest_call(endpoint=consts.CISCOESA_TEST_CONNECTIVITY_ENDPOINT,
                                                   action_result=action_result, timeout=30)

        if phantom.is_fail(ret_value):
            self.save_progress(action_result.get_message())
            self.set_status(phantom.APP_ERROR, consts.CISCOESA_TEST_CONNECTIVITY_FAIL)
            return action_result.get_status()

        self.set_status_save_progress(phantom.APP_SUCCESS, consts.CISCOESA_TEST_CONNECTIVITY_PASS)

        return action_result.get_status()

    def handle_action(self, param):
        """ This function gets current action identifier and calls member function of its own to handle the action.

        :param param: dictionary which contains information about the actions to be executed
        :return: status success/failure
        """

        # Dictionary mapping each action with its corresponding actions
        action_mapping = {
            "test_asset_connectivity": self._test_asset_connectivity,
            "get_report": self._get_report,
            "decode_url": self._decode_url
        }

        action = self.get_action_identifier()

        try:
            run_action = action_mapping[action]
        except:
            raise ValueError("action {action} is not supported".format(action=action))

        return run_action(param)

    def finalize(self):
        """ This function gets called once all the param dictionary elements are looped over and no more handle_action
        calls are left to be made. It gives the AppConnector a chance to loop through all the results that were
        accumulated by multiple handle_action function calls and create any summary if required. Another usage is
        cleanup, disconnect from remote devices etc.
        """

        return phantom.APP_SUCCESS


if __name__ == "__main__":

    import sys

    import pudb

    pudb.set_trace()
    if len(sys.argv) < 2:
        print("No test json specified as input")
        sys.exit(0)
    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))
        connector = CiscoesaConnector()
        connector.print_progress_message = True
        return_value = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(return_value), indent=4))
    sys.exit(0)
