# File: ciscoesa_connector.py
#
# Copyright (c) 2017-2025 Splunk Inc.
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
import datetime
import json
import re
import socket
import urllib.parse
from typing import TYPE_CHECKING, Any, Iterable, Optional, cast

import requests
from bs4 import BeautifulSoup
from dateutil import parser

if TYPE_CHECKING:
    from unittest.mock import MagicMock

    phantom = MagicMock()

    class ActionResult(MagicMock):
        pass

    class BaseConnector(MagicMock):
        pass

else:
    import phantom.app as phantom
    from phantom.action_result import ActionResult
    from phantom.base_connector import BaseConnector

import ciscoesa_consts as consts

# Dictionary that maps each error code with its corresponding message
ERROR_RESPONSE_DICT = {
    consts.CISCOESA_REST_RESP_BAD_REQUEST: consts.CISCOESA_REST_RESP_BAD_REQUEST_MESSAGE,
    consts.CISCOESA_REST_RESP_UNAUTHORIZED: consts.CISCOESA_REST_RESP_UNAUTHORIZED_MESSAGE,
    consts.CISCOESA_REST_RESP_FORBIDDEN: consts.CISCISCOESA_REST_RESP_FORBIDDEN_MESSAGE,
    consts.CISCOESA_REST_RESP_NOT_FOUND: consts.CISCOESA_REST_RESP_NOT_FOUND_MESSAGE,
    consts.CISCOESA_REST_RESP_INTERNAL_SERVER_ERROR: consts.CISCOESA_REST_RESP_INTERNAL_SERVER_ERROR_MESSAGE,
    consts.CISCOESA_REST_RESP_NOT_ACCEPTABLE: consts.CISCOESA_REST_RESP_NOT_ACCEPTABLE_MESSAGE,
    consts.CISCOESA_REST_RESP_ENTITY_TOO_LARGE: consts.CISCOESA_REST_RESP_ENTITY_TOO_LARGE_MESSAGE,
    consts.CISCOESA_REST_RESP_URI_TOO_LONG: consts.CISCOESA_REST_RESP_URI_TOO_LONG_MESSAGE,
    consts.CISCOESA_REST_RESP_NOT_IMPLEMENTED: consts.CISCOESA_REST_RESP_NOT_IMPLEMENTED_MESSAGE,
    consts.CISCOESA_REST_RESP_BAD_GATEWAY: consts.CISCOESA_REST_RESP_BAD_GATEWAY_MESSAGE,
}

# Object that maps report title with its corresponding endpoint
# key: report title
# value: report endpoint
REPORT_TITLE_TO_NAME_AND_FILTER_MAPPING = {
    consts.CISCOESA_MAIL_USER_DETAILS_REPORT_TITLE: consts.CISCOESA_MAIL_USER_DETAILS_REPORT_NAME,
    consts.CISCOESA_MAIL_INCOMING_DOMAIN_DETAILS_REPORT_TITLE: consts.CISCOESA_MAIL_INCOMING_DOMAIN_DETAILS_REPORT_NAME,
    consts.CISCOESA_MAIL_INCOMING_IP_HOSTNAME_DETAILS_REPORT_TITLE: consts.CISCOESA_MAIL_INCOMING_IP_HOSTNAME_DETAILS_REPORT_NAME,
    consts.CISCOESA_MAIL_INCOMING_NETWORK_OWNER_DETAILS_REPORT_TITLE: consts.CISCOESA_MAIL_INCOMING_NETWORK_OWNER_DETAILS_REPORT_NAME,
    consts.CISCOESA_OUTGOING_SENDERS_DOMAIN_DETAILS_REPORT_TITLE: consts.CISCOESA_OUTGOING_SENDERS_DOMAIN_DETAILS_REPORT_NAME,
    consts.CISCOESA_MAIL_OUTGOING_SENDERS_IP_HOSTNAME_DETAILS_REPORT_TITLE: consts.CISCOESA_MAIL_OUTGOING_SENDERS_IP_HOSTNAME_DETAILS_REPORT_NAME,  # noqa: E501
    consts.CISCOESA_OUTGOING_CONTENT_FILTERS_REPORT_TITLE: consts.CISCOESA_OUTGOING_CONTENT_FILTERS_REPORT_NAME,
    consts.CISCOESA_OUTGOING_DESTINATIONS_REPORT_TITLE: consts.CISCOESA_OUTGOING_DESTINATIONS_REPORT_NAME,
    consts.CISCOESA_VIRUS_TYPES_REPORT_TITLE: consts.CISCOESA_VIRUS_TYPES_REPORT_NAME,
    consts.CISCOESA_INBOUND_SMTP_AUTH_REPORT_TITLE: consts.CISCOESA_INBOUND_SMTP_AUTH_REPORT_NAME,
    consts.CISCOESA_DLP_OUTGOING_POLICY_REPORT_TITLE: consts.CISCOESA_DLP_OUTGOING_POLICY_REPORT_NAME,
}


def _is_ip(ip_address: str) -> bool:
    """Function that validates IP address (IPv4 or IPv6).

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
    """This is an AppConnector class that inherits the BaseConnector class. It implements various actions supported by
    Cisco ESA and helper methods required to run the actions.
    """

    def __init__(self) -> None:

        # Calling the BaseConnector's init function
        super(CiscoesaConnector, self).__init__()

        self._url = None
        self._username = None
        self._password = None
        self._verify_server_cert = False

    def _process_empty_response(self, response: requests.Response, action_result: ActionResult) -> tuple[bool, Optional[dict]]:
        if response.status_code == 200:
            return phantom.APP_SUCCESS, {}

        return action_result.set_status(phantom.APP_ERROR, "Empty response and no information in the header"), None

    def _process_html_response(self, response: requests.Response, action_result: ActionResult) -> tuple[bool, None]:
        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split("\n")
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = "\n".join(split_lines)
        except Exception:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code, error_text)

        message = message.replace("{", "{{").replace("}", "}}")
        return action_result.set_status(phantom.APP_ERROR, message), None

    def _process_json_response(self, r: requests.Response, action_result: ActionResult) -> tuple[bool, Optional[Any]]:
        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(str(e))), None

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return phantom.APP_SUCCESS, resp_json

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(r.status_code, r.text.replace("{", "{{").replace("}", "}}"))

        return action_result.set_status(phantom.APP_ERROR, message), None

    def _process_response(self, r: requests.Response, action_result: ActionResult) -> tuple[bool, Optional[Any]]:
        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, "add_debug_data"):
            action_result.add_debug_data({"r_status_code": r.status_code})
            action_result.add_debug_data({"r_text": r.text})
            action_result.add_debug_data({"r_headers": r.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        if "json" in r.headers.get("Content-Type", ""):
            return self._process_json_response(r, action_result)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if "html" in r.headers.get("Content-Type", ""):
            return self._process_html_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_response(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
            r.status_code, r.text.replace("{", "{{").replace("}", "}}")
        )

        return action_result.set_status(phantom.APP_ERROR, message), None

    def _get_error_message_from_exception(self, e: Exception) -> str:
        """This function is used to get appropriate error message from the exception.
        :param e: Exception object
        :return: error message
        """
        error_message = consts.CISCOESA_ERROR_MESSAGE
        error_code = consts.CISCOESA_ERROR_CODE_MESSAGE
        self.error_print("Exception occurred: ", e)

        try:
            if hasattr(e, "args"):
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_message = e.args[1]
                elif len(e.args) == 1:
                    error_code = consts.CISCOESA_ERROR_CODE_MESSAGE
                    error_message = e.args[0]
        except Exception as ex:
            self.error_print("Error occurred while retrieving exception information: ", ex)

        if not error_code:
            error_text = "Error Message: {}".format(error_message)
        else:
            error_text = consts.CISCOESA_ERROR_MESSAGE_FORMAT.format(error_code, error_message)

        return error_text

    def initialize(self) -> bool:
        """This is an optional function that can be implemented by the AppConnector derived class. Since the
        configuration dictionary is already validated by the time this function is called, it's a good place to do any
        extra initialization of any internal modules. This function MUST return a value of either phantom.APP_SUCCESS or
        phantom.APP_ERROR. If this function returns phantom.APP_ERROR, then AppConnector::handle_action will not get
        called.
        """
        config = self.get_config()
        self._url = config[consts.CISCOESA_CONFIG_URL].strip("/")
        self._sma_url = (config.get(consts.CISCOESA_CONFIG_SMA_URL, False) or self._url).strip("/")

        if self._url == self._sma_url:
            self._esa_is_sma = True
        else:
            self._esa_is_sma = False

        self._username = config[consts.CISCOESA_CONFIG_USERNAME]
        self._password = config[consts.CISCOESA_CONFIG_PASSWORD]
        self._verify_server_cert = config.get(consts.CISCOESA_CONFIG_VERIFY_SSL, False)

        self._cluster = config[consts.CISCOESA_CONFIG_CLUSTER]
        self._timeout = config.get(consts.CISCOESA_CONFIG_TIMEOUT, consts.CISCOESA_REQUEST_TIMEOUT)
        self._auth = (self._username, self._password)

        # In "get report" action, if "starts_with" parameter is set, validate IP and email
        self.set_validator(consts.CISCOESA_CONTAINS_IP, None)
        self.set_validator(consts.CISCOESA_CONTAINS_EMAIL, None)

        return phantom.APP_SUCCESS

    def _validate_integers(self, action_result: ActionResult, parameter: Optional[Any], key: str, allow_zero: bool = False) -> Optional[int]:
        """This method is to check if the provided input parameter value
        is a non-zero positive integer and returns the integer value of the parameter itself.
        :param action_result: Action result or BaseConnector object
        :param parameter: input parameter
        :return: integer value of the parameter or None in case of failure
        """

        if parameter is not None:
            try:
                if not float(parameter).is_integer():
                    action_result.set_status(phantom.APP_ERROR, consts.CISCOESA_VALIDATE_INTEGER_MESSAGE.format(key=key))
                    return None
                parameter = int(parameter)

            except Exception:
                action_result.set_status(phantom.APP_ERROR, consts.CISCOESA_VALIDATE_INTEGER_MESSAGE.format(key=key))
                return None

            if parameter < 0:
                action_result.set_status(phantom.APP_ERROR, "Please provide a valid non-negative integer value in the {} parameter".format(key))
                return None
            if not allow_zero and parameter == 0:
                action_result.set_status(phantom.APP_ERROR, "Please provide non-zero positive integer in {}".format(key))
                return None

        return parameter

    def _validate_date_time(self, date_time_value: str, action_result: ActionResult) -> tuple[bool, Optional[datetime.datetime]]:
        """Function used to validate date and time format. As per the app configuration, date and time must be provided
        in YYYY-MM-DDTHH:00 format.

        :param date_time_value: date and time value that needs to be split and validated
        :param action_result: Object of ActionResult class
        :return: status success/failure and (parsed datetime or None)
        """

        date_time = date_time_value.split("T")

        # If given datetime not in expected format
        if len(date_time) <= 1:
            self.error_print(consts.CISCOESA_DATE_TIME_FORMAT_ERROR)
            return action_result.set_status(phantom.APP_ERROR, consts.CISCOESA_DATE_TIME_FORMAT_ERROR), None

        if len(date_time[1].split(":")) != 2:
            self.error_print(consts.CISCOESA_DATE_TIME_FORMAT_ERROR)
            return action_result.set_status(phantom.APP_ERROR, consts.CISCOESA_DATE_TIME_FORMAT_ERROR), None

        date = date_time[0].split("-")
        hour = date_time[1].split(":")[0]

        if len(date) != 3:
            self.error_print(consts.CISCOESA_DATE_TIME_FORMAT_ERROR)
            return action_result.set_status(phantom.APP_ERROR, consts.CISCOESA_DATE_TIME_FORMAT_ERROR), None

        try:
            parsed_date_time = datetime.datetime(year=int(date[0]), month=int(date[1]), day=int(date[2]), hour=int(hour))
        except Exception:
            self.error_print(consts.CISCOESA_DATE_TIME_VALIDATION_ERROR)
            return action_result.set_status(phantom.APP_ERROR, consts.CISCOESA_DATE_TIME_VALIDATION_ERROR), None

        return phantom.APP_SUCCESS, parsed_date_time

    def _make_rest_call(
        self, endpoint: str, action_result: ActionResult, method: str = "get", use_sma: bool = False, **kwargs
    ) -> tuple[bool, Optional[Any]]:
        """Function that makes the REST call to the device. It is a generic function that can be called from various
        action handlers.

        :param endpoint: REST endpoint that needs to be appended to the service address
        :param action_result: object of ActionResult class
        :param params: request parameters if method is get
        :param method: get/post/put/delete ( Default method will be "get" )
        :param timeout: request timeout in seconds
        :return: status success/failure(along with appropriate message), response obtained by making an API call
        """

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json

        # Create a URL to connect to
        url = f"{self._url}{endpoint}" if not use_sma else f"{self._sma_url}{endpoint}"

        try:
            r = request_func(url, timeout=self._timeout, auth=self._auth, verify=self._verify_server_cert, **kwargs)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(str(e))), resp_json

        return self._process_response(r, action_result)

    def _decode_url(self, param: dict[str, Any]) -> bool:
        """Process URL and return it stripped
        of the 'secure-web.cisco.com' portion and unquoted

        :param param: dictionary of input parameters
        :return: status success/failure
        """

        self.save_progress("Decoding URL")

        action_result = self.add_action_result(ActionResult(dict(param)))

        encoded_url = param["encoded_url"]
        sw_match = re.match(r"^(https?://)?secure-web\.cisco\.com/.+/(?P<quoted>.+)$", encoded_url)

        # Parse the URL if it looks like what we are expecting otherwise return the whole URL unquoted.
        if sw_match:
            message = "Parsed from secure-web.cisco.com URL and decoded"
            if sw_match.group("quoted"):
                decode_me = sw_match.group("quoted")
            else:
                decode_me = encoded_url.split("/")[-1]
        else:
            message = "Decoded entire URL"
            decode_me = encoded_url

        action_result.add_data({"decoded_url": urllib.parse.unquote(decode_me)})

        self.save_progress("Decoding URL succeeded")

        return action_result.set_status(phantom.APP_SUCCESS, message)

    def _get_report(self, param: dict[str, Any]) -> bool:
        """Function to retrieve statistical report from the Email Security appliance.

        :param param: dictionary of input parameters
        :return: status success/failure
        """

        action_result = self.add_action_result(ActionResult(dict(param)))
        api_params: dict[str, Any] = {"device_type": "esa"}

        # Getting mandatory parameters
        report_title = param[consts.CISCOESA_GET_REPORT_JSON_REPORT_TITLE]
        if report_title not in consts.CISCOESA_REPORT_TITLE:
            return action_result.set_status(phantom.APP_ERROR, consts.CISCOESA_REPORT_TITLE_ERROR)

        # Getting optional parameters
        start_time: Optional[str] = param.get(consts.CISCOESA_GET_REPORT_JSON_START_TIME)
        end_time: Optional[str] = param.get(consts.CISCOESA_GET_REPORT_JSON_END_TIME)
        filter_by = param.get(consts.CISCOESA_GET_REPORT_JSON_FILTER_BY)
        filter_value = param.get(consts.CISCOESA_GET_REPORT_JSON_FILTER_VALUE)
        limit = self._validate_integers(
            action_result, param.get(consts.CISCOESA_GET_REPORT_JSON_LIMIT, consts.CISCOESA_DEFAULT_LIMIT), consts.CISCOESA_GET_REPORT_JSON_LIMIT
        )
        if limit is None:
            return action_result.get_status()
        offset = self._validate_integers(
            action_result,
            param.get(consts.CISCOESA_GET_REPORT_JSON_OFFSET, consts.CISCOESA_DEFAULT_OFFSET),
            consts.CISCOESA_GET_REPORT_JSON_OFFSET,
            allow_zero=True,
        )
        if offset is None:
            return action_result.get_status()
        starts_with = param.get(consts.CISCOESA_GET_REPORT_JSON_STARTS_WITH)
        order_by = param.get(consts.CISCOESA_GET_REPORT_JSON_ORDER_BY)
        order_dir = param.get(consts.CISCOESA_GET_REPORT_JSON_ORDER_DIR)

        api_params[consts.CISCOESA_GET_REPORT_JSON_LIMIT] = limit
        api_params[consts.CISCOESA_GET_REPORT_JSON_OFFSET] = offset

        # If both start_time and end_time is not given, then by default, API will query report for last 250 days
        if not start_time and not end_time:
            start_time = (datetime.datetime.now() - datetime.timedelta(days=consts.CISCOESA_DEFAULT_SPAN_DAYS)).strftime(
                consts.CISCOESA_INPUT_TIME_FORMAT
            )

            end_time = datetime.datetime.now().strftime(consts.CISCOESA_INPUT_TIME_FORMAT)

        # If start_time is given, but end_time is not given
        elif start_time and not end_time:
            try:
                # end_time will be calculated equivalent to given start_time
                end_time_dt = datetime.datetime.strptime(start_time, consts.CISCOESA_INPUT_TIME_FORMAT) + datetime.timedelta(
                    days=consts.CISCOESA_DEFAULT_SPAN_DAYS
                )
                # If calculated end_time is a future date, then it will be replaced by current date
                if (
                    datetime.datetime.strptime(start_time, consts.CISCOESA_INPUT_TIME_FORMAT)
                    + datetime.timedelta(days=consts.CISCOESA_DEFAULT_SPAN_DAYS)
                    >= datetime.datetime.now()
                ):
                    end_time_dt = datetime.datetime.now()
            except Exception:
                self.error_print(consts.CISCOESA_DATE_TIME_FORMAT_ERROR)
                return action_result.set_status(phantom.APP_ERROR, consts.CISCOESA_DATE_TIME_FORMAT_ERROR)

            # Converting date in string format
            end_time = end_time_dt.strftime(consts.CISCOESA_INPUT_TIME_FORMAT)

        # If start_time is not given, but end_time is given
        elif end_time and not start_time:
            try:
                # start_time will be calculated equivalent to given end_time
                temp_time1 = datetime.datetime.strptime(end_time, consts.CISCOESA_INPUT_TIME_FORMAT)
                temp_time2 = datetime.timedelta(days=consts.CISCOESA_DEFAULT_SPAN_DAYS)
                start_time = (temp_time1 - temp_time2).strftime(consts.CISCOESA_INPUT_TIME_FORMAT)
            except Exception:
                self.error_print(consts.CISCOESA_DATE_TIME_FORMAT_ERROR)
                return action_result.set_status(phantom.APP_ERROR, consts.CISCOESA_DATE_TIME_FORMAT_ERROR)

        # At this point, we should be guaranteed that neither of these are None
        start_time = cast(str, start_time)
        end_time = cast(str, end_time)

        # Validating start_time
        validate_status, parsed_start_time = self._validate_date_time(start_time, action_result)
        if phantom.is_fail(validate_status) or parsed_start_time is None:
            return action_result.get_status()

        # Validating end_time
        validate_status, parsed_end_time = self._validate_date_time(end_time, action_result)
        if phantom.is_fail(validate_status) or parsed_end_time is None:
            return action_result.get_status()

        # Comparing start time and end time
        if parsed_start_time >= parsed_end_time:
            self.error_print(consts.CISCOESA_START_TIME_GREATER_THEN_END_TIME)
            return action_result.set_status(phantom.APP_ERROR, consts.CISCOESA_START_TIME_GREATER_THEN_END_TIME)

        # if starts_with parameter is not set, then IP and email must be validated
        # Search value should be validated to be either an IP address or an email, if report title is
        # "Incoming Mail: IP Addresses", "Outgoing Senders: IP Addresses" or "Internal Users"
        if not starts_with and (filter_by and filter_value):
            if (
                report_title
                in [
                    consts.CISCOESA_MAIL_INCOMING_IP_HOSTNAME_DETAILS_REPORT_TITLE,
                    consts.CISCOESA_MAIL_OUTGOING_SENDERS_IP_HOSTNAME_DETAILS_REPORT_TITLE,
                ]
                and not _is_ip(filter_value)
            ) or (report_title == consts.CISCOESA_MAIL_USER_DETAILS_REPORT_TITLE and not phantom.is_email(filter_value)):
                self.error_print(consts.CISCOESA_SEARCH_VALUE_VALIDATION_FAIL)
                return action_result.set_status(phantom.APP_ERROR, consts.CISCOESA_SEARCH_VALUE_VALIDATION_FAIL)

        # Report will be queried for last given duration period
        # Time zone that will be considered for calculating time and date will be GMT having 00:00 offset from UTC
        # Time to query the report supports only 00 minutes
        try:
            start_time = parsed_start_time.strftime(consts.CISCOESA_API_TIME_FORMAT)
            end_time = parsed_end_time.strftime(consts.CISCOESA_API_TIME_FORMAT)
        except Exception as error:
            return action_result.set_status(phantom.APP_ERROR, self._get_error_message_from_exception(error))

        api_params[consts.CISCOESA_GET_REPORT_PARAM_START_DATE] = start_time
        api_params[consts.CISCOESA_GET_REPORT_PARAM_END_DATE] = end_time

        # Obtain report name
        report_name = REPORT_TITLE_TO_NAME_AND_FILTER_MAPPING[report_title]

        if filter_by:
            api_params[consts.CISCOESA_GET_REPORT_JSON_FILTER_BY_KEY] = filter_by
        if filter_value:
            api_params[consts.CISCOESA_GET_REPORT_JSON_FILTER_VALUE_KEY] = filter_value

        if filter_by and filter_value:
            if starts_with:
                api_params[consts.CISCOESA_GET_REPORT_JSON_FILTER_OPERATOR] = "begins_with"
            else:
                api_params[consts.CISCOESA_GET_REPORT_JSON_FILTER_OPERATOR] = "is"

        if order_by:
            api_params[consts.CISCOESA_GET_REPORT_JSON_ORDER_BY_KEY] = order_by
        if order_dir:
            if order_dir not in consts.CISCOESA_ORDER_DIR:
                return action_result.set_status(phantom.APP_ERROR, consts.CISCOESA_ORDER_DIR_ERROR)
            api_params[consts.CISCOESA_GET_REPORT_JSON_ORDER_DIR_KEY] = order_dir

        report_endpoint = consts.CISCOESA_GET_REPORT_ENDPOINT.format(report_name=report_name)
        self.send_progress(consts.CISCOESA_GET_REPORT_INTERMEDIATE_MESSAGE.format(report_title=report_title))

        # Making REST call to get report data
        response_status, report_data = self._make_rest_call(report_endpoint, action_result, params=api_params)

        # Something went wrong while querying a report
        if phantom.is_fail(response_status):
            self.error_print(consts.CISCOESA_GET_REPORT_ERROR.format(report_title=report_title))
            return action_result.get_status()
        action_result.add_data(report_data)

        return action_result.set_status(phantom.APP_SUCCESS, consts.CISCOESA_REPORTS_QUERIED_SUCCESS_MESSAGE)

    def _test_asset_connectivity(self, param: dict[str, Any]) -> bool:
        """This function tests the connectivity of an asset with given credentials.

        :param param: (not used in this method)
        :return: status success/failure
        """

        action_result = ActionResult()

        self.save_progress(consts.CISCOESA_CONNECTIVITY_TEST_MESSAGE)
        self.save_progress("Configured URL: {url}".format(url=self._url))

        ret_value, _ = self._make_rest_call(endpoint=consts.CISCOESA_TEST_CONNECTIVITY_ENDPOINT, action_result=action_result)

        if phantom.is_fail(ret_value):
            self.save_progress(action_result.get_message())
            self.set_status(phantom.APP_ERROR, consts.CISCOESA_TEST_CONNECTIVITY_FAIL)
            return action_result.get_status()

        self.set_status_save_progress(phantom.APP_SUCCESS, consts.CISCOESA_TEST_CONNECTIVITY_SUCCESS)

        return action_result.get_status()

    def _handle_list_dictionary_items(self, param: dict[str, Any]) -> bool:
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        dictionary_name = param[consts.CISCOESA_DICTIONARY_JSON_NAME]

        req_params = {"device_type": "esa"}
        if self._cluster:
            req_params["mode"] = "cluster"

        dictionary_endpoint = f"{consts.CISCOESA_DICTIONARY_ENDPOINT}/{dictionary_name}"

        # make rest call
        ret_val, response = self._make_rest_call(dictionary_endpoint, action_result, params=req_params)
        response = cast(dict[str, Any], response)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Add the response into the data section
        summary = action_result.update_summary({})
        if "data" in response:
            action_result.add_data(response["data"])
            if response["data"].get("words_count", False):
                summary["encoding"] = response["data"]["encoding"]
                summary["ignorecase"] = response["data"]["ignorecase"]
                summary["wholewords"] = response["data"]["wholewords"]
                summary["term_count"] = response["data"]["words_count"]["term_count"]
                summary["smart_identifier_count"] = response["data"]["words_count"]["smart_identifier_count"]
        else:
            action_result.add_data(response)
            summary["message"] = f"No 'data' section detected in response. Details {response}."

        self.save_progress(f"Action handler for: {self.get_action_identifier()} succeeded")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_add_dictionary_items(self, param: dict[str, Any]) -> bool:
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        dictionary_name = param[consts.CISCOESA_DICTIONARY_JSON_NAME]
        words = param[consts.CISCOESA_DICTIONARY_JSON_WORDS]

        ret_val, validated_words = self._parse_and_validate_words(action_result, words)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        dictionary_endpoint = f"{consts.CISCOESA_DICTIONARY_ENDPOINT}/{dictionary_name}/words"

        req_params = {"device_type": "esa"}
        if self._cluster:
            req_params["mode"] = "cluster"

        payload = {"data": {"words": validated_words}}

        # make rest call
        ret_val, response = self._make_rest_call(dictionary_endpoint, action_result, params=req_params, method="post", json=payload)
        response = cast(dict[str, Any], response)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        summary = action_result.update_summary({})
        if "data" in response:
            action_result.add_data(response["data"])
            if response["data"].get("message", False):
                summary["message"] = response["data"]["message"]
        else:
            action_result.add_data(response)
            summary["message"] = f"No 'data' section detected in response. Details {response}."

        self.save_progress(f"Action handler for: {self.get_action_identifier()} succeeded")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_remove_dictionary_items(self, param: dict[str, Any]) -> bool:
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        dictionary_name = param[consts.CISCOESA_DICTIONARY_JSON_NAME]
        words = param[consts.CISCOESA_DICTIONARY_JSON_WORDS]

        validated_words = [x.lstrip(" \"'").rstrip(" \"'") for x in words.split(",")]

        dictionary_endpoint = f"{consts.CISCOESA_DICTIONARY_ENDPOINT}/{dictionary_name}/words"

        # device_type=esa
        req_params = {"device_type": "esa"}
        if self._cluster:
            req_params["mode"] = "cluster"

        payload = {"data": {"words": validated_words}}

        # make rest call
        ret_val, response = self._make_rest_call(dictionary_endpoint, action_result, params=req_params, method="delete", json=payload)
        response = cast(dict[str, Any], response)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        summary = action_result.update_summary({})
        if "data" in response:
            action_result.add_data(response["data"])
            if response["data"].get("message", False):
                summary["message"] = response["data"]["message"]
        else:
            action_result.add_data(response)
            summary["message"] = f"No 'data' section detected in response. Details {response}."

        self.save_progress(f"Action handler for: {self.get_action_identifier()} succeeded")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_dictionaries(self, param: dict[str, Any]) -> bool:
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        dictionary_endpoint = consts.CISCOESA_DICTIONARY_ENDPOINT

        # device_type=esa
        req_params = {"device_type": "esa"}
        if self._cluster:
            req_params["mode"] = "cluster"

        # make rest call
        ret_val, response = self._make_rest_call(dictionary_endpoint, action_result, params=req_params)
        response = cast(dict[str, Any], response)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        summary = action_result.update_summary({})
        if "data" in response:
            action_result.update_data(response["data"])
            summary["message"] = f"Succesfully retrieved {len(response['data'])} dictionaries"
            summary["dictionaries"] = len(response["data"])
        else:
            action_result.add_data(response)
            summary["message"] = f"No 'data' section detected in response. Details {response}."

        self.save_progress(f"Action handler for: {self.get_action_identifier()} succeeded")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _parse_and_validate_words(self, action_result: ActionResult, input_str: str) -> tuple[bool, Optional[list[list[str]]]]:
        # Extended regex pattern to capture word, weight, and optional prefix
        pattern = re.compile(r"(\*?[^\|]+)(?:\|([\d.]+))?(?:\|(prefix))?")
        pairs = input_str.split(",")

        result = []
        for pair in pairs:
            match = pattern.fullmatch(pair.strip())
            if not match:
                return action_result.set_status(phantom.APP_ERROR, consts.CISCOESA_INVALID_WORDS_MESSAGE.format(pair)), None

            word = match.group(1)
            weight = match.group(2)
            prefix = match.group(3)

            # Validate and process weight if provided
            if weight is None:
                weight_value = 1
            else:
                try:
                    weight_value = int(weight)
                    if not (0 <= weight_value <= 10):
                        return action_result.set_status(phantom.APP_ERROR, consts.CISCOESA_INVALID_WORDS_WEIGHT_MESSAGE.format(pair)), None
                except ValueError:
                    return action_result.set_status(phantom.APP_ERROR, consts.CISCOESA_INVALID_WORDS_WEIGHT_MESSAGE.format(pair)), None

            # Validate the presence of "prefix" only with words starting with '*'
            if prefix and not word.startswith("*"):
                return action_result.set_status(phantom.APP_ERROR, consts.CISCOESA_INVALID_PREFIX_MESSAGE.format(pair)), None

            # Construct the output based on the captured values
            if prefix:
                result.append([word, weight_value, prefix])
            else:
                result.append([word, weight_value] if weight else [word])

        return phantom.APP_SUCCESS, result

    def _handle_add_dictionary(self, param: dict[str, Any]) -> bool:
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        dictionary_name = param["dictionary_name"]
        ignorecase = 1 if param["ignorecase"] else 0
        wholewords = 1 if param["wholewords"] else 0
        words = param["words"]
        ret_val, validated_words = self._parse_and_validate_words(action_result, words)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        dictionary_endpoint = f"{consts.CISCOESA_DICTIONARY_ENDPOINT}/{dictionary_name}"

        # device_type=esa
        req_params = {"device_type": "esa"}
        if self._cluster:
            req_params["mode"] = "cluster"

        payload = {"data": {"ignorecase": ignorecase, "wholewords": wholewords, "words": validated_words, "encoding": "utf-8"}}

        # make rest call
        ret_val, response = self._make_rest_call(dictionary_endpoint, action_result, params=req_params, method="post", json=payload)
        response = cast(dict[str, Any], response)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Add the response into the data section
        summary = action_result.update_summary({})
        if "data" in response:
            action_result.add_data(response["data"])
            if response["data"].get("message", False):
                summary["message"] = response["data"]["message"]
        else:
            action_result.add_data(response)
            summary["message"] = f"No 'data' section detected in response. Details {response}."

        self.save_progress(f"Action handler for: {self.get_action_identifier()} succeeded")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_remove_dictionary(self, param: dict[str, Any]) -> bool:
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        dictionary_name = param["dictionary_name"]

        dictionary_endpoint = f"{consts.CISCOESA_DICTIONARY_ENDPOINT}/{dictionary_name}"

        req_params = {"device_type": "esa"}
        if self._cluster:
            req_params["mode"] = "cluster"

        # make rest call
        ret_val, response = self._make_rest_call(dictionary_endpoint, action_result, params=req_params, method="delete")
        response = cast(dict[str, Any], response)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response["data"])
        summary = action_result.update_summary({})
        if "data" in response:
            if response["data"].get("message", False):
                summary["message"] = response["data"]["message"]
        else:
            action_result.add_data(response)
            summary["message"] = f"No 'data' section detected in response. Details {response}."

        self.save_progress(f"Action handler for: {self.get_action_identifier()} succeeded")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_policy_items(self, action_result: ActionResult, param: dict[str, Any]) -> tuple[bool, Optional[dict[str, Any]]]:
        policy = param[consts.CISCOESA_POLICY_JSON_POLICY_NAME]
        policy_endpoint = consts.CISCOESA_POLICY_ENDPOINT.format(policy=policy)

        req_params = {"device_type": "esa"}
        if self._cluster:
            req_params["mode"] = "cluster"

        ret_val, response = self._make_rest_call(policy_endpoint, action_result, params=req_params)
        response = cast(dict[str, Any], response)

        if phantom.is_fail(ret_val):
            return action_result.get_status(), None

        return ret_val, response

    def _handle_list_policy_items(self, param: dict[str, Any]) -> bool:
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, response = self._get_policy_items(action_result, param)

        if phantom.is_fail(ret_val) or response is None:
            return action_result.get_status()

        summary = action_result.update_summary({})
        if "data" in response:
            action_result.update_data(response["data"])
            summary["entries"] = len(response["data"])
            summary["message"] = f"Successfully retrieved {len(response['data'])} entries."
        else:
            action_result.add_data(response)
            summary["message"] = f"No 'data' section detected in response. Details {response}."

        self.save_progress(f"Action handler for: {self.get_action_identifier()} succeeded")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _validate_domain_entries(self, action_result: ActionResult, parameter: str, domain_entries: str) -> tuple[bool, Optional[list[str]]]:
        valid_domain_pattern = re.compile(r"^[^@]*\@((?:\.*?[\w]+\.)+[\w]+)*$")
        valid_ip_pattern = re.compile(r"^[^@]*\@\[ipv6:[0-9a-fA-F:]+\]$|^[^@]*\@\[\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\]$")

        domain_entry_list = domain_entries.split(",")

        valid_entries = []
        invalid_entries = []

        for entry in domain_entry_list:
            entry = entry.strip()
            if entry == "ANY":
                if len(domain_entry_list) > 1:
                    invalid_entries.append(entry)
                    continue
                valid_entries.append(entry)
            elif valid_domain_pattern.match(entry) or valid_ip_pattern.match(entry):
                valid_entries.append(entry)
            else:
                invalid_entries.append(entry)

        if invalid_entries:
            return action_result.set_status(phantom.APP_ERROR, consts.CISCOESA_INVALID_DOMAIN_ENTRIES.format(parameter, invalid_entries)), None

        return phantom.APP_SUCCESS, valid_entries

    def _validate_policy_params(
        self,
        action_result: ActionResult,
        sender_config: str,
        sender: str,
        sender_not: str,
        receiver: str,
        receiver_not: str,
        operation: str,
        raw_json: str,
    ) -> bool:
        errors: list[str] = []

        if raw_json:
            if any([sender, sender_not, receiver, receiver_not]):
                errors.append(consts.CISCOESA_INVALID_POLICY_JSON_RAW)
        else:
            if sender_config == "sender":
                if not sender:
                    errors.append(consts.CISCOESA_INVALID_POLICY_REQUIRES.format("sender"))
                if sender_not:
                    errors.append(consts.CISCOESA_INVALID_POLICY_NOT_REQUIRES.format("sender", "sender_not"))
            elif sender_config == "sender_not":
                if not sender_not:
                    errors.append(consts.CISCOESA_INVALID_POLICY_REQUIRES.format("sender_not"))
                if sender:
                    errors.append(consts.CISCOESA_INVALID_POLICY_NOT_REQUIRES.format("sendernot", "sender"))
            else:
                errors.append(consts.CISCOESA_INVALID_POLICY_UNKNOWN.format(sender_config))

            # Check operation for receiver_not rule
            if operation == "or" and receiver_not:
                errors.append(consts.CISCOESA_INVALID_POLICY_RECEIVER_NOT)

        if errors:
            return action_result.set_status(phantom.APP_ERROR, consts.CISCOESA_INVALID_DOMAIN_ENTRIES_PARAMS.format(",".join(errors)))
        else:
            return phantom.APP_SUCCESS

    def _build_esa_policy_from_param(self, action_result: ActionResult, param: dict[str, Any]) -> tuple[bool, Optional[dict[str, Any]]]:
        # Optional values should use the .get() function
        sender_config = param.get(consts.CISCOESA_POLICY_JSON_SENDER_CONFIG, False)
        sender = param.get(consts.CISCOESA_POLICY_JSON_SENDER, False)
        sender_not = param.get(consts.CISCOESA_POLICY_JSON_SENDER_NOT, False)
        receiver = param.get(consts.CISCOESA_POLICY_JSON_RECEIVER, False)
        receiver_not = param.get(consts.CISCOESA_POLICY_JSON_RECEIVER_NOT, False)
        operation = param.get(consts.CISCOESA_POLICY_JSON_OPERATION, "and")
        raw_json = param.get(consts.CISCOESA_POLICY_JSON_RAW_JSON, False)

        ret_val = self._validate_policy_params(action_result, sender_config, sender, sender_not, receiver, receiver_not, operation, raw_json)

        if phantom.is_fail(ret_val):
            return action_result.get_status(), None

        if raw_json:
            try:
                payload = json.loads(raw_json)
            except Exception as e:
                return action_result.set_status(phantom.APP_ERROR, consts.CISCOESA_INVALID_DOMAIN_JSON_RAW.format(e)), None
        else:
            ret_val, sender = self._validate_domain_entries(action_result, "sender", sender) if sender else (phantom.APP_SUCCESS, False)
            if phantom.is_fail(ret_val):
                return action_result.get_status(), None

            ret_val, sender_not = (
                self._validate_domain_entries(action_result, "sender_not", sender_not) if sender_not else (phantom.APP_SUCCESS, False)
            )
            if phantom.is_fail(ret_val):
                return action_result.get_status(), None

            ret_val, receiver = self._validate_domain_entries(action_result, "receiver", receiver) if receiver else (phantom.APP_SUCCESS, False)
            if phantom.is_fail(ret_val):
                return action_result.get_status(), None

            ret_val, receiver_not = (
                self._validate_domain_entries(action_result, "receiver_not", receiver_not) if receiver_not else (phantom.APP_SUCCESS, False)
            )
            if phantom.is_fail(ret_val):
                return action_result.get_status(), None

            sender_config_values = sender if sender else sender_not

            payload = {
                "data": {"sender_config": {sender_config: {"domain_entries": sender_config_values}}, "receiver_config": {"operation": operation}}
            }
            if receiver:
                payload["data"]["receiver_config"]["receiver"] = {}
                payload["data"]["receiver_config"]["receiver"]["domain_entries"] = receiver

            if receiver_not:
                payload["data"]["receiver_config"]["receiver_not"] = {}
                payload["data"]["receiver_config"]["receiver_not"]["domain_entries"] = receiver_not

        return phantom.APP_SUCCESS, payload

    def _validate_esa_policy(self, action_result: ActionResult, policy: dict[str, Any]) -> bool:
        validation_errors = []
        if "sender_config" not in policy:
            validation_errors.append("Missing 'sender_config' key.")
        sender_config = policy.get("sender_config", {})
        sender = sender_config.get("sender")
        sender_not = sender_config.get("sender_not")

        if sender is None and sender_not is None:
            validation_errors.append("Either 'sender' or 'sender_not' must be configured in 'sender_config'.")

        if sender is not None:
            domain_entries = sender.get("domain_entries")
            if domain_entries is None:
                validation_errors.append("'domain_entries' is required in 'sender' if it is configured.")
            if not isinstance(domain_entries, list) or not domain_entries:
                validation_errors.append("'sender' must contain a non-empty 'domain_entries' list.")

        if sender_not is not None:
            domain_entries = sender.get("domain_entries")
            if domain_entries is None:
                validation_errors.append("'domain_entries' is required in 'sender' if it is configured.")
            if not isinstance(domain_entries, list) or not domain_entries:
                validation_errors.append("'sender_not' must contain a non-empty 'domain_entries' list if 'sender' is configured.")

        if "receiver_config" not in policy:
            validation_errors.append("Missing 'receiver_config' key.")

        receiver_config = policy.get("receiver_config", {})
        if "receiver" not in receiver_config:
            validation_errors.append("Missing 'receiver' key in 'receiver_config'.")
        else:
            receiver = receiver_config.get("receiver")
            domain_entries = receiver.get("domain_entries")
            if domain_entries is None:
                validation_errors.append("'domain_entries' is required in 'receiver'.")
            if not isinstance(domain_entries, list) or not domain_entries:
                validation_errors.append("'receiver' must contain a non-empty 'domain_entries' list.")

        if "operation" not in receiver_config:
            validation_errors.append("Missing 'operation' key in 'receiver_config'.")

        receiver_not = receiver_config.get("receiver_not", None)
        if receiver_not is not None:
            domain_entries = receiver_not.get("domain_entries")
            if domain_entries is None:
                validation_errors.append("'domain_entries' is required in 'receiver_not' if it is configured.")
            if not isinstance(domain_entries, list) or not domain_entries:
                validation_errors.append("'receiver_not' must contain a non-empty 'domain_entries' list.")

        if len(validation_errors) > 0:
            action_result.set_status(
                phantom.APP_ERROR, consts.CISCOESA_IVALID_POLICY_FORMAT.format(json.dumps(policy), ",".join(validation_errors))
            )
            return action_result.get_status()
        else:
            return phantom.APP_SUCCESS

    def _add_update_policy_items(
        self, action_result: ActionResult, param: dict[str, Any], action: str = "add", raw_json: Optional[dict[str, Any]] = None
    ) -> tuple[bool, Optional[dict[str, Any]]]:

        ret_val, payload = self._build_esa_policy_from_param(action_result, param)
        payload = cast(dict[str, Any], payload)
        if phantom.is_fail(ret_val):
            return action_result.get_status(), None

        policy = param[consts.CISCOESA_POLICY_JSON_POLICY_NAME]

        # update takes a list
        if action == "update":
            if raw_json:
                payload = raw_json
            elif not param.get(consts.CISCOESA_POLICY_JSON_RAW_JSON, False):
                payload["data"] = [payload["data"]]

        policy_endpoint = consts.CISCOESA_POLICY_ENDPOINT.format(policy=policy)

        # device_type=esa
        req_params = {"device_type": "esa"}
        if self._cluster:
            req_params["mode"] = "cluster"

        method = "post" if action == "add" else "put"

        # make rest call
        ret_val, response = self._make_rest_call(policy_endpoint, action_result, params=req_params, method=method, json=payload)

        if phantom.is_fail(ret_val):
            return action_result.get_status(), None

        return phantom.APP_SUCCESS, response

    def _handle_add_policy_items(self, param: dict[str, Any]) -> bool:
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        # make rest call
        ret_val, response = self._add_update_policy_items(action_result, param, action="add")
        response = cast(dict[str, Any], response)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response["data"])
        summary = action_result.update_summary({})
        if "data" in response:
            if response["data"].get("message", False):
                summary["message"] = response["data"]["message"]
        else:
            action_result.add_data(response)
            summary["message"] = f"No 'data' section detected in response. Details {response}."

        self.save_progress(f"Action handler for: {self.get_action_identifier()} succeeded")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_update_policy_items(self, param: dict[str, Any]) -> bool:
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        # make rest call
        ret_val, response = self._add_update_policy_items(action_result, param, action="update")
        response = cast(dict[str, Any], response)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response["data"])
        summary = action_result.update_summary({})
        if "data" in response:
            if response["data"].get("message", False):
                summary["message"] = response["data"]["message"]
        else:
            action_result.add_data(response)
            summary["message"] = f"No 'data' section detected in response. Details {response}."

        self.save_progress(f"Action handler for: {self.get_action_identifier()} succeeded")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _is_subset_or_equal(self, entry_list: Iterable, match_list: Iterable) -> bool:
        return set(match_list).issubset(set(entry_list))

    def _is_matching_element(self, original: dict[str, Any], to_match: dict[str, Any]) -> bool:
        # Check sender_config match
        original_sender_domains = original["sender_config"]["sender"]["domain_entries"]
        to_match_sender_domains = to_match["sender_config"]["sender"]["domain_entries"]

        # All entries in to_match sender must be in original sender domains
        if not self._is_subset_or_equal(original_sender_domains, to_match_sender_domains):
            return False

        # Check receiver_not (must match all entries exactly or partially)
        original_receiver_not = original["receiver_config"].get("receiver_not", {}).get("domain_entries", [])
        to_match_receiver_not = to_match["receiver_config"].get("receiver_not", {}).get("domain_entries", [])

        if to_match_receiver_not:
            if not self._is_subset_or_equal(original_receiver_not, to_match_receiver_not):
                return False

        # Check receiver (needs at least one match and must be a subset)
        original_receiver = original["receiver_config"].get("receiver", {}).get("domain_entries", [])
        to_match_receiver = to_match["receiver_config"].get("receiver", {}).get("domain_entries", [])

        if to_match_receiver:
            if not self._is_subset_or_equal(original_receiver, to_match_receiver):
                return False

        # Check if other fields match exactly (e.g., operation)
        if original["receiver_config"]["operation"] != to_match["receiver_config"]["operation"]:
            return False

        return True

    def _remove_matching_element(
        self, action_result: ActionResult, data: list[dict[str, Any]], element_to_remove: dict[str, Any], policy: str
    ) -> tuple[bool, Optional[dict[str, Any]]]:

        updated_data = []
        element_found = False  # To track if we find any matching element

        for item in data:
            # Check if this item is a match
            if self._is_matching_element(item, element_to_remove):
                element_found = True  # Mark that we've found a match

                # Remove matching domain entries but keep others
                new_item = item.copy()

                # Remove matching sender domain entries
                original_sender_domains = item["sender_config"]["sender"]["domain_entries"]
                to_match_sender_domains = element_to_remove["sender_config"]["sender"]["domain_entries"]
                new_item["sender_config"]["sender"]["domain_entries"] = [
                    entry for entry in original_sender_domains if entry not in to_match_sender_domains
                ]
                if len(new_item["sender_config"]["sender"]["domain_entries"]) == 0:
                    del new_item["sender_config"]["sender"]

                # Remove matching receiver domain entries
                if element_to_remove["receiver_config"].get("receiver"):
                    original_receiver_domains = item["receiver_config"]["receiver"]["domain_entries"]
                    to_match_receiver_domains = element_to_remove["receiver_config"]["receiver"]["domain_entries"]
                    new_item["receiver_config"]["receiver"]["domain_entries"] = [
                        entry for entry in original_receiver_domains if entry not in to_match_receiver_domains
                    ]
                    if len(new_item["receiver_config"]["receiver"]["domain_entries"]) == 0:
                        del new_item["receiver_config"]["receiver"]

                if element_to_remove["receiver_config"].get("receiver_not"):
                    original_receiver_domains = item["receiver_config"]["receiver_not"]["domain_entries"]
                    to_match_receiver_domains = element_to_remove["receiver_config"]["receiver_not"]["domain_entries"]
                    new_item["receiver_config"]["receiver_not"]["domain_entries"] = [
                        entry for entry in original_receiver_domains if entry not in to_match_receiver_domains
                    ]

                    if len(new_item["receiver_config"]["receiver_not"]["domain_entries"]) == 0:
                        del new_item["receiver_config"]["receiver_not"]

                # If after removing, domain entries are empty, skip this element
                if not new_item["sender_config"].get("sender", False) and not new_item["receiver_config"].get("receiver", False):
                    # policy will be completely removed. Proceeding to next.
                    continue

                ret_val = self._validate_esa_policy(action_result, new_item)
                if phantom.is_fail(ret_val):
                    return action_result.get_status(), None

                updated_data.append(new_item)

            else:
                # If no match, add the original item to the updated data
                updated_data.append(item)

        # Return empty array if no element was found and modified
        if not element_found:
            return action_result.set_status(phantom.APP_ERROR, consts.CISCOESA_ERROR_ENTRY_NOTFOUND.format(policy)), None

        updated_policy = {"data": updated_data}
        return phantom.APP_SUCCESS, updated_policy

    def _handle_remove_policy_items(self, param: dict[str, Any]) -> bool:
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        policy = param[consts.CISCOESA_POLICY_JSON_POLICY_NAME]
        ret_val, to_remove = self._build_esa_policy_from_param(action_result, param)
        if phantom.is_fail(ret_val) or to_remove is None:
            return action_result.get_status()

        ret_val, response = self._get_policy_items(action_result, param)
        if phantom.is_fail(ret_val) or response is None:
            return action_result.get_status()

        if not response.get("data", False):
            return action_result.set_status(phantom.APP_ERROR, consts.CISCOESA_ERROR_NODATA_POLICY)

        ret_val, updated_policy = self._remove_matching_element(action_result, response["data"], to_remove["data"], policy)
        if phantom.is_fail(ret_val) or updated_policy is None:
            return action_result.get_status()

        if not updated_policy["data"]:
            return action_result.set_status(phantom.APP_ERROR, f"Cannot remove policy item: resulting {policy=} would be empty.")

        # make rest call
        ret_val, response = self._add_update_policy_items(action_result, param, action="update", raw_json=updated_policy)
        if phantom.is_fail(ret_val) or response is None:
            return action_result.get_status()

        action_result.add_data(response["data"])
        summary = action_result.update_summary({})
        if "data" in response:
            if response["data"].get("message", False):
                summary["message"] = response["data"]["message"]
        else:
            action_result.add_data(response)
            summary["message"] = f"No 'data' section detected in response. Details {response}."

        self.save_progress(f"Action handler for: {self.get_action_identifier()} succeeded")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _validate_and_format_dates(
        self, action_result: ActionResult, start_date: str, end_date: str
    ) -> tuple[bool, Optional[str], Optional[str]]:
        format = "%Y-%m-%dT00:00:00.000Z"
        try:
            parsed_start_date = parser.parse(start_date)
            parsed_end_date = parser.parse(end_date)
            # Format the parsed date into the required format with 'T00:00:00.000Z'
            return phantom.APP_SUCCESS, parsed_start_date.strftime(format), parsed_end_date.strftime(format)
        except (ValueError, parser.ParserError):
            # Handle errors if the date format is unrecognized
            return action_result.set_status(phantom.APP_ERROR, f"Parsing date failed. Details {start_date=}, {end_date=}"), None, None

    def _handle_search_pov_quarantine(self, param: dict[str, Any]) -> bool:
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        # Required values can be accessed directly
        start_date = param[consts.CISCOESA_QUARANTINE_JSON_START_DATE]
        end_date = param[consts.CISCOESA_QUARANTINE_JSON_END_DATE]
        offset = param[consts.CISCOESA_QUARANTINE_JSON_OFFSET]
        limit = param[consts.CISCOESA_QUARANTINE_JSON_LIMIT]
        quarantines = param[consts.CISCOESA_POV_QUARANTINE_JSON_QUARANTINES]

        ret_val, start_date, end_date = self._validate_and_format_dates(action_result, start_date, end_date)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        subject_filter_by = param.get(consts.CISCOESA_POV_QUARANTINE_JSON_SUBJECT_FILTER_BY, False)
        subject_filter_value = param.get(consts.CISCOESA_POV_QUARANTINE_JSON_SUBJECT_FILTER_VALUE, False)
        originating_esa_ip = param.get(consts.CISCOESA_POV_QUARANTINE_JSON_ORIGINATING_ESA_IP, False)
        attachment_name = param.get(consts.CISCOESA_POV_QUARANTINE_JSON_ATTACHMENT_NAME, False)
        attachment_size_filter_by = param.get(consts.CISCOESA_POV_QUARANTINE_JSON_ATTACHMENT_SIZE_FILTER_BY, False)
        attachment_size_from_value = param.get(consts.CISCOESA_POV_QUARANTINE_JSON_ATTACHMENT_SIZE_FROM_VALUE, False)
        attachment_size_to_value = param.get(consts.CISCOESA_POV_QUARANTINE_JSON_ATTACHMENT_SIZE_TO_VALUE, False)
        order_by = param.get(consts.CISCOESA_QUARANTINE_JSON_ORDER_BY, False)
        order_dir = param.get(consts.CISCOESA_QUARANTINE_JSON_ORDER_DIR, False)
        envelope_recipient_filter_by = param.get(consts.CISCOESA_POV_QUARANTINE_JSON_ENVELOPE_RECIPIENT_FILTER_BY, False)
        envelope_recipient_filter_value = param.get(consts.CISCOESA_QUARANTINE_JSON_ENVELOPE_RECIPIENT_FILTER_VALUE, False)
        envelope_sender_filter_by = param.get(consts.CISCOESA_POV_QUARANTINE_JSON_ENVELOPE_SENDER_FILTER_BY, False)
        envelope_sender_filter_value = param.get(consts.CISCOESA_POV_QUARANTINE_JSON_ENVELOPE_SENDER_FILTER_VALUE, False)

        params = {
            "startDate": start_date,
            "endDate": end_date,
            "quarantines": quarantines,
            "subjectFilterBy": subject_filter_by,
            "subjectFilterValue": subject_filter_value,
            "originatingEsaIp": originating_esa_ip,
            "attachmentName": attachment_name,
            "attachmentSizeFilterBy": attachment_size_filter_by,
            "attachmentSizeFromValue": attachment_size_from_value,
            "attachmentSizeToValue": attachment_size_to_value,
            "quarantineType": "pvo",
            "orderBy": order_by,
            "orderDir": order_dir,
            "offset": offset,
            "limit": limit,
            "envelopeRecipientFilterBy": envelope_recipient_filter_by,
            "envelopeRecipientFilterValue": envelope_recipient_filter_value,
            "envelopeSenderFilterBy": envelope_sender_filter_by,
            "envelopeSenderFilterValue": envelope_sender_filter_value,
        }

        req_params = {k: v for k, v in params.items() if v}

        pov_quarantine_endpoint = (
            consts.CISCOESA_QUARANTINE_ENDPOINT.format(esa_sma="esa")
            if self._esa_is_sma
            else consts.CISCOESA_QUARANTINE_ENDPOINT.format(esa_sma="sma")
        )

        # make rest call
        ret_val, response = self._make_rest_call(pov_quarantine_endpoint, action_result, params=req_params, method="get", use_sma=True)

        if phantom.is_fail(ret_val) or response is None:
            return action_result.get_status()

        if response.get("meta", False):
            summary = action_result.update_summary({})
            summary["message"] = f"Found {response['meta']['totalCount']} messages for qurantines {quarantines}."
        if "data" in response:
            action_result.update_data(response["data"])
        else:
            action_result.add_data(response)
            summary["message"] = f"No 'data' section detected in response. Details {response}."

        self.save_progress(f"Action handler for: {self.get_action_identifier()} succeeded")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _release_quarantine(
        self, action_result: ActionResult, param: dict[str, Any], quaranrantine_type: str = "spam"
    ) -> tuple[bool, Optional[dict[str, Any]]]:
        mids = param[consts.CISCOESA_POV_QUARANTINE_JSON_MIDS]

        mids = [int(x.strip(" ")) for x in mids.split(",")]

        quarantine_endpoint = (
            consts.CISCOESA_QUARANTINE_ENDPOINT.format(esa_sma="esa")
            if self._esa_is_sma
            else consts.CISCOESA_QUARANTINE_ENDPOINT.format(esa_sma="sma")
        )

        payload = {"action": "release", "mids": mids, "quarantineType": quaranrantine_type}

        if quaranrantine_type == "pvo":
            quarantine_name = param[consts.CISCOESA_POV_QUARANTINE_JSON_QUARANTINE_NAME]
            payload["quarantineName"] = quarantine_name

        # make rest call
        ret_val, response = self._make_rest_call(quarantine_endpoint, action_result, method="post", use_sma=True, json=payload)

        if phantom.is_fail(ret_val) or response is None:
            return action_result.get_status(), None

        return phantom.APP_SUCCESS, response

    def _handle_release_pov_quarantine(self, param: dict[str, Any]) -> bool:
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, response = self._release_quarantine(action_result, param, "pvo")

        if phantom.is_fail(ret_val) or response is None:
            return action_result.get_status()

        summary = action_result.update_summary({})
        if "data" in response:
            action_result.add_data(response["data"])
            summary["message"] = f"Successfully released {response['data']['totalCount']} messages"
        else:
            action_result.add_data(response)
            summary["message"] = f"No 'data' section detected in response. Details {response}."

        self.save_progress(f"Action handler for: {self.get_action_identifier()} succeeded")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_search_spam_quarantine(self, param: dict[str, Any]) -> bool:
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        start_date = param[consts.CISCOESA_QUARANTINE_JSON_START_DATE]
        end_date = param[consts.CISCOESA_QUARANTINE_JSON_END_DATE]

        offset = param.get(consts.CISCOESA_QUARANTINE_JSON_OFFSET, False)
        limit = param.get(consts.CISCOESA_QUARANTINE_JSON_LIMIT, False)
        order_by = param.get(consts.CISCOESA_QUARANTINE_JSON_ORDER_BY, False)
        order_dir = param.get(consts.CISCOESA_QUARANTINE_JSON_ORDER_DIR, False)
        envelope_recipient_filter_operator = param.get(consts.CISCOESA_SPAM_QUARANTINE_JSON_ENVELOPE_RECIPIENT_FILTER_OPERATOR, False)
        envelope_recipient_filter_value = param.get(consts.CISCOESA_QUARANTINE_JSON_ENVELOPE_RECIPIENT_FILTER_VALUE, False)
        filter_operator = param.get(consts.CISCOESA_SPAM_QUARANTINE_JSON_FILTER_OPERATOR, False)
        filter_value = param.get(consts.CISCOESA_SPAM_QUARANTINE_JSON_FILTER_VALUE, False)

        params = {
            "startDate": start_date,
            "endDate": end_date,
            "quarantineType": "spam",
            "orderBy": order_by,
            "orderDir": order_dir,
            "offset": offset,
            "limit": limit,
            "envelopeRecipientFilterOperator": envelope_recipient_filter_operator,
            "envelopeRecipientFilterValue": envelope_recipient_filter_value,
            "filterOperator": filter_operator,
            "filterValue": filter_value,
        }

        req_params = {k: v for k, v in params.items() if v}

        quarantine_endpoint = (
            consts.CISCOESA_QUARANTINE_ENDPOINT.format(esa_sma="esa")
            if self._esa_is_sma
            else consts.CISCOESA_QUARANTINE_ENDPOINT.format(esa_sma="sma")
        )

        # make rest call
        ret_val, response = self._make_rest_call(quarantine_endpoint, action_result, params=req_params, method="get", use_sma=True)

        if phantom.is_fail(ret_val) or response is None:
            return action_result.get_status()

        if response.get("meta", False):
            summary = action_result.update_summary({})
            summary["message"] = f"Found {response['meta']['totalCount']} messages for SPAM quarantine."
        if "data" in response:
            action_result.update_data(response["data"])
        else:
            action_result.add_data(response)
            summary["message"] = f"No 'data' section detected in response. Details {response}."

        self.save_progress(f"Action handler for: {self.get_action_identifier()} succeeded")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_release_spam_quarantine(self, param: dict[str, Any]) -> bool:
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, response = self._release_quarantine(action_result, param, "spam")

        if phantom.is_fail(ret_val) or response is None:
            return action_result.get_status()

        summary = action_result.update_summary({})
        if "data" in response:
            action_result.add_data(response["data"])
            summary["message"] = f"Successfully released {response['data']['totalCount']} messages"
        else:
            action_result.add_data(response)
            summary["message"] = f"No 'data' section detected in response. Details {response}."

        self.save_progress(f"Action handler for: {self.get_action_identifier()} succeeded")
        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param: dict[str, Any]) -> bool:
        """This function gets current action identifier and calls member function of its own to handle the action.

        :param param: dictionary which contains information about the actions to be executed
        :return: status success/failure
        """

        # Dictionary mapping each action with its corresponding actions
        action_mapping = {
            "test_asset_connectivity": self._test_asset_connectivity,
            "get_report": self._get_report,
            "decode_url": self._decode_url,
            "list_dictionary_items": self._handle_list_dictionary_items,
            "add_dictionary_items": self._handle_add_dictionary_items,
            "remove_dictionary_items": self._handle_remove_dictionary_items,
            "list_dictionaries": self._handle_list_dictionaries,
            "add_dictionary": self._handle_add_dictionary,
            "remove_dictionary": self._handle_remove_dictionary,
            "list_policy_items": self._handle_list_policy_items,
            "add_policy_items": self._handle_add_policy_items,
            "update_policy_items": self._handle_update_policy_items,
            "remove_policy_items": self._handle_remove_policy_items,
            "search_pov_quarantine": self._handle_search_pov_quarantine,
            "release_pov_quarantine": self._handle_release_pov_quarantine,
            "release_spam_quarantine": self._handle_release_spam_quarantine,
            "search_spam_quarantine": self._handle_search_spam_quarantine,
        }

        action = self.get_action_identifier()

        try:
            run_action = action_mapping[action]
        except Exception:
            raise ValueError("action {action} is not supported".format(action=action))

        return run_action(param)

    def finalize(self) -> bool:
        """This function gets called once all the param dictionary elements are looped over and no more handle_action
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
