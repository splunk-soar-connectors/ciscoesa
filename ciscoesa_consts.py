# File: ciscoesa_consts.py
#
# Copyright (c) 2017-2021 Splunk Inc.
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
CISCOESA_CONFIG_URL = "url"
CISCOESA_CONFIG_USERNAME = "username"
CISCOESA_CONFIG_PASSWORD = "password"
CISCOESA_CONFIG_VERIFY_SSL = "verify_server_cert"
CISCOESA_REST_RESP_SUCCESS = 200
CISCOESA_REST_RESP_BAD_REQUEST = 400
CISCOESA_REST_RESP_BAD_REQUEST_MSG = "Bad request"
CISCOESA_REST_RESP_UNAUTHORIZED = 401
CISCOESA_REST_RESP_UNAUTHORIZED_MSG = "Invalid username or password"
CISCOESA_REST_RESP_FORBIDDEN = 403
CISCOESA_REST_RESP_FORBIDDEN_MSG = "Forbidden"
CISCOESA_REST_RESP_NOT_FOUND = 404
CISCOESA_REST_RESP_NOT_FOUND_MSG = "Not found"
CISCOESA_REST_RESP_INTERNAL_SERVER_ERROR = 500
CISCOESA_REST_RESP_INTERNAL_SERVER_ERROR_MSG = "Internal server error"
CISCOESA_REST_RESP_NOT_ACCEPTABLE = 406
CISCOESA_REST_RESP_NOT_ACCEPTABLE_MSG = "Not acceptable"
CISCOESA_REST_RESP_ENTITY_TOO_LARGE = 413
CISCOESA_REST_RESP_ENTITY_TOO_LARGE_MSG = "Payload too large"
CISCOESA_REST_RESP_URI_TOO_LONG = 414
CISCOESA_REST_RESP_URI_TOO_LONG_MSG = "URI too long"
CISCOESA_REST_RESP_NOT_IMPLEMENTED = 501
CISCOESA_REST_RESP_NOT_IMPLEMENTED_MSG = "Not implemented"
CISCOESA_REST_RESP_BAD_GATEWAY = 502
CISCOESA_REST_RESP_BAD_GATEWAY_MSG = "Bad gateway"
CISCOESA_ERR_API_UNSUPPORTED_METHOD = "Unsupported method {method}"
CISCOESA_EXCEPTION_OCCURRED = "Exception occurred"
CISCOESA_ERR_SERVER_CONNECTION = "Connection failed"
CISCOESA_ERR_JSON_PARSE = "Unable to parse the response into a dictionary.\nResponse text - {raw_text}"
CISCOESA_ERR_FROM_SERVER = "API failed\nStatus code: {status}\nDetail: {detail}"
CISCOESA_REST_RESP_OTHER_ERROR_MSG = "Error returned"
CISCOESA_CONNECTION_TEST_MSG = "Querying endpoint to verify the credentials provided"
CISCOESA_TEST_CONNECTIVITY_FAIL = "Test Connectivity Failed"
CISCOESA_TEST_CONNECTIVITY_PASS = "Test Connectivity Passed"
CISCOESA_TEST_CONNECTIVITY_ENDPOINT = "/api/v1.0/health"
CISCOESA_GET_REPORT_ENDPOINT = "/api/v1.0/stats/{report_name}"
CISCOESA_GET_REPORT_JSON_REPORT_TITLE = "report_title"
CISCOESA_GET_REPORT_JSON_START_TIME = "start_time"
CISCOESA_GET_REPORT_JSON_END_TIME = "end_time"
CISCOESA_GET_REPORT_JSON_SEARCH_VALUE = "search_value"
CISCOESA_GET_REPORT_JSON_LIMIT = "limit"
CISCOESA_GET_REPORT_JSON_STARTS_WITH = "starts_with"
CISCOESA_GET_REPORT_PARAM_MAX = "max"
CISCOESA_GET_REPORT_PARAM_ENTITY = "entity"
CISCOESA_GET_REPORT_PARAM_RECIPIENT = "recipient"
CISCOESA_GET_REPORT_PARAM_COUNT = "count"
CISCOESA_GET_REPORT_PARAM_DATA = "data"
CISCOESA_GET_REPORT_PARAM_DURATION = "duration"
CISCOESA_CONTAINS_EMAIL = "email"
CISCOESA_CONTAINS_IP = "ip"
CISCOESA_DEFAULT_LIMIT = 10
CISCOESA_DEFAULT_SPAN_DAYS = 249
CISCOESA_DATE_TIME_VALIDATION_ERROR = "Entered date and time is in the incorrect format"
CISCOESA_DATE_TIME_FORMAT_ERROR = "Date and time must be in YYYY-MM-DDTHH:00 format"
CISCOESA_START_TIME_GREATER_THEN_END_TIME = "The start time must be less than the end time"
CISCOESA_INPUT_TIME_FORMAT = "%Y-%m-%dT%H:00"
CISCOESA_API_TIME_FORMAT = "%Y-%m-%dT%H:00+00:00"
CISCOESA_DURATION_FORMAT = "{start_time}/{end_time}"
CISCOESA_REPORTS_QUERIED_SUCCESS_MSG = "Report queried successfully"
CISCOESA_MAIL_USER_DETAILS_REPORT_TITLE = "Internal Users"
CISCOESA_SEARCH_VALUE_VALIDATION_FAIL = "Parameter 'search_value' failed validation"
CISCOESA_UNEXPECTED_RESPONSE = "Expected response not found for report: {report_name}"
CISCOESA_MAIL_USER_DETAILS_REPORT_NAME = "mail_users_detail"
CISCOESA_MAIL_INCOMING_DOMAIN_DETAILS_REPORT_TITLE = "Incoming Mail: Domains"
CISCOESA_MAIL_INCOMING_DOMAIN_DETAILS_REPORT_NAME = "mail_incoming_domain_detail"
CISCOESA_MAIL_INCOMING_IP_HOSTNAME_DETAILS_REPORT_TITLE = "Incoming Mail: IP Addresses"
CISCOESA_MAIL_INCOMING_IP_HOSTNAME_DETAILS_REPORT_NAME = "mail_incoming_ip_hostname_detail"
CISCOESA_MAIL_INCOMING_NETWORK_OWNER_DETAILS_REPORT_TITLE = "Incoming Mail: Network Owners"
CISCOESA_MAIL_INCOMING_NETWORK_OWNER_DETAILS_REPORT_NAME = "mail_incoming_network_detail"
CISCOESA_OUTGOING_SENDERS_DOMAIN_DETAILS_REPORT_TITLE = "Outgoing Senders: Domains"
CISCOESA_OUTGOING_SENDERS_DOMAIN_DETAILS_REPORT_NAME = "mail_sender_domain_detail"
CISCOESA_MAIL_OUTGOING_SENDERS_IP_HOSTNAME_DETAILS_REPORT_TITLE = "Outgoing Senders: IP Addresses"
CISCOESA_MAIL_OUTGOING_SENDERS_IP_HOSTNAME_DETAILS_REPORT_NAME = "mail_sender_ip_hostname_detail"
CISCOESA_OUTGOING_DESTINATIONS_REPORT_TITLE = "Outgoing Destinations"
CISCOESA_OUTGOING_DESTINATIONS_REPORT_NAME = "mail_destination_domain_detail"
CISCOESA_VIRUS_TYPES_REPORT_TITLE = "Virus Types"
CISCOESA_VIRUS_TYPES_REPORT_NAME = "mail_virus_type_detail"
CISCOESA_OUTGOING_CONTENT_FILTERS_REPORT_TITLE = "Outgoing Content Filters"
CISCOESA_OUTGOING_CONTENT_FILTERS_REPORT_NAME = "mail_content_filter_outgoing"
CISCOESA_INBOUND_SMTP_AUTH_REPORT_TITLE = "Inbound SMTP Authentication"
CISCOESA_INBOUND_SMTP_AUTH_REPORT_NAME = "mail_authentication_incoming_domain"
CISCOESA_DLP_OUTGOING_POLICY_REPORT_TITLE = "DLP Outgoing Policy"
CISCOESA_DLP_OUTGOING_POLICY_REPORT_NAME = "mail_dlp_outgoing_policy_detail"
CISCOESA_GET_REPORT_ERROR = "Error occurred while getting data for report: {report_title}"
CISCOESA_GET_REPORT_INTERMEDIATE_MSG = "Querying report '{report_title}'"
CISCOESA_GET_REPORT_PARSE_ERROR = "Error occurred while parsing report data: {error}"
