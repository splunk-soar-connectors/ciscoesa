# Cisco ESA

Publisher: Splunk \
Connector Version: 4.1.0 \
Product Vendor: Cisco \
Product Name: Cisco ESA \
Minimum Product Version: 6.3.0

This app supports investigation on the Cisco Email Security Appliance (ESA) device

### Configuration variables

This table lists the configuration variables required to operate Cisco ESA. These variables are specified when configuring a Cisco ESA asset in Splunk SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**url** | required | string | URL (e.g. https://10.10.10.10:6443) |
**sma_url** | optional | string | SMA URL (e.g. https://10.20.20.20:6443) |
**username** | required | string | Username (for both ESA and SMA) |
**password** | required | password | Password (for both ESA and SMA) |
**verify_server_cert** | optional | boolean | Verify server certificate |
**cluster_mode** | optional | boolean | Check if ESA is deployed in cluster mode |
**timeout** | optional | numeric | REST API timeout |

### Supported Actions

[test connectivity](#action-test-connectivity) - Validate credentials provided for connectivity \
[decode url](#action-decode-url) - Process Cisco encoded URL \
[get report](#action-get-report) - Retrieve statistical reports from ESA \
[list dictionaries](#action-list-dictionaries) - List all dictionaries available in Cisco ESA \
[list dictionary items](#action-list-dictionary-items) - List all entries of an ESA dictionary \
[add dictionary](#action-add-dictionary) - Adds a new ESA dictionary \
[add dictionary items](#action-add-dictionary-items) - Add an entry to an ESA dictionary \
[remove dictionary](#action-remove-dictionary) - Removes an existing ESA dictionary \
[remove dictionary items](#action-remove-dictionary-items) - Remove an entry from an ESA dictionary \
[add policy items](#action-add-policy-items) - Add users to an Incoming Mail Policy \
[list policy items](#action-list-policy-items) - List information of all users of an Incoming Mail Policy \
[remove policy items](#action-remove-policy-items) - Remove users from an Incoming Mail Policy \
[update policy items](#action-update-policy-items) - Update users in an Incoming Mail Policy \
[search pov quarantine](#action-search-pov-quarantine) - Search messages in the other quarantine that match multiple attributes \
[release pov quarantine](#action-release-pov-quarantine) - Release a message that matches the mid attribute from a pov quarantine \
[search spam quarantine](#action-search-spam-quarantine) - Search messages in the spam quarantine that match multiple attributes \
[release spam quarantine](#action-release-spam-quarantine) - Release a message that matches the mid attribute from spam quarantine \
[list hat groups](#action-list-hat-groups) - Retrieves HAT configuration details of all sender groups in listener \
[list hat group](#action-list-hat-group) - Retrieves HAT Configuration Details for Specific Sender Group \
[add hat group](#action-add-hat-group) - Creates HAT sender group with specific configuration \
[remove hat group](#action-remove-hat-group) - Deletes specific HAT sender group \
[add hat sender](#action-add-hat-sender) - Adds HAT senders to existing sender group \
[remove hat sender](#action-remove-hat-sender) - Deletes specific HAT senders from sender group \
[update hat order](#action-update-hat-order) - Updates order of HAT sender groups for listener \
[find hat group](#action-find-hat-group) - Finds HAT senders in sender groups

## action: 'test connectivity'

Validate credentials provided for connectivity

Type: **test** \
Read only: **True**

#### Action Parameters

No parameters are required for this action

#### Action Output

No Output

## action: 'decode url'

Process Cisco encoded URL

Type: **investigate** \
Read only: **True**

Parse and decode URL from "secure-web.cisco.com" to get the redirected URL.<ul><li>It will accept the entire URL:<p><code>http://secure-web.cisco.com/{random_chars}/https%3A%2F%2Fmy.phantom.us%2F4.1%2Fdocs%2Fapp_reference%2Fphantom_ciscoesa</code></li><li>Everything except the protocol:<p><code>secure-web.cisco.com/{random_chars}/https%3A%2F%2Fmy.phantom.us%2F4.1%2Fdocs%2Fapp_reference%2Fphantom_ciscoesa</code></li><li>Or just the quoted section:<p><code>https%3A%2F%2Fmy.phantom.us%2F4.1%2Fdocs%2Fapp_reference%2Fphantom_ciscoesa</code></li></ul>

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**encoded_url** | required | Encoded URL to process | string | `url` `encoded url` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.encoded_url | string | `url` `encoded url` | https://www.w3schools.com/tags/ref_urlencode.ASP#:~:text=URL%20Encoding%20(Percent%20Encoding)&text=URLs%20can%20only%20be%20sent,followed%20by%20two%20hexadecimal%20digits. |
action_result.data.\*.decoded_url | string | `url` | https://www.w3schools.com/tags/ref_urlencode.ASP#:~:text=URL Encoding (Percent Encoding)&text=URLs can only be sent,followed by two hexadecimal digits. |
action_result.summary | string | | |
action_result.message | string | | Decoded entire URL Parsed from secure-web.cisco.com URL and decoded |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get report'

Retrieve statistical reports from ESA

Type: **investigate** \
Read only: **True**

This action is used to query "Query-based Reports" which counts various events in your appliance against a user-specified entity such as IP address, domain name, etc. for a specified duration.<br>If <b>start_time</b> and <b>end_time</b> are not given, then the report will be queried for the last 250 days.<br>If either <b>start_time</b> or <b>end_time</b> is provided, then the report will be queried for 250 days relative to the given parameter.<br>Following is the mapping of the report title and its corresponding entity that can be provided to filter reports:<table><tbody><tr class='plain'><th>Report Title</th><th>Entity Value</th></tr><tr><td>Internal Users</td><td>Email ID of the internal user (e.g. user@example.com)</td></tr><tr><td>Incoming Mail: Domains</td><td>Domain name (e.g. abc.com)</td></tr><tr><td>Incoming Mail: IP Addresses</td><td>IPv4 or IPv6 address</td></tr><tr><td>Incoming Mail: Network Owners</td><td>Name of the network owner (e.g. Xyz Corporation)</td></tr><tr><td>Outgoing Senders: Domains</td><td>Domain name (e.g. abc.com)</td></tr><tr><td>Outgoing Senders: IP Addresses</td><td>IPv4 or IPv6 address</td></tr><tr><td>Outgoing Destinations</td><td>Domain name (e.g. abc.com)</td></tr><tr><td>Outgoing Content Filters</td><td>Name of the outgoing Content Filter</td></tr><tr><td>Virus Types</td><td>Name of virus</td></tr><tr><td>Inbound SMTP Authentication</td><td>Domain name (e.g. abc.com)</td></tr><tr><td>Data Loss Prevention (DLP) Outgoing Policy</td><td>Name of the DLP policy</td></tr></tbody></table><br>The action supports limiting the number of items returned using the <b>limit</b> parameter. If the <b>limit</b> parameter is 0, then the action will fetch no data for the selected report(s). If the limit is not specified, the action will fetch by default 10 items for all specified reports. For a particular report, if the limit specified is greater than the available data, the action will fetch all data for that report.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**report_title** | required | Report Title | string | `ciscoesa report title` |
**filter_by** | optional | Entity to filter the results | string | |
**filter_value** | optional | Entity value to filter the results | string | |
**starts_with** | optional | Retrieve items starting with specified filter value | boolean | |
**start_time** | optional | Start time (YYYY-MM-DDTHH:00) | string | |
**end_time** | optional | End time (YYYY-MM-DDTHH:00) | string | |
**limit** | optional | Maximum number of items to retrieve | numeric | |
**offset** | optional | Starting index of overall result set | numeric | |
**order_by** | optional | The attribute by which to order the data in the response | string | |
**order_dir** | optional | Sort direction of results | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.end_time | string | | 2001-12-12T11:00 |
action_result.parameter.filter_by | string | | ip_address |
action_result.parameter.filter_value | string | | Test Policy |
action_result.parameter.limit | numeric | | 11 |
action_result.parameter.offset | numeric | | 0 |
action_result.parameter.order_by | string | | bulk_mail |
action_result.parameter.order_dir | string | | asc |
action_result.parameter.report_title | string | `ciscoesa report title` | DLP Outgoing Policy |
action_result.parameter.start_time | string | | 2001-11-12T11:00 |
action_result.parameter.starts_with | boolean | | Test |
action_result.data.\*.data.blocked_dmarc.resultSet.\*.key | string | | unknown domain |
action_result.data.\*.data.blocked_dmarc.resultSet.\*.value | numeric | | 0 |
action_result.data.\*.data.blocked_invalid_recipient.resultSet.\*.key | string | | unknown domain |
action_result.data.\*.data.blocked_invalid_recipient.resultSet.\*.value | numeric | | 0 |
action_result.data.\*.data.blocked_reputation.resultSet.\*.key | string | | unknown domain |
action_result.data.\*.data.blocked_reputation.resultSet.\*.value | numeric | | 42 |
action_result.data.\*.data.blocked_sdr.resultSet.\*.key | string | | unknown domain |
action_result.data.\*.data.blocked_sdr.resultSet.\*.value | numeric | | 0 |
action_result.data.\*.data.bulk_mail.resultSet.\*.key | string | | unknown domain |
action_result.data.\*.data.bulk_mail.resultSet.\*.value | numeric | | 0 |
action_result.data.\*.data.detected_amp.resultSet.\*.key | string | | unknown domain |
action_result.data.\*.data.detected_amp.resultSet.\*.value | numeric | | 0 |
action_result.data.\*.data.detected_spam.resultSet.\*.key | string | | unknown domain |
action_result.data.\*.data.detected_spam.resultSet.\*.value | numeric | | 0 |
action_result.data.\*.data.detected_virus.resultSet.\*.key | string | | unknown domain |
action_result.data.\*.data.detected_virus.resultSet.\*.value | numeric | | 0 |
action_result.data.\*.data.dns_verified.resultSet.\*.key | string | | unknown domain |
action_result.data.\*.data.dns_verified.resultSet.\*.value | numeric | | 0 |
action_result.data.\*.data.last_sender_group.resultSet.\*.key | string | | unknown domain |
action_result.data.\*.data.last_sender_group.resultSet.\*.value | numeric | | 0 |
action_result.data.\*.data.last_sender_group_name.resultSet.\*.key | string | | unknown domain |
action_result.data.\*.data.last_sender_group_name.resultSet.\*.value | string | | UNKNOWNLIST |
action_result.data.\*.data.marketing_mail.resultSet.\*.key | string | | unknown domain |
action_result.data.\*.data.marketing_mail.resultSet.\*.value | numeric | | 0 |
action_result.data.\*.data.resultSet.auth_disallow.\* | string | | |
action_result.data.\*.data.resultSet.auth_fail.\* | string | | |
action_result.data.\*.data.resultSet.auth_success.\* | string | | |
action_result.data.\*.data.resultSet.blocked_dmarc.\*.key | string | | unknown domain |
action_result.data.\*.data.resultSet.blocked_dmarc.\*.value | numeric | | 0 |
action_result.data.\*.data.resultSet.blocked_invalid_recipient.\*.count.key | string | | unknown domain |
action_result.data.\*.data.resultSet.blocked_invalid_recipient.\*.count.value | numeric | | 0 |
action_result.data.\*.data.resultSet.blocked_invalid_recipient.\*.key | string | | unknown domain |
action_result.data.\*.data.resultSet.blocked_invalid_recipient.\*.recipient | string | | 10.1.16.99 |
action_result.data.\*.data.resultSet.blocked_invalid_recipient.\*.value | numeric | | 0 |
action_result.data.\*.data.resultSet.blocked_reputation.\*.key | string | | unknown domain |
action_result.data.\*.data.resultSet.blocked_reputation.\*.key | string | | unknown domain |
action_result.data.\*.data.resultSet.blocked_reputation.\*.key | string | | unknown domain |
action_result.data.\*.data.resultSet.blocked_reputation.\*.recipient | string | | 10.1.16.99 |
action_result.data.\*.data.resultSet.blocked_reputation.\*.value | numeric | | 42 |
action_result.data.\*.data.resultSet.blocked_reputation.\*.value | numeric | | 24 |
action_result.data.\*.data.resultSet.blocked_reputation.\*.value | numeric | | 0 |
action_result.data.\*.data.resultSet.blocked_sdr.\*.count.key | string | | unknown domain |
action_result.data.\*.data.resultSet.blocked_sdr.\*.count.value | numeric | | 0 |
action_result.data.\*.data.resultSet.blocked_sdr.\*.key | string | | unknown domain |
action_result.data.\*.data.resultSet.blocked_sdr.\*.recipient | string | | 10.1.16.99 |
action_result.data.\*.data.resultSet.blocked_sdr.\*.value | numeric | | 0 |
action_result.data.\*.data.resultSet.bulk_mail.\*.count.key | string | | unknown domain |
action_result.data.\*.data.resultSet.bulk_mail.\*.count.value | numeric | | 0 |
action_result.data.\*.data.resultSet.bulk_mail.\*.key | string | | unknown domain |
action_result.data.\*.data.resultSet.bulk_mail.\*.recipient | string | | 10.1.16.99 |
action_result.data.\*.data.resultSet.bulk_mail.\*.value | numeric | | 0 |
action_result.data.\*.data.resultSet.cert_fail.\* | string | | |
action_result.data.\*.data.resultSet.cert_fallback_fail.\* | string | | |
action_result.data.\*.data.resultSet.cert_fallback_success.\* | string | | |
action_result.data.\*.data.resultSet.cert_success.\* | string | | |
action_result.data.\*.data.resultSet.conn_plain.\* | string | | |
action_result.data.\*.data.resultSet.conn_tls_fail.\* | string | | |
action_result.data.\*.data.resultSet.conn_tls_opt_fail.\* | string | | |
action_result.data.\*.data.resultSet.conn_tls_opt_success.\* | string | | |
action_result.data.\*.data.resultSet.conn_tls_success.\* | string | | |
action_result.data.\*.data.resultSet.conn_tls_total.\* | string | | |
action_result.data.\*.data.resultSet.detected_amp.\*.count.key | string | | unknown domain |
action_result.data.\*.data.resultSet.detected_amp.\*.count.value | numeric | | 0 |
action_result.data.\*.data.resultSet.detected_amp.\*.key | string | | unknown domain |
action_result.data.\*.data.resultSet.detected_amp.\*.recipient | string | | 10.1.16.99 |
action_result.data.\*.data.resultSet.detected_amp.\*.value | numeric | | 0 |
action_result.data.\*.data.resultSet.detected_spam.\* | string | | |
action_result.data.\*.data.resultSet.detected_spam.\* | string | | |
action_result.data.\*.data.resultSet.detected_spam.\*.count.key | string | | unknown domain |
action_result.data.\*.data.resultSet.detected_spam.\*.count.value | numeric | | 0 |
action_result.data.\*.data.resultSet.detected_spam.\*.key | string | | unknown domain |
action_result.data.\*.data.resultSet.detected_spam.\*.recipient | string | | 10.1.16.99 |
action_result.data.\*.data.resultSet.detected_spam.\*.value | numeric | | 0 |
action_result.data.\*.data.resultSet.detected_virus.\*.count.key | string | | unknown domain |
action_result.data.\*.data.resultSet.detected_virus.\*.count.value | numeric | | 0 |
action_result.data.\*.data.resultSet.detected_virus.\*.key | string | | unknown domain |
action_result.data.\*.data.resultSet.detected_virus.\*.recipient | string | | 10.1.16.99 |
action_result.data.\*.data.resultSet.detected_virus.\*.value | numeric | | 0 |
action_result.data.\*.data.resultSet.dns_verified.\*.count.key | string | | unknown domain |
action_result.data.\*.data.resultSet.dns_verified.\*.count.value | numeric | | 0 |
action_result.data.\*.data.resultSet.dns_verified.\*.key | string | | unknown domain |
action_result.data.\*.data.resultSet.dns_verified.\*.recipient | string | | 10.1.16.99 |
action_result.data.\*.data.resultSet.dns_verified.\*.value | numeric | | 0 |
action_result.data.\*.data.resultSet.encrypted_tls.\* | string | | |
action_result.data.\*.data.resultSet.incoming_bulk_mail.\* | string | | |
action_result.data.\*.data.resultSet.incoming_bulk_mail.\*.count | numeric | | 0 |
action_result.data.\*.data.resultSet.incoming_bulk_mail.\*.recipient | string | | test@user.com |
action_result.data.\*.data.resultSet.incoming_detected_amp.\* | string | | |
action_result.data.\*.data.resultSet.incoming_detected_amp.\*.count | numeric | | 0 |
action_result.data.\*.data.resultSet.incoming_detected_amp.\*.recipient | string | | test@user.com |
action_result.data.\*.data.resultSet.incoming_detected_content_filter.\* | string | | |
action_result.data.\*.data.resultSet.incoming_detected_content_filter.\*.count | numeric | | 0 |
action_result.data.\*.data.resultSet.incoming_detected_content_filter.\*.recipient | string | | test@user.com |
action_result.data.\*.data.resultSet.incoming_detected_ims_spam_increment_over_case.\* | string | | |
action_result.data.\*.data.resultSet.incoming_detected_ims_spam_increment_over_case.\*.count | numeric | | 0 |
action_result.data.\*.data.resultSet.incoming_detected_ims_spam_increment_over_case.\*.recipient | string | | test@user.com |
action_result.data.\*.data.resultSet.incoming_detected_spam.\* | string | | |
action_result.data.\*.data.resultSet.incoming_detected_spam.\*.count | numeric | | 0 |
action_result.data.\*.data.resultSet.incoming_detected_spam.\*.recipient | string | | test@user.com |
action_result.data.\*.data.resultSet.incoming_detected_virus.\* | string | | |
action_result.data.\*.data.resultSet.incoming_detected_virus.\*.count | numeric | | 0 |
action_result.data.\*.data.resultSet.incoming_detected_virus.\*.recipient | string | | test@user.com |
action_result.data.\*.data.resultSet.incoming_graymail.\* | string | | |
action_result.data.\*.data.resultSet.incoming_graymail.\*.count | numeric | | 0 |
action_result.data.\*.data.resultSet.incoming_graymail.\*.recipient | string | | test@user.com |
action_result.data.\*.data.resultSet.incoming_marketing_mail.\* | string | | |
action_result.data.\*.data.resultSet.incoming_marketing_mail.\*.count | numeric | | 0 |
action_result.data.\*.data.resultSet.incoming_marketing_mail.\*.recipient | string | | test@user.com |
action_result.data.\*.data.resultSet.incoming_social_mail.\* | string | | |
action_result.data.\*.data.resultSet.incoming_social_mail.\*.count | numeric | | 0 |
action_result.data.\*.data.resultSet.incoming_social_mail.\*.recipient | string | | test@user.com |
action_result.data.\*.data.resultSet.incoming_threat_content_filter.\* | string | | |
action_result.data.\*.data.resultSet.incoming_threat_content_filter.\*.count | numeric | | 0 |
action_result.data.\*.data.resultSet.incoming_threat_content_filter.\*.recipient | string | | test@user.com |
action_result.data.\*.data.resultSet.incoming_total_clean_recipients.\* | string | | |
action_result.data.\*.data.resultSet.incoming_total_clean_recipients.\*.count | numeric | | 2 |
action_result.data.\*.data.resultSet.incoming_total_clean_recipients.\*.recipient | string | | test@user.com |
action_result.data.\*.data.resultSet.incoming_total_recipients.\* | string | | |
action_result.data.\*.data.resultSet.incoming_total_recipients.\*.count | numeric | | 2 |
action_result.data.\*.data.resultSet.incoming_total_recipients.\*.recipient | string | | test@user.com |
action_result.data.\*.data.resultSet.last_sender_group.\*.count.key | string | | unknown domain |
action_result.data.\*.data.resultSet.last_sender_group.\*.count.value | numeric | | 0 |
action_result.data.\*.data.resultSet.last_sender_group.\*.key | string | | unknown domain |
action_result.data.\*.data.resultSet.last_sender_group.\*.recipient | string | | 10.1.16.99 |
action_result.data.\*.data.resultSet.last_sender_group.\*.value | numeric | | 0 |
action_result.data.\*.data.resultSet.last_sender_group_name.\*.count.key | string | | unknown domain |
action_result.data.\*.data.resultSet.last_sender_group_name.\*.count.value | string | | UNKNOWNLIST |
action_result.data.\*.data.resultSet.last_sender_group_name.\*.key | string | | unknown domain |
action_result.data.\*.data.resultSet.last_sender_group_name.\*.recipient | string | | 10.1.16.99 |
action_result.data.\*.data.resultSet.last_sender_group_name.\*.value | string | | UNKNOWNLIST |
action_result.data.\*.data.resultSet.marketing_mail.\*.count.key | string | | unknown domain |
action_result.data.\*.data.resultSet.marketing_mail.\*.count.value | numeric | | 0 |
action_result.data.\*.data.resultSet.marketing_mail.\*.key | string | | unknown domain |
action_result.data.\*.data.resultSet.marketing_mail.\*.recipient | string | | 10.1.16.99 |
action_result.data.\*.data.resultSet.marketing_mail.\*.value | numeric | | 0 |
action_result.data.\*.data.resultSet.noauth.\* | string | | |
action_result.data.\*.data.resultSet.outgoing_detected_amp.\* | string | | |
action_result.data.\*.data.resultSet.outgoing_detected_amp.\*.count | numeric | | 0 |
action_result.data.\*.data.resultSet.outgoing_detected_amp.\*.recipient | string | | test@user.com |
action_result.data.\*.data.resultSet.outgoing_detected_content_filter.\* | string | | |
action_result.data.\*.data.resultSet.outgoing_detected_content_filter.\*.count | numeric | | 0 |
action_result.data.\*.data.resultSet.outgoing_detected_content_filter.\*.recipient | string | | test@user.com |
action_result.data.\*.data.resultSet.outgoing_detected_ims_spam_increment_over_case.\* | string | | |
action_result.data.\*.data.resultSet.outgoing_detected_ims_spam_increment_over_case.\*.count | numeric | | 0 |
action_result.data.\*.data.resultSet.outgoing_detected_ims_spam_increment_over_case.\*.recipient | string | | test@user.com |
action_result.data.\*.data.resultSet.outgoing_detected_spam.\* | string | | |
action_result.data.\*.data.resultSet.outgoing_detected_spam.\*.count | numeric | | 0 |
action_result.data.\*.data.resultSet.outgoing_detected_spam.\*.recipient | string | | test@user.com |
action_result.data.\*.data.resultSet.outgoing_detected_virus.\* | string | | |
action_result.data.\*.data.resultSet.outgoing_detected_virus.\*.count | numeric | | 0 |
action_result.data.\*.data.resultSet.outgoing_detected_virus.\*.recipient | string | | test@user.com |
action_result.data.\*.data.resultSet.outgoing_threat_content_filter.\* | string | | |
action_result.data.\*.data.resultSet.outgoing_threat_content_filter.\*.count | numeric | | 0 |
action_result.data.\*.data.resultSet.outgoing_threat_content_filter.\*.recipient | string | | test@user.com |
action_result.data.\*.data.resultSet.outgoing_total_clean_recipients.\* | string | | |
action_result.data.\*.data.resultSet.outgoing_total_clean_recipients.\*.count | numeric | | 0 |
action_result.data.\*.data.resultSet.outgoing_total_clean_recipients.\*.recipient | string | | test@user.com |
action_result.data.\*.data.resultSet.outgoing_total_recipients.\* | string | | |
action_result.data.\*.data.resultSet.outgoing_total_recipients.\*.count | numeric | | 0 |
action_result.data.\*.data.resultSet.outgoing_total_recipients.\*.recipient | string | | test@user.com |
action_result.data.\*.data.resultSet.sbrs_score.\*.count.key | string | | unknown domain |
action_result.data.\*.data.resultSet.sbrs_score.\*.count.value | numeric | | 0 |
action_result.data.\*.data.resultSet.sbrs_score.\*.key | string | | unknown domain |
action_result.data.\*.data.resultSet.sbrs_score.\*.recipient | string | | 10.1.16.99 |
action_result.data.\*.data.resultSet.sbrs_score.\*.value | numeric | | 0 |
action_result.data.\*.data.resultSet.social_mail.\* | string | | |
action_result.data.\*.data.resultSet.social_mail.\* | string | | |
action_result.data.\*.data.resultSet.social_mail.\*.count.key | string | | unknown domain |
action_result.data.\*.data.resultSet.social_mail.\*.count.value | numeric | | 0 |
action_result.data.\*.data.resultSet.social_mail.\*.key | string | | unknown domain |
action_result.data.\*.data.resultSet.social_mail.\*.recipient | string | | 10.1.16.99 |
action_result.data.\*.data.resultSet.social_mail.\*.value | numeric | | 0 |
action_result.data.\*.data.resultSet.threat_content_filter.\* | string | | |
action_result.data.\*.data.resultSet.threat_content_filter.\*.key | string | | unknown domain |
action_result.data.\*.data.resultSet.threat_content_filter.\*.recipient | string | | 10.1.16.99 |
action_result.data.\*.data.resultSet.threat_content_filter.\*.value | numeric | | 0 |
action_result.data.\*.data.resultSet.total.\* | string | | |
action_result.data.\*.data.resultSet.total_accepted_connections.\* | string | | |
action_result.data.\*.data.resultSet.total_clean_recipients.\* | string | | |
action_result.data.\*.data.resultSet.total_clean_recipients.\*.count.key | string | | unknown domain |
action_result.data.\*.data.resultSet.total_clean_recipients.\*.count.value | numeric | | 0 |
action_result.data.\*.data.resultSet.total_clean_recipients.\*.key | string | | unknown domain |
action_result.data.\*.data.resultSet.total_clean_recipients.\*.recipient | string | | 10.1.16.99 |
action_result.data.\*.data.resultSet.total_clean_recipients.\*.value | numeric | | 0 |
action_result.data.\*.data.resultSet.total_graymail_recipients.\* | string | | |
action_result.data.\*.data.resultSet.total_graymail_recipients.\*.count.key | string | | unknown domain |
action_result.data.\*.data.resultSet.total_graymail_recipients.\*.count.value | numeric | | 0 |
action_result.data.\*.data.resultSet.total_graymail_recipients.\*.key | string | | unknown domain |
action_result.data.\*.data.resultSet.total_graymail_recipients.\*.recipient | string | | 10.1.16.99 |
action_result.data.\*.data.resultSet.total_graymail_recipients.\*.value | numeric | | 0 |
action_result.data.\*.data.resultSet.total_recipients.\* | string | | |
action_result.data.\*.data.resultSet.total_recipients.\*.count.key | string | | unknown domain |
action_result.data.\*.data.resultSet.total_recipients.\*.count.value | numeric | | 42 |
action_result.data.\*.data.resultSet.total_recipients.\*.key | string | | unknown domain |
action_result.data.\*.data.resultSet.total_recipients.\*.recipient | string | | 10.1.16.99 |
action_result.data.\*.data.resultSet.total_recipients.\*.value | numeric | | 42 |
action_result.data.\*.data.resultSet.total_rejected_connections.\* | string | | |
action_result.data.\*.data.resultSet.total_threat_recipients.\* | string | | |
action_result.data.\*.data.resultSet.total_threat_recipients.\*.count.key | string | | unknown domain |
action_result.data.\*.data.resultSet.total_threat_recipients.\*.count.value | numeric | | 42 |
action_result.data.\*.data.resultSet.total_threat_recipients.\*.key | string | | unknown domain |
action_result.data.\*.data.resultSet.total_threat_recipients.\*.recipient | string | | 10.1.16.99 |
action_result.data.\*.data.resultSet.total_threat_recipients.\*.value | numeric | | 42 |
action_result.data.\*.data.resultSet.total_throttled_recipients.\* | string | | |
action_result.data.\*.data.sbrs_score.resultSet.\*.key | string | | unknown domain |
action_result.data.\*.data.sbrs_score.resultSet.\*.value | numeric | | 0 |
action_result.data.\*.data.social_mail.resultSet.\*.key | string | | unknown domain |
action_result.data.\*.data.social_mail.resultSet.\*.value | numeric | | 0 |
action_result.data.\*.data.threat_content_filter.resultSet.\*.key | string | | unknown domain |
action_result.data.\*.data.threat_content_filter.resultSet.\*.value | numeric | | 0 |
action_result.data.\*.data.total_clean_recipients.resultSet.\*.key | string | | unknown domain |
action_result.data.\*.data.total_clean_recipients.resultSet.\*.value | numeric | | 0 |
action_result.data.\*.data.total_graymail_recipients.resultSet.\*.key | string | | unknown domain |
action_result.data.\*.data.total_graymail_recipients.resultSet.\*.value | numeric | | 0 |
action_result.data.\*.data.total_recipients.resultSet.\*.key | string | | unknown domain |
action_result.data.\*.data.total_recipients.resultSet.\*.value | numeric | | 42 |
action_result.data.\*.data.total_threat_recipients.resultSet.\*.key | string | | unknown domain |
action_result.data.\*.data.total_threat_recipients.resultSet.\*.value | numeric | | 42 |
action_result.data.\*.data.type | string | | mail_sender_domain_detail |
action_result.data.\*.mail_incoming_domain_detail.data.blocked_reputation.\*.count | numeric | | 6702 |
action_result.data.\*.mail_incoming_domain_detail.data.blocked_reputation.\*.recipient | string | | unknown domain |
action_result.data.\*.mail_incoming_domain_detail.data.total_recipients.\*.count | numeric | | 6702 |
action_result.data.\*.mail_incoming_domain_detail.data.total_recipients.\*.recipient | string | | unknown domain |
action_result.data.\*.mail_incoming_domain_detail.data.total_rejected_connections.\*.count | numeric | | 2234 |
action_result.data.\*.mail_incoming_domain_detail.data.total_rejected_connections.\*.recipient | string | | unknown domain |
action_result.data.\*.mail_incoming_domain_detail.data.total_threat_recipients.\*.count | numeric | | 6702 |
action_result.data.\*.mail_incoming_domain_detail.data.total_threat_recipients.\*.recipient | string | | unknown domain |
action_result.data.\*.mail_incoming_domain_detail.uri | string | | /api/v1.0/stats/mail_incoming_domain_detail?duration=2021-07-30T12%3A00%2B00%3A00%2F2022-04-05T12%3A00%2B00%3A00&max=10 |
action_result.data.\*.mail_users_detail.uri | string | | /api/v1.0/stats/mail_users_detail?duration=2021-07-31T10%3A00%2B00%3A00%2F2022-04-06T10%3A00%2B00%3A00&max=10 |
action_result.data.\*.meta.totalCount | numeric | | -1 |
action_result.summary | string | | |
action_result.message | string | | Report queried successfully |
summary.total_objects | numeric | | 12 |
summary.total_objects_successful | numeric | | 34 |

## action: 'list dictionaries'

List all dictionaries available in Cisco ESA

Type: **investigate** \
Read only: **False**

#### Action Parameters

No parameters are required for this action

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | |
action_result.data | string | | |
action_result.data.\*.name | string | | |
action_result.data.\*.encoding | string | | |
action_result.data.\*.ignorecase | numeric | | |
action_result.data.\*.wholewords | numeric | | |
action_result.data.\*.words_count | numeric | | |
action_result.data.\*.words_count.term_count | numeric | | |
action_result.data.\*.words_count.smart_identifier_count | numeric | | |
action_result.data.\*.words | string | | |
action_result.data.\*.words.\*.0 | string | | |
action_result.data.\*.words.\*.1 | string | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'list dictionary items'

List all entries of an ESA dictionary

Type: **investigate** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**dictionary_name** | required | Name of dictionary to list | string | `ciscoesa dictionary name` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.dictionary_name | string | `ciscoesa dictionary name` | |
action_result.status | string | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'add dictionary'

Adds a new ESA dictionary

Type: **investigate** \
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**dictionary_name** | required | Name of the ESA dictionary. | string | |
**ignorecase** | required | Indicates if the term that needs to be matched is case-sensitive (False) or not case-sensitive (True) | boolean | |
**wholewords** | required | Indicates if the words need to be matched completely (True) or not completely (False). | boolean | |
**words** | required | A list of terms to add to a dictionary. It takes a comma separated list with the structure "word1|weight1" or "word1|weigh1|prefix" (for smart identifiers) | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.dictionary_name | string | | |
action_result.parameter.ignorecase | boolean | | |
action_result.parameter.wholewords | boolean | | |
action_result.parameter.words | string | | |
action_result.status | string | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'add dictionary items'

Add an entry to an ESA dictionary

Type: **investigate** \
Read only: **False**

Per the documentation, the action will handle escaping special regex character prior to adding to the dictionary.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**dictionary_name** | required | Name of dictionary to add an item to | string | `ciscoesa dictionary name` |
**words** | required | A list of terms to add to a dictionary. It takes a comma separated list with the structure "word1|weight1" or "word1|weigh1|prefix" (for smart identifiers). | string | `ciscoesa item value` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.dictionary_name | string | `ciscoesa dictionary name` | |
action_result.parameter.words | string | `ciscoesa item value` | |
action_result.status | string | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'remove dictionary'

Removes an existing ESA dictionary

Type: **investigate** \
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**dictionary_name** | required | Name of the ESA dictionary. | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.dictionary_name | string | | |
action_result.status | string | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'remove dictionary items'

Remove an entry from an ESA dictionary

Type: **investigate** \
Read only: **False**

Per the documentation, the action will handle escaping special regex character prior to removing from the dictionary.

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**dictionary_name** | required | Name of dictionary to remove an item from | string | `ciscoesa dictionary name` |
**words** | required | A list of terms to remove from the dictionary. It takes a comma separated list of words. | string | `ciscoesa item value` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.dictionary_name | string | `ciscoesa dictionary name` | |
action_result.parameter.words | string | `ciscoesa item value` | |
action_result.status | string | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'add policy items'

Add users to an Incoming Mail Policy

Type: **investigate** \
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**policy** | required | Incoming Email Policy | string | |
**sender_config** | optional | This is either "sender" or "sender_not" which then contains the list of domain_entries. | string | |
**sender** | optional | Comma separated list of domain_entries for sender (e.g.: user@example.com,User@,@example.com,@.example.com,user@[1.2.3.4],@[1.1.2.3], user@[ipv6:2001:db8::1]) | string | |
**sender_not** | optional | Comma separated list of domain_entries for sender_not (e.g.: user@example.com,User@,@example.com,@.example.com,user@[1.2.3.4],@[1.1.2.3], user@[ipv6:2001:db8::1]) | string | |
**receiver** | optional | Comma separated list of domain_entries for receiver (e.g.: user@example.com,User@,@example.com,@.example.com,user@[1.2.3.4],@[1.1.2.3], user@[ipv6:2001:db8::1]) | string | |
**receiver_not** | optional | Comma separated list of domain_entries for receiver_not (e.g.: user@example.com,User@,@example.com,@.example.com,user@[1.2.3.4],@[1.1.2.3], user@[ipv6:2001:db8::1]) | string | |
**operation** | optional | Boolean logic between receiver and receiver_not domain_entries. The values can be "and" or "or" . | string | |
**raw_json** | optional | Raw JSON payload for add policy items action. | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.policy | string | | |
action_result.parameter.sender_config | string | | |
action_result.parameter.sender | string | | |
action_result.parameter.sender_not | string | | |
action_result.parameter.receiver | string | | |
action_result.parameter.receiver_not | string | | |
action_result.parameter.operation | string | | |
action_result.parameter.raw_json | string | | |
action_result.status | string | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'list policy items'

List information of all users of an Incoming Mail Policy

Type: **investigate** \
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**policy** | required | Incoming Mail Policy | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.policy | string | | |
action_result.data | string | | |
action_result.data.\*.sender_config | string | | |
action_result.data.\*.sender_config.sender | string | | |
action_result.data.\*.sender_config.sender.domain_entries | string | | |
action_result.data.\*.sender_config.sender.domain_entries.0 | string | | |
action_result.data.\*.receiver_config | string | | |
action_result.data.\*.receiver_config.operation | string | | |
action_result.data.\*.receiver_config.receiver | string | | |
action_result.data.\*.receiver_config.receiver.domain_entries | string | | |
action_result.data.\*.receiver_config.receiver.domain_entries.0 | string | | |
action_result.status | string | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'remove policy items'

Remove users from an Incoming Mail Policy

Type: **investigate** \
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**policy** | required | Incoming Email Policy | string | |
**sender_config** | optional | This is either "sender" or "sender_not" which then contains the list of domain_entries. | string | |
**sender** | optional | Comma separated list of domain_entries for sender (e.g.: user@example.com,User@,@example.com,@.example.com,user@[1.2.3.4],@[1.1.2.3], user@[ipv6:2001:db8::1]) | string | |
**sender_not** | optional | Comma separated list of domain_entries for sender_not (e.g.: user@example.com,User@,@example.com,@.example.com,user@[1.2.3.4],@[1.1.2.3], user@[ipv6:2001:db8::1]) | string | |
**receiver** | optional | Comma separated list of domain_entries for receiver (e.g.: user@example.com,User@,@example.com,@.example.com,user@[1.2.3.4],@[1.1.2.3], user@[ipv6:2001:db8::1]) | string | |
**receiver_not** | optional | Comma separated list of domain_entries for receiver_not (e.g.: user@example.com,User@,@example.com,@.example.com,user@[1.2.3.4],@[1.1.2.3], user@[ipv6:2001:db8::1]) | string | |
**operation** | optional | Boolean logic between receiver and receiver_not domain_entries. The values can be "and" or "or" . raw_json: Raw JSON payload for add policy items action. | string | |
**raw_json** | optional | Raw JSON payload for add policy items action. | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.policy | string | | |
action_result.parameter.sender_config | string | | |
action_result.parameter.sender | string | | |
action_result.parameter.sender_not | string | | |
action_result.parameter.receiver | string | | |
action_result.parameter.receiver_not | string | | |
action_result.parameter.operation | string | | |
action_result.parameter.raw_json | string | | |
action_result.status | string | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'update policy items'

Update users in an Incoming Mail Policy

Type: **investigate** \
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**policy** | required | Incoming Email Policy | string | |
**sender_config** | optional | This is either "sender" or "sender_not" which then contains the list of domain_entries. | string | |
**sender** | optional | Comma separated list of domain_entries for sender (e.g.: user@example.com,User@,@example.com,@.example.com,user@[1.2.3.4],@[1.1.2.3], user@[ipv6:2001:db8::1]) | string | |
**sender_not** | optional | Comma separated list of domain_entries for sender_not (e.g.: user@example.com,User@,@example.com,@.example.com,user@[1.2.3.4],@[1.1.2.3], user@[ipv6:2001:db8::1]) | string | |
**receiver** | optional | Comma separated list of domain_entries for receiver (e.g.: user@example.com,User@,@example.com,@.example.com,user@[1.2.3.4],@[1.1.2.3], user@[ipv6:2001:db8::1]) | string | |
**receiver_not** | optional | Comma separated list of domain_entries for receiver_not (e.g.: user@example.com,User@,@example.com,@.example.com,user@[1.2.3.4],@[1.1.2.3], user@[ipv6:2001:db8::1]) | string | |
**operation** | optional | Boolean logic between receiver domain_entries. The values can be "and" or "or" | string | |
**raw_json** | optional | Raw JSON payload for update policy items action. | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.policy | string | | |
action_result.parameter.sender_config | string | | |
action_result.parameter.sender | string | | |
action_result.parameter.sender_not | string | | |
action_result.parameter.receiver | string | | |
action_result.parameter.receiver_not | string | | |
action_result.parameter.operation | string | | |
action_result.parameter.raw_json | string | | |
action_result.status | string | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'search pov quarantine'

Search messages in the other quarantine that match multiple attributes

Type: **investigate** \
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**start_date** | required | The starting point of the time period for the query. It specifies the date and time from which data should be retrieved, formatted as YYYY-MM-DDThh:mm:00.000Z. | string | |
**end_date** | required | The ending point of the time period for the query. It specifies the date and time up to which data should be retrieved, formatted as YYYY-MM-DDThh:mm:00.000Z. | string | |
**quarantines** | required | This parameter defines the quarantines to search for. Comma separated list of quarantines (e.g.: Outbreak,Virus,File Analysis,Unclassified,Policy). | string | |
**offset** | required | Specify an offset value to retrieve a subset of records starting with the offset value. Offset works with limit, which determines how many records to retrieve starting from the offset. | string | |
**limit** | required | Specify the number of records to retrieve. | string | |
**subject_filter_by** | optional | Filter logic to filter the Subject field. | string | |
**subject_filter_value** | optional | Subject value to used to filter Subjects using subjectFilterBy logic. | string | |
**originating_esa_ip** | optional | The IP address of the ESA in which the message was processed. | string | |
**attachment_name** | optional | The name of the attachment available in the searched emails. | string | |
**attachment_size_filter_by** | optional | Filter logic to filter the attachments. | string | |
**attachment_size_from_value** | optional | Specify an attachment size in KB. This is applicable only for attachmentSizeFilterBy=ragne or attachmentSizeFilterBy=more_than | string | |
**attachment_size_to_value** | optional | Specify an attachment size in KB. This is applicable only for attachmentSizeFilterBy=ragne or attachmentSizeFilterBy=less_than | string | |
**order_by** | optional | Specify how to order to retrieved messages. | string | |
**order_dir** | optional | Specify order direction for retrieved messages. | string | |
**envelope_recipient_filter_by** | optional | Filter logic to filter the email Recipient. | string | |
**envelope_recipient_filter_value** | optional | The value to search for. This is a user defined value. For example: envelopeRecipientFilterValue=user. | string | |
**envelope_sender_filter_by** | optional | Filter logic to filter the email Sender. | string | |
**envelope_sender_filter_value** | optional | The value to search for. This is a user defined value. For example: envelopeSenderFilterValue=user. | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.start_date | string | | |
action_result.parameter.end_date | string | | |
action_result.parameter.quarantines | string | | |
action_result.parameter.offset | string | | |
action_result.parameter.limit | string | | |
action_result.parameter.subject_filter_by | string | | |
action_result.parameter.subject_filter_value | string | | |
action_result.parameter.originating_esa_ip | string | | |
action_result.parameter.attachment_name | string | | |
action_result.parameter.attachment_size_filter_by | string | | |
action_result.parameter.attachment_size_from_value | string | | |
action_result.parameter.attachment_size_to_value | string | | |
action_result.parameter.order_by | string | | |
action_result.parameter.order_dir | string | | |
action_result.parameter.envelope_recipient_filter_by | string | | |
action_result.parameter.envelope_recipient_filter_value | string | | |
action_result.parameter.envelope_sender_filter_by | string | | |
action_result.parameter.envelope_sender_filter_value | string | | |
action_result.status | string | | |
action_result.data | string | | |
action_result.data.\*.mid | numeric | | |
action_result.data.\*.attributes | string | | |
action_result.data.\*.attributes.size | string | | |
action_result.data.\*.attributes.esaMid | numeric | | |
action_result.data.\*.attributes.sender | string | | |
action_result.data.\*.attributes.subject | string | | |
action_result.data.\*.attributes.received | string | | |
action_result.data.\*.attributes.recipient | string | | |
action_result.data.\*.attributes.esaHostName | string | | |
action_result.data.\*.attributes.inQuarantines | string | | |
action_result.data.\*.attributes.scheduledExit | string | | |
action_result.data.\*.attributes.originatingEsaIp | string | | |
action_result.data.\*.attributes.quarantineForReason | string | | |
action_result.data.\*.attributes.quarantineForReasonDict | string | | |
action_result.data.\*.attributes.quarantineForReasonDict.\*.reason | string | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'release pov quarantine'

Release a message that matches the mid attribute from a pov quarantine

Type: **investigate** \
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**mids** | required | POV quarantine message ids to be released. | string | |
**quarantine_name** | required | POV quarantine name. | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.mids | string | | |
action_result.parameter.quarantine_name | string | | |
action_result.status | string | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'search spam quarantine'

Search messages in the spam quarantine that match multiple attributes

Type: **investigate** \
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**start_date** | required | The starting point of the time period for the query. It specifies the date and time from which data should be retrieved, formatted as YYYY-MM-DDThh:mm:00.000Z. | string | |
**end_date** | required | The ending point of the time period for the query. It specifies the date and time up to which data should be retrieved, formatted as YYYY-MM-DDThh:mm:00.000Z. | string | |
**offset** | optional | Specify an offset value to retrieve a subset of records starting with the offset value. Offset works with limit, which determines how many records to retrieve starting from the offset. | string | |
**limit** | optional | Specify the number of records to retrieve. | string | |
**order_by** | optional | Specify how to order to retrieved messages. | string | |
**order_dir** | optional | Specify order direction for retrieved messages. | string | |
**envelope_recipient_filter_operator** | optional | Filter logic to filter the email Recipient. | string | |
**envelope_recipient_filter_value** | optional | The value to search for. This is a user defined value. For example: envelopeRecipientFilterValue=user. | string | |
**filter_operator** | optional | Filter logic to filter the email. | string | |
**filter_value** | optional | The value to search for. This is a user defined value. For example: filterValue=abc.com. | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.start_date | string | | |
action_result.parameter.end_date | string | | |
action_result.parameter.offset | string | | |
action_result.parameter.limit | string | | |
action_result.parameter.order_by | string | | |
action_result.parameter.order_dir | string | | |
action_result.parameter.envelope_recipient_filter_operator | string | | |
action_result.parameter.envelope_recipient_filter_value | string | | |
action_result.parameter.filter_operator | string | | |
action_result.parameter.filter_value | string | | |
action_result.status | string | | |
action_result.data | string | | |
action_result.data.\*.mid | numeric | | |
action_result.data.\*.attributes | string | | |
action_result.data.\*.attributes.envelopeRecipient | string | | |
action_result.data.\*.attributes.toAddress | string | | |
action_result.data.\*.attributes.subject | string | | |
action_result.data.\*.attributes.date | string | | |
action_result.data.\*.attributes.fromAddress | string | | |
action_result.data.\*.attributes.size | string | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'release spam quarantine'

Release a message that matches the mid attribute from spam quarantine

Type: **generic** \
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**mids** | required | Spam quarantine message ids to be released (comma separated list of ids) | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.mids | string | | |
action_result.status | string | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'list hat groups'

Retrieves HAT configuration details of all sender groups in listener

Type: **investigate** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**listener_name** | required | Listener to retrieve configuration from | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.listener_name | string | | |
action_result.status | string | | |
action_result.data | string | | |
action_result.data.\* | string | | |
action_result.data.\*.name | string | | |
action_result.data.\*.sbrs | string | | |
action_result.data.\*.sbrs.\* | numeric | | |
action_result.data.\*.order | string | | |
action_result.data.\*.senders | string | | |
action_result.data.\*.senders.ip_address_list | string | | |
action_result.data.\*.senders.ip_address_list.\* | string | | |
action_result.data.\*.senders.ip_address_list.\*.description | string | | |
action_result.data.\*.senders.ip_address_list.\*.sender_name | string | | |
action_result.data.\*.senders.geo_list | string | | |
action_result.data.\*.senders.geo_list.\* | string | | |
action_result.data.\*.senders.geo_list.\*.description | string | | |
action_result.data.\*.senders.geo_list.\*.sender_name | string | | |
action_result.data.\*.dns_list | string | | |
action_result.data.\*.dns_list.\* | string | | |
action_result.data.\*.sbrs_none | string | | |
action_result.data.\*.description | string | | |
action_result.data.\*.flow_profile | string | | |
action_result.data.\*.dns_host_verification | string | | |
action_result.data.\*.dns_host_verification.lookup_fail | string | | |
action_result.data.\*.dns_host_verification.record_not_exist | string | | |
action_result.data.\*.dns_host_verification.lookup_not_matched | string | | |
action_result.data.\*.dns_host_verification.external_threat_feeds | string | | |
action_result.data.\*.dns_host_verification.external_threat_feeds.\* | string | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'list hat group'

Retrieves HAT Configuration Details for Specific Sender Group

Type: **investigate** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**listener_name** | required | Listener to retrieve configuration from | string | |
**sender_group** | required | Sender group to retrieve configuration for | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.listener_name | string | | |
action_result.status | string | | |
action_result.data | string | | |
action_result.data.\* | string | | |
action_result.data.\*.name | string | | |
action_result.data.\*.sbrs | string | | |
action_result.data.\*.sbrs.\* | numeric | | |
action_result.data.\*.order | string | | |
action_result.data.\*.senders | string | | |
action_result.data.\*.senders.ip_address_list | string | | |
action_result.data.\*.senders.ip_address_list.\* | string | | |
action_result.data.\*.senders.ip_address_list.\*.description | string | | |
action_result.data.\*.senders.ip_address_list.\*.sender_name | string | | |
action_result.data.\*.senders.geo_list | string | | |
action_result.data.\*.senders.geo_list.\* | string | | |
action_result.data.\*.senders.geo_list.\*.description | string | | |
action_result.data.\*.senders.geo_list.\*.sender_name | string | | |
action_result.data.\*.dns_list | string | | |
action_result.data.\*.dns_list.\* | string | | |
action_result.data.\*.sbrs_none | string | | |
action_result.data.\*.description | string | | |
action_result.data.\*.flow_profile | string | | |
action_result.data.\*.dns_host_verification | string | | |
action_result.data.\*.dns_host_verification.lookup_fail | string | | |
action_result.data.\*.dns_host_verification.record_not_exist | string | | |
action_result.data.\*.dns_host_verification.lookup_not_matched | string | | |
action_result.data.\*.dns_host_verification.external_threat_feeds | string | | |
action_result.data.\*.dns_host_verification.external_threat_feeds.\* | string | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |
action_result.parameter.sender_group | string | | |

## action: 'add hat group'

Creates HAT sender group with specific configuration

Type: **investigate** \
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**listener_name** | required | Listener to add the sender group to | string | |
**sender_group** | required | Sender group name to be added | string | |
**flow_profile** | required | The name of the Mail Flow Policy associated with the sender group. | string | |
**order** | optional | The index is used to define the position of the sender group. | numeric | |
**description** | optional | The description for the sender group. | string | |
**sbrs_none** | optional | Include SBRS Scores of "None" | boolean | |
**external_threat_feeds** | optional | A comma separated list of External Threat Feed sources ((configured in the Mail Policy > External Threat Feed Manager page in the web interface). | string | |
**sbrs** | optional | SenderBase Reputation Score (SBRS) for the sender group. The values can be from -10.0 to 10.0: e.g. -1.5,8.5 | string | |
**dns_list** | optional | Remote blocked list queries such as 'query.blocked_list.example' are allowed. Separate multiple entries with commas | string | |
**lookup_not_matched** | optional | The value - "true " indicates that the - Connecting host reverse DNS lookup (PTR) does not match the forward DNS lookup (A). | boolean | |
**record_not_exist** | optional | The value - "true " indicates that the Connecting host PTR record does not exist in DNS. | boolean | |
**lookup_fail** | optional | The value - "true " indicates that the Connecting host PTR lookup fails because of temporary DNS failure. | boolean | |
**ip_sender_name** | optional | IPv4 or IPv6 addresses, hostname, and partial hostname for the ip_address_list. | string | |
**ip_description** | optional | The key contains data that describes the sender in the sender group. | string | |
**geo_sender_name** | optional | Country name for the geo_list. | string | |
**geo_description** | optional | The key contains data that describes the sender in the sender group. | string | |
**raw_json** | optional | Raw JSON for senders keys. Example: {"ip_address_list":[{"sender_name":".cisco.com","description":"Cisco"},{"sender_name":"example_none_d.com","description":""}],"geo_list":[{"sender_name":"India","description":""}]} | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.listener_name | string | | |
action_result.parameter.sender_group | string | | |
action_result.parameter.flow_profile | string | | |
action_result.parameter.order | numeric | | |
action_result.parameter.description | string | | |
action_result.parameter.sbrs_none | boolean | | |
action_result.parameter.external_threat_feeds | string | | |
action_result.parameter.sbrs | string | | |
action_result.parameter.dns_list | string | | |
action_result.parameter.lookup_not_matched | boolean | | |
action_result.parameter.record_not_exist | boolean | | |
action_result.parameter.lookup_fail | boolean | | |
action_result.parameter.ip_sender_name | string | | |
action_result.parameter.ip_description | string | | |
action_result.parameter.geo_sender_name | string | | |
action_result.parameter.geo_description | string | | |
action_result.parameter.raw_json | string | | |
action_result.status | string | | |
action_result.message | string | | |
action_result.data | string | | |
action_result.data.\* | string | | |
action_result.data.\*.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'remove hat group'

Deletes specific HAT sender group

Type: **investigate** \
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**listener_name** | required | Listener to remove the sender group from | string | |
**sender_group** | required | Sender groupto remove | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.listener_name | string | | |
action_result.parameter.sender_group | string | | |
action_result.status | string | | |
action_result.data | string | | |
action_result.data.\* | string | | |
action_result.data.\*.message | string | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'add hat sender'

Adds HAT senders to existing sender group

Type: **investigate** \
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**listener_name** | required | Listener to add sender to | string | |
**sender_group** | required | Sender group name to add sender to | string | |
**ip_sender_name** | optional | IPv4 or IPv6 addresses, hostname, and partial hostname for the ip_address_list | string | |
**ip_description** | optional | The key contains data describing the sender in the sender group | string | |
**geo_sender_name** | optional | Country name for the geo_list | string | |
**geo_description** | optional | The key contains data describing the sender in the sender group | string | |
**raw_json** | optional | Raw JSON for senders keys. Example: {"ip_address_list":[{"sender_name":".cisco.com","description":"Cisco"},{"sender_name":"example_none_d.com","description":""}],"geo_list":[{"sender_name":"India","description":""}]} | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.listener_name | string | | |
action_result.parameter.sender_group | string | | |
action_result.parameter.ip_sender_name | string | | |
action_result.parameter.ip_description | string | | |
action_result.parameter.geo_sender_name | string | | |
action_result.parameter.geo_description | string | | |
action_result.parameter.raw_json | string | | |
action_result.status | string | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'remove hat sender'

Deletes specific HAT senders from sender group

Type: **investigate** \
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**listener_name** | required | Listener to remove senders from | string | |
**sender_group** | required | Sender group name to add sender to | string | |
**senders** | required | Comma separated list containing the names of the senders to delete. | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.listener_name | string | | |
action_result.parameter.sender_group | string | | |
action_result.parameter.senders | string | | |
action_result.status | string | | |
action_result.data | string | | |
action_result.data.\* | string | | |
action_result.data.\*.message | string | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'update hat order'

Updates order of HAT sender groups for listener

Type: **investigate** \
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**listener_name** | required | Listener to update sender groups order for | string | |
**sender_group** | optional | Sender group to change order for | string | |
**order** | optional | New order for the specified sender group | numeric | |
**raw_json** | optional | Raw JSON for data key: e.g. {"BLOCKED_LIST":3,"ALLOWED_LIST":1,"SUSPECTLIST":4,"UNKNOWNLIST":2} | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.listener_name | string | | |
action_result.parameter.sender_group | string | | |
action_result.parameter.order | numeric | | |
action_result.parameter.raw_json | string | | |
action_result.status | string | | |
action_result.data | string | | |
action_result.data.\* | string | | |
action_result.data.\*.message | string | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'find hat group'

Finds HAT senders in sender groups

Type: **investigate** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**listener_name** | optional | Listener to search term in | string | |
**sender_group** | optional | Sender group to search term in | string | |
**search_text** | required | Search text to be searched | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.listener_name | string | | |
action_result.parameter.sender_group | string | | |
action_result.parameter.search_text | string | | |
action_result.status | string | | |
action_result.data | string | | |
action_result.data.\* | string | | |
action_result.data.\*.sender_name | string | | |
action_result.data.\*.description | string | | |
action_result.data.\*.sender_group | string | | |
action_result.data.\*.listener | string | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

______________________________________________________________________

Auto-generated Splunk SOAR Connector documentation.

Copyright 2025 Splunk Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
