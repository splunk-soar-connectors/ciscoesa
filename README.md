[comment]: # "Auto-generated SOAR connector documentation"
# Cisco ESA

Publisher: Splunk  
Connector Version: 3\.0\.0  
Product Vendor: Cisco  
Product Name: Cisco ESA  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5\.4\.0  

This app supports investigation on the Cisco Email Security Appliance \(ESA\) device

### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Cisco ESA asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**url** |  required  | string | URL \(e\.g\. https\://10\.10\.10\.10\:6443\)
**verify\_server\_cert** |  optional  | boolean | Verify server certificate
**username** |  required  | string | Username
**password** |  required  | password | Password
**ssh\_username** |  optional  | string | SSH Username \(Used for dictionary related actions\)
**ssh\_password** |  optional  | password | SSH Password \(Used for dictionary related actions\)

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate credentials provided for connectivity  
[decode url](#action-decode-url) - Process Cisco encoded URL  
[get report](#action-get-report) - Retrieve statistical reports from ESA  
[list dictionary items](#action-list-dictionary-items) - List all entries of an ESA dictionary  
[add dictionary item](#action-add-dictionary-item) - Add an entry to an ESA dictionary  
[remove dictionary item](#action-remove-dictionary-item) - Remove an entry from an ESA dictionary  

## action: 'test connectivity'
Validate credentials provided for connectivity

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'decode url'
Process Cisco encoded URL

Type: **investigate**  
Read only: **True**

Parse and decode URL from "secure\-web\.cisco\.com" to get the redirected URL\.<ul><li>It will accept the entire URL\:<p><code>http\://secure\-web\.cisco\.com/\{random\_chars\}/https%3A%2F%2Fmy\.phantom\.us%2F4\.1%2Fdocs%2Fapp\_reference%2Fphantom\_ciscoesa</code></li><li>Everything except the protocol\:<p><code>secure\-web\.cisco\.com/\{random\_chars\}/https%3A%2F%2Fmy\.phantom\.us%2F4\.1%2Fdocs%2Fapp\_reference%2Fphantom\_ciscoesa</code></li><li>Or just the quoted section\:<p><code>https%3A%2F%2Fmy\.phantom\.us%2F4\.1%2Fdocs%2Fapp\_reference%2Fphantom\_ciscoesa</code></li></ul>

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**encoded\_url** |  required  | Encoded URL to process | string |  `url`  `encoded url` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action\_result\.status | string |  |   success  failed 
action\_result\.parameter\.encoded\_url | string |  `url`  `encoded url`  |   https\://www\.w3schools\.com/tags/ref\_urlencode\.ASP\#\:~\:text=URL%20Encoding%20\(Percent%20Encoding\)&text=URLs%20can%20only%20be%20sent,followed%20by%20two%20hexadecimal%20digits\. 
action\_result\.data\.\*\.decoded\_url | string |  `url`  |   https\://www\.w3schools\.com/tags/ref\_urlencode\.ASP\#\:~\:text=URL Encoding \(Percent Encoding\)&text=URLs can only be sent,followed by two hexadecimal digits\. 
action\_result\.summary | string |  |  
action\_result\.message | string |  |   Decoded entire URL  Parsed from secure\-web\.cisco\.com URL and decoded 
summary\.total\_objects | numeric |  |   1 
summary\.total\_objects\_successful | numeric |  |   1   

## action: 'get report'
Retrieve statistical reports from ESA

Type: **investigate**  
Read only: **True**

This action is used to query "Query\-based Reports" which counts various events in your appliance against a user\-specified entity such as IP address, domain name, etc\. for a specified duration\.<br>If <b>start\_time</b> and <b>end\_time</b> are not given, then the report will be queried for the last 250 days\.<br>If either <b>start\_time</b> or <b>end\_time</b> is provided, then the report will be queried for 250 days relative to the given parameter\.<br>Following is the mapping of the report title and its corresponding entity that can be provided to filter reports\:<table><tbody><tr class='plain'><th>Report Title</th><th>Entity Value</th></tr><tr><td>Internal Users</td><td>Email ID of the internal user \(e\.g\. user\@example\.com\)</td></tr><tr><td>Incoming Mail\: Domains</td><td>Domain name \(e\.g\. abc\.com\)</td></tr><tr><td>Incoming Mail\: IP Addresses</td><td>IPv4 or IPv6 address</td></tr><tr><td>Incoming Mail\: Network Owners</td><td>Name of the network owner \(e\.g\. Xyz Corporation\)</td></tr><tr><td>Outgoing Senders\: Domains</td><td>Domain name \(e\.g\. abc\.com\)</td></tr><tr><td>Outgoing Senders\: IP Addresses</td><td>IPv4 or IPv6 address</td></tr><tr><td>Outgoing Destinations</td><td>Domain name \(e\.g\. abc\.com\)</td></tr><tr><td>Outgoing Content Filters</td><td>Name of the outgoing Content Filter</td></tr><tr><td>Virus Types</td><td>Name of virus</td></tr><tr><td>Inbound SMTP Authentication</td><td>Domain name \(e\.g\. abc\.com\)</td></tr><tr><td>Data Loss Prevention \(DLP\) Outgoing Policy</td><td>Name of the DLP policy</td></tr></tbody></table><br>The action supports limiting the number of items returned using the <b>limit</b> parameter\. If the <b>limit</b> parameter is 0, then the action will fetch no data for the selected report\(s\)\. If the limit is not specified, the action will fetch by default 10 items for all specified reports\. For a particular report, if the limit specified is greater than the available data, the action will fetch all data for that report\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**report\_title** |  required  | Report Title | string |  `ciscoesa report title` 
**filter\_by** |  optional  | Entity to filter the results | string | 
**filter\_value** |  optional  | Entity value to filter the results | string | 
**starts\_with** |  optional  | Retrieve items starting with specified filter value | boolean | 
**start\_time** |  optional  | Start time \(YYYY\-MM\-DDTHH\:00\) | string | 
**end\_time** |  optional  | End time \(YYYY\-MM\-DDTHH\:00\) | string | 
**limit** |  optional  | Maximum number of items to retrieve | numeric | 
**offset** |  optional  | Starting index of overall result set | numeric | 
**order\_by** |  optional  | The attribute by which to order the data in the response | string | 
**order\_dir** |  optional  | Sort direction of results | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action\_result\.status | string |  |   success  failed 
action\_result\.parameter\.end\_time | string |  |   2001\-12\-12T11\:00 
action\_result\.parameter\.filter\_by | string |  |   ip\_address 
action\_result\.parameter\.filter\_value | string |  |   Test Policy 
action\_result\.parameter\.limit | numeric |  |   11 
action\_result\.parameter\.offset | numeric |  |   0 
action\_result\.parameter\.order\_by | string |  |   bulk\_mail 
action\_result\.parameter\.order\_dir | string |  |   asc 
action\_result\.parameter\.report\_title | string |  `ciscoesa report title`  |   DLP Outgoing Policy 
action\_result\.parameter\.start\_time | string |  |   2001\-11\-12T11\:00 
action\_result\.parameter\.starts\_with | boolean |  |   Test 
action\_result\.data\.\*\.data\.blocked\_dmarc\.resultSet\.\*\.key | string |  |   unknown domain 
action\_result\.data\.\*\.data\.blocked\_dmarc\.resultSet\.\*\.value | numeric |  |   0 
action\_result\.data\.\*\.data\.blocked\_invalid\_recipient\.resultSet\.\*\.key | string |  |   unknown domain 
action\_result\.data\.\*\.data\.blocked\_invalid\_recipient\.resultSet\.\*\.value | numeric |  |   0 
action\_result\.data\.\*\.data\.blocked\_reputation\.resultSet\.\*\.key | string |  |   unknown domain 
action\_result\.data\.\*\.data\.blocked\_reputation\.resultSet\.\*\.value | numeric |  |   42 
action\_result\.data\.\*\.data\.blocked\_sdr\.resultSet\.\*\.key | string |  |   unknown domain 
action\_result\.data\.\*\.data\.blocked\_sdr\.resultSet\.\*\.value | numeric |  |   0 
action\_result\.data\.\*\.data\.bulk\_mail\.resultSet\.\*\.key | string |  |   unknown domain 
action\_result\.data\.\*\.data\.bulk\_mail\.resultSet\.\*\.value | numeric |  |   0 
action\_result\.data\.\*\.data\.detected\_amp\.resultSet\.\*\.key | string |  |   unknown domain 
action\_result\.data\.\*\.data\.detected\_amp\.resultSet\.\*\.value | numeric |  |   0 
action\_result\.data\.\*\.data\.detected\_spam\.resultSet\.\*\.key | string |  |   unknown domain 
action\_result\.data\.\*\.data\.detected\_spam\.resultSet\.\*\.value | numeric |  |   0 
action\_result\.data\.\*\.data\.detected\_virus\.resultSet\.\*\.key | string |  |   unknown domain 
action\_result\.data\.\*\.data\.detected\_virus\.resultSet\.\*\.value | numeric |  |   0 
action\_result\.data\.\*\.data\.dns\_verified\.resultSet\.\*\.key | string |  |   unknown domain 
action\_result\.data\.\*\.data\.dns\_verified\.resultSet\.\*\.value | numeric |  |   0 
action\_result\.data\.\*\.data\.last\_sender\_group\.resultSet\.\*\.key | string |  |   unknown domain 
action\_result\.data\.\*\.data\.last\_sender\_group\.resultSet\.\*\.value | numeric |  |   0 
action\_result\.data\.\*\.data\.last\_sender\_group\_name\.resultSet\.\*\.key | string |  |   unknown domain 
action\_result\.data\.\*\.data\.last\_sender\_group\_name\.resultSet\.\*\.value | string |  |   UNKNOWNLIST 
action\_result\.data\.\*\.data\.marketing\_mail\.resultSet\.\*\.key | string |  |   unknown domain 
action\_result\.data\.\*\.data\.marketing\_mail\.resultSet\.\*\.value | numeric |  |   0 
action\_result\.data\.\*\.data\.resultSet\.auth\_disallow\.\* | string |  |  
action\_result\.data\.\*\.data\.resultSet\.auth\_fail\.\* | string |  |  
action\_result\.data\.\*\.data\.resultSet\.auth\_success\.\* | string |  |  
action\_result\.data\.\*\.data\.resultSet\.blocked\_dmarc\.\*\.key | string |  |   unknown domain 
action\_result\.data\.\*\.data\.resultSet\.blocked\_dmarc\.\*\.value | numeric |  |   0 
action\_result\.data\.\*\.data\.resultSet\.blocked\_invalid\_recipient\.\*\.count\.key | string |  |   unknown domain 
action\_result\.data\.\*\.data\.resultSet\.blocked\_invalid\_recipient\.\*\.count\.value | numeric |  |   0 
action\_result\.data\.\*\.data\.resultSet\.blocked\_invalid\_recipient\.\*\.key | string |  |   unknown domain 
action\_result\.data\.\*\.data\.resultSet\.blocked\_invalid\_recipient\.\*\.recipient | string |  |   10\.1\.16\.99 
action\_result\.data\.\*\.data\.resultSet\.blocked\_invalid\_recipient\.\*\.value | numeric |  |   0 
action\_result\.data\.\*\.data\.resultSet\.blocked\_reputation\.\*\.key | string |  |   unknown domain 
action\_result\.data\.\*\.data\.resultSet\.blocked\_reputation\.\*\.key | string |  |   unknown domain 
action\_result\.data\.\*\.data\.resultSet\.blocked\_reputation\.\*\.key | string |  |   unknown domain 
action\_result\.data\.\*\.data\.resultSet\.blocked\_reputation\.\*\.recipient | string |  |   10\.1\.16\.99 
action\_result\.data\.\*\.data\.resultSet\.blocked\_reputation\.\*\.value | numeric |  |   42 
action\_result\.data\.\*\.data\.resultSet\.blocked\_reputation\.\*\.value | numeric |  |   24 
action\_result\.data\.\*\.data\.resultSet\.blocked\_reputation\.\*\.value | numeric |  |   0 
action\_result\.data\.\*\.data\.resultSet\.blocked\_sdr\.\*\.count\.key | string |  |   unknown domain 
action\_result\.data\.\*\.data\.resultSet\.blocked\_sdr\.\*\.count\.value | numeric |  |   0 
action\_result\.data\.\*\.data\.resultSet\.blocked\_sdr\.\*\.key | string |  |   unknown domain 
action\_result\.data\.\*\.data\.resultSet\.blocked\_sdr\.\*\.recipient | string |  |   10\.1\.16\.99 
action\_result\.data\.\*\.data\.resultSet\.blocked\_sdr\.\*\.value | numeric |  |   0 
action\_result\.data\.\*\.data\.resultSet\.bulk\_mail\.\*\.count\.key | string |  |   unknown domain 
action\_result\.data\.\*\.data\.resultSet\.bulk\_mail\.\*\.count\.value | numeric |  |   0 
action\_result\.data\.\*\.data\.resultSet\.bulk\_mail\.\*\.key | string |  |   unknown domain 
action\_result\.data\.\*\.data\.resultSet\.bulk\_mail\.\*\.recipient | string |  |   10\.1\.16\.99 
action\_result\.data\.\*\.data\.resultSet\.bulk\_mail\.\*\.value | numeric |  |   0 
action\_result\.data\.\*\.data\.resultSet\.cert\_fail\.\* | string |  |  
action\_result\.data\.\*\.data\.resultSet\.cert\_fallback\_fail\.\* | string |  |  
action\_result\.data\.\*\.data\.resultSet\.cert\_fallback\_success\.\* | string |  |  
action\_result\.data\.\*\.data\.resultSet\.cert\_success\.\* | string |  |  
action\_result\.data\.\*\.data\.resultSet\.conn\_plain\.\* | string |  |  
action\_result\.data\.\*\.data\.resultSet\.conn\_tls\_fail\.\* | string |  |  
action\_result\.data\.\*\.data\.resultSet\.conn\_tls\_opt\_fail\.\* | string |  |  
action\_result\.data\.\*\.data\.resultSet\.conn\_tls\_opt\_success\.\* | string |  |  
action\_result\.data\.\*\.data\.resultSet\.conn\_tls\_success\.\* | string |  |  
action\_result\.data\.\*\.data\.resultSet\.conn\_tls\_total\.\* | string |  |  
action\_result\.data\.\*\.data\.resultSet\.detected\_amp\.\*\.count\.key | string |  |   unknown domain 
action\_result\.data\.\*\.data\.resultSet\.detected\_amp\.\*\.count\.value | numeric |  |   0 
action\_result\.data\.\*\.data\.resultSet\.detected\_amp\.\*\.key | string |  |   unknown domain 
action\_result\.data\.\*\.data\.resultSet\.detected\_amp\.\*\.recipient | string |  |   10\.1\.16\.99 
action\_result\.data\.\*\.data\.resultSet\.detected\_amp\.\*\.value | numeric |  |   0 
action\_result\.data\.\*\.data\.resultSet\.detected\_spam\.\* | string |  |  
action\_result\.data\.\*\.data\.resultSet\.detected\_spam\.\* | string |  |  
action\_result\.data\.\*\.data\.resultSet\.detected\_spam\.\*\.count\.key | string |  |   unknown domain 
action\_result\.data\.\*\.data\.resultSet\.detected\_spam\.\*\.count\.value | numeric |  |   0 
action\_result\.data\.\*\.data\.resultSet\.detected\_spam\.\*\.key | string |  |   unknown domain 
action\_result\.data\.\*\.data\.resultSet\.detected\_spam\.\*\.recipient | string |  |   10\.1\.16\.99 
action\_result\.data\.\*\.data\.resultSet\.detected\_spam\.\*\.value | numeric |  |   0 
action\_result\.data\.\*\.data\.resultSet\.detected\_virus\.\*\.count\.key | string |  |   unknown domain 
action\_result\.data\.\*\.data\.resultSet\.detected\_virus\.\*\.count\.value | numeric |  |   0 
action\_result\.data\.\*\.data\.resultSet\.detected\_virus\.\*\.key | string |  |   unknown domain 
action\_result\.data\.\*\.data\.resultSet\.detected\_virus\.\*\.recipient | string |  |   10\.1\.16\.99 
action\_result\.data\.\*\.data\.resultSet\.detected\_virus\.\*\.value | numeric |  |   0 
action\_result\.data\.\*\.data\.resultSet\.dns\_verified\.\*\.count\.key | string |  |   unknown domain 
action\_result\.data\.\*\.data\.resultSet\.dns\_verified\.\*\.count\.value | numeric |  |   0 
action\_result\.data\.\*\.data\.resultSet\.dns\_verified\.\*\.key | string |  |   unknown domain 
action\_result\.data\.\*\.data\.resultSet\.dns\_verified\.\*\.recipient | string |  |   10\.1\.16\.99 
action\_result\.data\.\*\.data\.resultSet\.dns\_verified\.\*\.value | numeric |  |   0 
action\_result\.data\.\*\.data\.resultSet\.encrypted\_tls\.\* | string |  |  
action\_result\.data\.\*\.data\.resultSet\.incoming\_bulk\_mail\.\* | string |  |  
action\_result\.data\.\*\.data\.resultSet\.incoming\_bulk\_mail\.\*\.count | numeric |  |   0 
action\_result\.data\.\*\.data\.resultSet\.incoming\_bulk\_mail\.\*\.recipient | string |  |   test\@user\.com 
action\_result\.data\.\*\.data\.resultSet\.incoming\_detected\_amp\.\* | string |  |  
action\_result\.data\.\*\.data\.resultSet\.incoming\_detected\_amp\.\*\.count | numeric |  |   0 
action\_result\.data\.\*\.data\.resultSet\.incoming\_detected\_amp\.\*\.recipient | string |  |   test\@user\.com 
action\_result\.data\.\*\.data\.resultSet\.incoming\_detected\_content\_filter\.\* | string |  |  
action\_result\.data\.\*\.data\.resultSet\.incoming\_detected\_content\_filter\.\*\.count | numeric |  |   0 
action\_result\.data\.\*\.data\.resultSet\.incoming\_detected\_content\_filter\.\*\.recipient | string |  |   test\@user\.com 
action\_result\.data\.\*\.data\.resultSet\.incoming\_detected\_ims\_spam\_increment\_over\_case\.\* | string |  |  
action\_result\.data\.\*\.data\.resultSet\.incoming\_detected\_ims\_spam\_increment\_over\_case\.\*\.count | numeric |  |   0 
action\_result\.data\.\*\.data\.resultSet\.incoming\_detected\_ims\_spam\_increment\_over\_case\.\*\.recipient | string |  |   test\@user\.com 
action\_result\.data\.\*\.data\.resultSet\.incoming\_detected\_spam\.\* | string |  |  
action\_result\.data\.\*\.data\.resultSet\.incoming\_detected\_spam\.\*\.count | numeric |  |   0 
action\_result\.data\.\*\.data\.resultSet\.incoming\_detected\_spam\.\*\.recipient | string |  |   test\@user\.com 
action\_result\.data\.\*\.data\.resultSet\.incoming\_detected\_virus\.\* | string |  |  
action\_result\.data\.\*\.data\.resultSet\.incoming\_detected\_virus\.\*\.count | numeric |  |   0 
action\_result\.data\.\*\.data\.resultSet\.incoming\_detected\_virus\.\*\.recipient | string |  |   test\@user\.com 
action\_result\.data\.\*\.data\.resultSet\.incoming\_graymail\.\* | string |  |  
action\_result\.data\.\*\.data\.resultSet\.incoming\_graymail\.\*\.count | numeric |  |   0 
action\_result\.data\.\*\.data\.resultSet\.incoming\_graymail\.\*\.recipient | string |  |   test\@user\.com 
action\_result\.data\.\*\.data\.resultSet\.incoming\_marketing\_mail\.\* | string |  |  
action\_result\.data\.\*\.data\.resultSet\.incoming\_marketing\_mail\.\*\.count | numeric |  |   0 
action\_result\.data\.\*\.data\.resultSet\.incoming\_marketing\_mail\.\*\.recipient | string |  |   test\@user\.com 
action\_result\.data\.\*\.data\.resultSet\.incoming\_social\_mail\.\* | string |  |  
action\_result\.data\.\*\.data\.resultSet\.incoming\_social\_mail\.\*\.count | numeric |  |   0 
action\_result\.data\.\*\.data\.resultSet\.incoming\_social\_mail\.\*\.recipient | string |  |   test\@user\.com 
action\_result\.data\.\*\.data\.resultSet\.incoming\_threat\_content\_filter\.\* | string |  |  
action\_result\.data\.\*\.data\.resultSet\.incoming\_threat\_content\_filter\.\*\.count | numeric |  |   0 
action\_result\.data\.\*\.data\.resultSet\.incoming\_threat\_content\_filter\.\*\.recipient | string |  |   test\@user\.com 
action\_result\.data\.\*\.data\.resultSet\.incoming\_total\_clean\_recipients\.\* | string |  |  
action\_result\.data\.\*\.data\.resultSet\.incoming\_total\_clean\_recipients\.\*\.count | numeric |  |   2 
action\_result\.data\.\*\.data\.resultSet\.incoming\_total\_clean\_recipients\.\*\.recipient | string |  |   test\@user\.com 
action\_result\.data\.\*\.data\.resultSet\.incoming\_total\_recipients\.\* | string |  |  
action\_result\.data\.\*\.data\.resultSet\.incoming\_total\_recipients\.\*\.count | numeric |  |   2 
action\_result\.data\.\*\.data\.resultSet\.incoming\_total\_recipients\.\*\.recipient | string |  |   test\@user\.com 
action\_result\.data\.\*\.data\.resultSet\.last\_sender\_group\.\*\.count\.key | string |  |   unknown domain 
action\_result\.data\.\*\.data\.resultSet\.last\_sender\_group\.\*\.count\.value | numeric |  |   0 
action\_result\.data\.\*\.data\.resultSet\.last\_sender\_group\.\*\.key | string |  |   unknown domain 
action\_result\.data\.\*\.data\.resultSet\.last\_sender\_group\.\*\.recipient | string |  |   10\.1\.16\.99 
action\_result\.data\.\*\.data\.resultSet\.last\_sender\_group\.\*\.value | numeric |  |   0 
action\_result\.data\.\*\.data\.resultSet\.last\_sender\_group\_name\.\*\.count\.key | string |  |   unknown domain 
action\_result\.data\.\*\.data\.resultSet\.last\_sender\_group\_name\.\*\.count\.value | string |  |   UNKNOWNLIST 
action\_result\.data\.\*\.data\.resultSet\.last\_sender\_group\_name\.\*\.key | string |  |   unknown domain 
action\_result\.data\.\*\.data\.resultSet\.last\_sender\_group\_name\.\*\.recipient | string |  |   10\.1\.16\.99 
action\_result\.data\.\*\.data\.resultSet\.last\_sender\_group\_name\.\*\.value | string |  |   UNKNOWNLIST 
action\_result\.data\.\*\.data\.resultSet\.marketing\_mail\.\*\.count\.key | string |  |   unknown domain 
action\_result\.data\.\*\.data\.resultSet\.marketing\_mail\.\*\.count\.value | numeric |  |   0 
action\_result\.data\.\*\.data\.resultSet\.marketing\_mail\.\*\.key | string |  |   unknown domain 
action\_result\.data\.\*\.data\.resultSet\.marketing\_mail\.\*\.recipient | string |  |   10\.1\.16\.99 
action\_result\.data\.\*\.data\.resultSet\.marketing\_mail\.\*\.value | numeric |  |   0 
action\_result\.data\.\*\.data\.resultSet\.noauth\.\* | string |  |  
action\_result\.data\.\*\.data\.resultSet\.outgoing\_detected\_amp\.\* | string |  |  
action\_result\.data\.\*\.data\.resultSet\.outgoing\_detected\_amp\.\*\.count | numeric |  |   0 
action\_result\.data\.\*\.data\.resultSet\.outgoing\_detected\_amp\.\*\.recipient | string |  |   test\@user\.com 
action\_result\.data\.\*\.data\.resultSet\.outgoing\_detected\_content\_filter\.\* | string |  |  
action\_result\.data\.\*\.data\.resultSet\.outgoing\_detected\_content\_filter\.\*\.count | numeric |  |   0 
action\_result\.data\.\*\.data\.resultSet\.outgoing\_detected\_content\_filter\.\*\.recipient | string |  |   test\@user\.com 
action\_result\.data\.\*\.data\.resultSet\.outgoing\_detected\_ims\_spam\_increment\_over\_case\.\* | string |  |  
action\_result\.data\.\*\.data\.resultSet\.outgoing\_detected\_ims\_spam\_increment\_over\_case\.\*\.count | numeric |  |   0 
action\_result\.data\.\*\.data\.resultSet\.outgoing\_detected\_ims\_spam\_increment\_over\_case\.\*\.recipient | string |  |   test\@user\.com 
action\_result\.data\.\*\.data\.resultSet\.outgoing\_detected\_spam\.\* | string |  |  
action\_result\.data\.\*\.data\.resultSet\.outgoing\_detected\_spam\.\*\.count | numeric |  |   0 
action\_result\.data\.\*\.data\.resultSet\.outgoing\_detected\_spam\.\*\.recipient | string |  |   test\@user\.com 
action\_result\.data\.\*\.data\.resultSet\.outgoing\_detected\_virus\.\* | string |  |  
action\_result\.data\.\*\.data\.resultSet\.outgoing\_detected\_virus\.\*\.count | numeric |  |   0 
action\_result\.data\.\*\.data\.resultSet\.outgoing\_detected\_virus\.\*\.recipient | string |  |   test\@user\.com 
action\_result\.data\.\*\.data\.resultSet\.outgoing\_threat\_content\_filter\.\* | string |  |  
action\_result\.data\.\*\.data\.resultSet\.outgoing\_threat\_content\_filter\.\*\.count | numeric |  |   0 
action\_result\.data\.\*\.data\.resultSet\.outgoing\_threat\_content\_filter\.\*\.recipient | string |  |   test\@user\.com 
action\_result\.data\.\*\.data\.resultSet\.outgoing\_total\_clean\_recipients\.\* | string |  |  
action\_result\.data\.\*\.data\.resultSet\.outgoing\_total\_clean\_recipients\.\*\.count | numeric |  |   0 
action\_result\.data\.\*\.data\.resultSet\.outgoing\_total\_clean\_recipients\.\*\.recipient | string |  |   test\@user\.com 
action\_result\.data\.\*\.data\.resultSet\.outgoing\_total\_recipients\.\* | string |  |  
action\_result\.data\.\*\.data\.resultSet\.outgoing\_total\_recipients\.\*\.count | numeric |  |   0 
action\_result\.data\.\*\.data\.resultSet\.outgoing\_total\_recipients\.\*\.recipient | string |  |   test\@user\.com 
action\_result\.data\.\*\.data\.resultSet\.sbrs\_score\.\*\.count\.key | string |  |   unknown domain 
action\_result\.data\.\*\.data\.resultSet\.sbrs\_score\.\*\.count\.value | numeric |  |   0 
action\_result\.data\.\*\.data\.resultSet\.sbrs\_score\.\*\.key | string |  |   unknown domain 
action\_result\.data\.\*\.data\.resultSet\.sbrs\_score\.\*\.recipient | string |  |   10\.1\.16\.99 
action\_result\.data\.\*\.data\.resultSet\.sbrs\_score\.\*\.value | numeric |  |   0 
action\_result\.data\.\*\.data\.resultSet\.social\_mail\.\* | string |  |  
action\_result\.data\.\*\.data\.resultSet\.social\_mail\.\* | string |  |  
action\_result\.data\.\*\.data\.resultSet\.social\_mail\.\*\.count\.key | string |  |   unknown domain 
action\_result\.data\.\*\.data\.resultSet\.social\_mail\.\*\.count\.value | numeric |  |   0 
action\_result\.data\.\*\.data\.resultSet\.social\_mail\.\*\.key | string |  |   unknown domain 
action\_result\.data\.\*\.data\.resultSet\.social\_mail\.\*\.recipient | string |  |   10\.1\.16\.99 
action\_result\.data\.\*\.data\.resultSet\.social\_mail\.\*\.value | numeric |  |   0 
action\_result\.data\.\*\.data\.resultSet\.threat\_content\_filter\.\* | string |  |  
action\_result\.data\.\*\.data\.resultSet\.threat\_content\_filter\.\*\.key | string |  |   unknown domain 
action\_result\.data\.\*\.data\.resultSet\.threat\_content\_filter\.\*\.recipient | string |  |   10\.1\.16\.99 
action\_result\.data\.\*\.data\.resultSet\.threat\_content\_filter\.\*\.value | numeric |  |   0 
action\_result\.data\.\*\.data\.resultSet\.total\.\* | string |  |  
action\_result\.data\.\*\.data\.resultSet\.total\_accepted\_connections\.\* | string |  |  
action\_result\.data\.\*\.data\.resultSet\.total\_clean\_recipients\.\* | string |  |  
action\_result\.data\.\*\.data\.resultSet\.total\_clean\_recipients\.\*\.count\.key | string |  |   unknown domain 
action\_result\.data\.\*\.data\.resultSet\.total\_clean\_recipients\.\*\.count\.value | numeric |  |   0 
action\_result\.data\.\*\.data\.resultSet\.total\_clean\_recipients\.\*\.key | string |  |   unknown domain 
action\_result\.data\.\*\.data\.resultSet\.total\_clean\_recipients\.\*\.recipient | string |  |   10\.1\.16\.99 
action\_result\.data\.\*\.data\.resultSet\.total\_clean\_recipients\.\*\.value | numeric |  |   0 
action\_result\.data\.\*\.data\.resultSet\.total\_graymail\_recipients\.\* | string |  |  
action\_result\.data\.\*\.data\.resultSet\.total\_graymail\_recipients\.\*\.count\.key | string |  |   unknown domain 
action\_result\.data\.\*\.data\.resultSet\.total\_graymail\_recipients\.\*\.count\.value | numeric |  |   0 
action\_result\.data\.\*\.data\.resultSet\.total\_graymail\_recipients\.\*\.key | string |  |   unknown domain 
action\_result\.data\.\*\.data\.resultSet\.total\_graymail\_recipients\.\*\.recipient | string |  |   10\.1\.16\.99 
action\_result\.data\.\*\.data\.resultSet\.total\_graymail\_recipients\.\*\.value | numeric |  |   0 
action\_result\.data\.\*\.data\.resultSet\.total\_recipients\.\* | string |  |  
action\_result\.data\.\*\.data\.resultSet\.total\_recipients\.\*\.count\.key | string |  |   unknown domain 
action\_result\.data\.\*\.data\.resultSet\.total\_recipients\.\*\.count\.value | numeric |  |   42 
action\_result\.data\.\*\.data\.resultSet\.total\_recipients\.\*\.key | string |  |   unknown domain 
action\_result\.data\.\*\.data\.resultSet\.total\_recipients\.\*\.recipient | string |  |   10\.1\.16\.99 
action\_result\.data\.\*\.data\.resultSet\.total\_recipients\.\*\.value | numeric |  |   42 
action\_result\.data\.\*\.data\.resultSet\.total\_rejected\_connections\.\* | string |  |  
action\_result\.data\.\*\.data\.resultSet\.total\_threat\_recipients\.\* | string |  |  
action\_result\.data\.\*\.data\.resultSet\.total\_threat\_recipients\.\*\.count\.key | string |  |   unknown domain 
action\_result\.data\.\*\.data\.resultSet\.total\_threat\_recipients\.\*\.count\.value | numeric |  |   42 
action\_result\.data\.\*\.data\.resultSet\.total\_threat\_recipients\.\*\.key | string |  |   unknown domain 
action\_result\.data\.\*\.data\.resultSet\.total\_threat\_recipients\.\*\.recipient | string |  |   10\.1\.16\.99 
action\_result\.data\.\*\.data\.resultSet\.total\_threat\_recipients\.\*\.value | numeric |  |   42 
action\_result\.data\.\*\.data\.resultSet\.total\_throttled\_recipients\.\* | string |  |  
action\_result\.data\.\*\.data\.sbrs\_score\.resultSet\.\*\.key | string |  |   unknown domain 
action\_result\.data\.\*\.data\.sbrs\_score\.resultSet\.\*\.value | numeric |  |   0 
action\_result\.data\.\*\.data\.social\_mail\.resultSet\.\*\.key | string |  |   unknown domain 
action\_result\.data\.\*\.data\.social\_mail\.resultSet\.\*\.value | numeric |  |   0 
action\_result\.data\.\*\.data\.threat\_content\_filter\.resultSet\.\*\.key | string |  |   unknown domain 
action\_result\.data\.\*\.data\.threat\_content\_filter\.resultSet\.\*\.value | numeric |  |   0 
action\_result\.data\.\*\.data\.total\_clean\_recipients\.resultSet\.\*\.key | string |  |   unknown domain 
action\_result\.data\.\*\.data\.total\_clean\_recipients\.resultSet\.\*\.value | numeric |  |   0 
action\_result\.data\.\*\.data\.total\_graymail\_recipients\.resultSet\.\*\.key | string |  |   unknown domain 
action\_result\.data\.\*\.data\.total\_graymail\_recipients\.resultSet\.\*\.value | numeric |  |   0 
action\_result\.data\.\*\.data\.total\_recipients\.resultSet\.\*\.key | string |  |   unknown domain 
action\_result\.data\.\*\.data\.total\_recipients\.resultSet\.\*\.value | numeric |  |   42 
action\_result\.data\.\*\.data\.total\_threat\_recipients\.resultSet\.\*\.key | string |  |   unknown domain 
action\_result\.data\.\*\.data\.total\_threat\_recipients\.resultSet\.\*\.value | numeric |  |   42 
action\_result\.data\.\*\.data\.type | string |  |   mail\_sender\_domain\_detail 
action\_result\.data\.\*\.mail\_incoming\_domain\_detail\.data\.blocked\_reputation\.\*\.count | numeric |  |   6702 
action\_result\.data\.\*\.mail\_incoming\_domain\_detail\.data\.blocked\_reputation\.\*\.recipient | string |  |   unknown domain 
action\_result\.data\.\*\.mail\_incoming\_domain\_detail\.data\.total\_recipients\.\*\.count | numeric |  |   6702 
action\_result\.data\.\*\.mail\_incoming\_domain\_detail\.data\.total\_recipients\.\*\.recipient | string |  |   unknown domain 
action\_result\.data\.\*\.mail\_incoming\_domain\_detail\.data\.total\_rejected\_connections\.\*\.count | numeric |  |   2234 
action\_result\.data\.\*\.mail\_incoming\_domain\_detail\.data\.total\_rejected\_connections\.\*\.recipient | string |  |   unknown domain 
action\_result\.data\.\*\.mail\_incoming\_domain\_detail\.data\.total\_threat\_recipients\.\*\.count | numeric |  |   6702 
action\_result\.data\.\*\.mail\_incoming\_domain\_detail\.data\.total\_threat\_recipients\.\*\.recipient | string |  |   unknown domain 
action\_result\.data\.\*\.mail\_incoming\_domain\_detail\.uri | string |  |   /api/v1\.0/stats/mail\_incoming\_domain\_detail?duration=2021\-07\-30T12%3A00%2B00%3A00%2F2022\-04\-05T12%3A00%2B00%3A00&max=10 
action\_result\.data\.\*\.mail\_users\_detail\.uri | string |  |   /api/v1\.0/stats/mail\_users\_detail?duration=2021\-07\-31T10%3A00%2B00%3A00%2F2022\-04\-06T10%3A00%2B00%3A00&max=10 
action\_result\.data\.\*\.meta\.totalCount | numeric |  |   -1 
action\_result\.summary | string |  |  
action\_result\.message | string |  |   Report queried successfully 
summary\.total\_objects | numeric |  |   12 
summary\.total\_objects\_successful | numeric |  |   34   

## action: 'list dictionary items'
List all entries of an ESA dictionary

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**name** |  required  | Name of dictionary to list | string |  `ciscoesa dictionary name` 
**cluster\_mode** |  optional  | Enable machine mode as cluster on ESA | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action\_result\.status | string |  |   success  failed 
action\_result\.parameter\.cluster\_mode | boolean |  |   True  False 
action\_result\.parameter\.name | string |  `ciscoesa dictionary name`  |   Mail\_To 
action\_result\.data\.\*\.value | string |  `ciscoesa item value`  |   test\@user\.com 
action\_result\.data\.\*\.weight | string |  |    1 
action\_result\.summary\.total\_items | numeric |  |   36 
action\_result\.message | string |  |   Successfully listed all entries of dictionary 
summary\.total\_objects | numeric |  |   1 
summary\.total\_objects\_successful | numeric |  |   1   

## action: 'add dictionary item'
Add an entry to an ESA dictionary

Type: **contain**  
Read only: **False**

Per the documentation, the action will handle escaping special regex character prior to adding to the dictionary\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**name** |  required  | Name of dictionary to add an item to | string |  `ciscoesa dictionary name` 
**value** |  required  | Value of entry to add to dictionary | string |  `ciscoesa item value` 
**commit\_message** |  required  | Commit message to add the item to the dictionary on the server at the end of this action | string | 
**cluster\_mode** |  optional  | Enable machine mode as cluster on ESA | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action\_result\.status | string |  |   success  failed 
action\_result\.parameter\.cluster\_mode | boolean |  |   True  False 
action\_result\.parameter\.commit\_message | string |  |   This is a test message 
action\_result\.parameter\.name | string |  `ciscoesa dictionary name`  |   test\_dict 
action\_result\.parameter\.value | string |  `ciscoesa item value`  |   test\_value 
action\_result\.data\.\*\.message | string |  |   Successfully added entry to dictionary 
action\_result\.summary\.status | string |  |   Successfully added entry to dictionary 
action\_result\.message | string |  |   Successfully added entry to dictionary 
summary\.total\_objects | numeric |  |   1 
summary\.total\_objects\_successful | numeric |  |   1   

## action: 'remove dictionary item'
Remove an entry from an ESA dictionary

Type: **correct**  
Read only: **False**

Per the documentation, the action will handle escaping special regex character prior to removing from the dictionary\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**name** |  required  | Name of dictionary to remove an item from | string |  `ciscoesa dictionary name` 
**value** |  required  | Value of entry to remove from dictionary | string |  `ciscoesa item value` 
**commit\_message** |  required  | Commit message to remove the item from the dictionary on the server at the end of this action | string | 
**cluster\_mode** |  optional  | Enable machine mode as cluster on ESA | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action\_result\.status | string |  |   success  failed 
action\_result\.parameter\.cluster\_mode | boolean |  |   True  False 
action\_result\.parameter\.commit\_message | string |  |   This is a test message 
action\_result\.parameter\.name | string |  `ciscoesa dictionary name`  |   test\_dict 
action\_result\.parameter\.value | string |  `ciscoesa item value`  |   test\_value 
action\_result\.data\.\*\.message | string |  |   Successfully removed entry from dictionary 
action\_result\.summary\.status | string |  |   Successfully removed entry from dictionary 
action\_result\.message | string |  |   Successfully removed entry from dictionary 
summary\.total\_objects | numeric |  |   1 
summary\.total\_objects\_successful | numeric |  |   1 