[comment]: # "Auto-generated SOAR connector documentation"
# Cisco ESA

Publisher: Splunk  
Connector Version: 2\.0\.5  
Product Vendor: Cisco  
Product Name: Cisco ESA  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5\.1\.0  

This app supports investigation on the Cisco Email Security Appliance \(ESA\) device

### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Cisco ESA asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**url** |  required  | string | URL \(e\.g\. https\://10\.10\.10\.10\:6443\)
**verify\_server\_cert** |  optional  | boolean | Verify server certificate
**username** |  required  | string | Username
**password** |  required  | password | Password

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate credentials provided for connectivity  
[decode url](#action-decode-url) - Process Cisco encoded URL  
[get report](#action-get-report) - Retrieve statistical reports from ESA  

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
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.encoded\_url | string |  `url`  `encoded url` 
action\_result\.data\.\*\.decoded\_url | string |  `url` 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get report'
Retrieve statistical reports from ESA

Type: **investigate**  
Read only: **True**

This action is used to query "Query\-based Reports" which counts various events in your appliance against a user\-specified entity such as IP address, domain name, etc\. for a specified duration\.<br>If <b>start\_time</b> and <b>end\_time</b> are not given, then the report will be queried for the last 250 days\.<br>If either <b>start\_time</b> or <b>end\_time</b> is provided, then the report will be queried for 250 days relative to the given parameter\.<br>Following is the mapping of the report title and its corresponding entity that can be provided to filter reports\:<table><tbody><tr class='plain'><th>Report Title</th><th>Entity Value</th></tr><tr><td>Internal Users</td><td>Email ID of the internal user \(e\.g\. user\@example\.com\)</td></tr><tr><td>Incoming Mail\: Domains</td><td>Domain name \(e\.g\. abc\.com\)</td></tr><tr><td>Incoming Mail\: IP Addresses</td><td>IPv4 or IPv6 address</td></tr><tr><td>Incoming Mail\: Network Owners</td><td>Name of the network owner \(e\.g\. Xyz Corporation\)</td></tr><tr><td>Outgoing Senders\: Domains</td><td>Domain name \(e\.g\. abc\.com\)</td></tr><tr><td>Outgoing Senders\: IP Addresses</td><td>IPv4 or IPv6 address</td></tr><tr><td>Outgoing Destinations</td><td>Domain name \(e\.g\. abc\.com\)</td></tr><tr><td>Outgoing Content Filters</td><td>Name of the outgoing Content Filter</td></tr><tr><td>Virus Types</td><td>Name of virus</td></tr><tr><td>Inbound SMTP Authentication</td><td>Domain name \(e\.g\. abc\.com\)</td></tr><tr><td>Data Loss Prevention \(DLP\) Outgoing Policy</td><td>Name of the DLP policy</td></tr></tbody></table><br>The action supports limiting the number of items returned using the <b>limit</b> parameter\. If the <b>limit</b> parameter is 0, then the action will fetch no data for the selected report\(s\)\. If the limit is not specified, the action will fetch by default 10 items for all specified reports\. For a particular report, if the limit specified is greater than the available data, the action will fetch all data for that report\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**report\_title** |  required  | Report Title | string |  `ciscoesa report title` 
**search\_value** |  optional  | Entity value to filter the results | string | 
**start\_time** |  optional  | Start time \(YYYY\-MM\-DDTHH\:00\) | string | 
**end\_time** |  optional  | End time \(YYYY\-MM\-DDTHH\:00\) | string | 
**limit** |  optional  | Maximum number of items to retrieve | numeric | 
**starts\_with** |  optional  | Retrieve items starting with specified entity value | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.end\_time | string | 
action\_result\.parameter\.limit | numeric | 
action\_result\.parameter\.report\_title | string |  `ciscoesa report title` 
action\_result\.parameter\.search\_value | string | 
action\_result\.parameter\.start\_time | string | 
action\_result\.parameter\.starts\_with | boolean | 
action\_result\.data\.\*\.mail\_authentication\_incoming\_domain\.data\.auth\_disallow\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_authentication\_incoming\_domain\.data\.auth\_disallow\.\*\.recipient | string |  `domain` 
action\_result\.data\.\*\.mail\_authentication\_incoming\_domain\.data\.auth\_fail\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_authentication\_incoming\_domain\.data\.auth\_fail\.\*\.recipient | string |  `domain` 
action\_result\.data\.\*\.mail\_authentication\_incoming\_domain\.data\.auth\_success\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_authentication\_incoming\_domain\.data\.auth\_success\.\*\.recipient | string |  `domain` 
action\_result\.data\.\*\.mail\_authentication\_incoming\_domain\.data\.cert\_fail\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_authentication\_incoming\_domain\.data\.cert\_fail\.\*\.recipient | string |  `domain` 
action\_result\.data\.\*\.mail\_authentication\_incoming\_domain\.data\.cert\_fallback\_fail\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_authentication\_incoming\_domain\.data\.cert\_fallback\_fail\.\*\.recipient | string |  `domain` 
action\_result\.data\.\*\.mail\_authentication\_incoming\_domain\.data\.cert\_fallback\_success\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_authentication\_incoming\_domain\.data\.cert\_fallback\_success\.\*\.recipient | string |  `domain` 
action\_result\.data\.\*\.mail\_authentication\_incoming\_domain\.data\.cert\_success\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_authentication\_incoming\_domain\.data\.cert\_success\.\*\.recipient | string |  `domain` 
action\_result\.data\.\*\.mail\_authentication\_incoming\_domain\.data\.noauth\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_authentication\_incoming\_domain\.data\.noauth\.\*\.recipient | string |  `domain` 
action\_result\.data\.\*\.mail\_authentication\_incoming\_domain\.data\.total\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_authentication\_incoming\_domain\.data\.total\.\*\.recipient | string |  `domain` 
action\_result\.data\.\*\.mail\_authentication\_incoming\_domain\.uri | string | 
action\_result\.data\.\*\.mail\_content\_filter\_outgoing\.data\.recipients\_matched\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_content\_filter\_outgoing\.data\.recipients\_matched\.\*\.recipient | string | 
action\_result\.data\.\*\.mail\_content\_filter\_outgoing\.uri | string | 
action\_result\.data\.\*\.mail\_destination\_domain\_detail\.data\.conn\_last\_tls\_status\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_destination\_domain\_detail\.data\.conn\_last\_tls\_status\.\*\.recipient | string |  `domain` 
action\_result\.data\.\*\.mail\_destination\_domain\_detail\.data\.conn\_plain\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_destination\_domain\_detail\.data\.conn\_plain\.\*\.recipient | string |  `domain` 
action\_result\.data\.\*\.mail\_destination\_domain\_detail\.data\.conn\_tls\_fail\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_destination\_domain\_detail\.data\.conn\_tls\_fail\.\*\.recipient | string |  `domain` 
action\_result\.data\.\*\.mail\_destination\_domain\_detail\.data\.conn\_tls\_opt\_fail\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_destination\_domain\_detail\.data\.conn\_tls\_opt\_fail\.\*\.recipient | string |  `domain` 
action\_result\.data\.\*\.mail\_destination\_domain\_detail\.data\.conn\_tls\_opt\_success\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_destination\_domain\_detail\.data\.conn\_tls\_opt\_success\.\*\.recipient | string |  `domain` 
action\_result\.data\.\*\.mail\_destination\_domain\_detail\.data\.conn\_tls\_success\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_destination\_domain\_detail\.data\.conn\_tls\_success\.\*\.recipient | string |  `domain` 
action\_result\.data\.\*\.mail\_destination\_domain\_detail\.data\.conn\_tls\_total\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_destination\_domain\_detail\.data\.conn\_tls\_total\.\*\.recipient | string |  `domain` 
action\_result\.data\.\*\.mail\_destination\_domain\_detail\.data\.delivered\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_destination\_domain\_detail\.data\.delivered\.\*\.recipient | string |  `domain` 
action\_result\.data\.\*\.mail\_destination\_domain\_detail\.data\.detected\_spam\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_destination\_domain\_detail\.data\.detected\_spam\.\*\.recipient | string |  `domain` 
action\_result\.data\.\*\.mail\_destination\_domain\_detail\.data\.detected\_virus\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_destination\_domain\_detail\.data\.detected\_virus\.\*\.recipient | string |  `domain` 
action\_result\.data\.\*\.mail\_destination\_domain\_detail\.data\.encrypted\_tls\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_destination\_domain\_detail\.data\.encrypted\_tls\.\*\.recipient | string |  `domain` 
action\_result\.data\.\*\.mail\_destination\_domain\_detail\.data\.hard\_bounces\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_destination\_domain\_detail\.data\.hard\_bounces\.\*\.recipient | string |  `domain` 
action\_result\.data\.\*\.mail\_destination\_domain\_detail\.data\.threat\_content\_filter\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_destination\_domain\_detail\.data\.threat\_content\_filter\.\*\.recipient | string |  `domain` 
action\_result\.data\.\*\.mail\_destination\_domain\_detail\.data\.total\_clean\_recipients\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_destination\_domain\_detail\.data\.total\_clean\_recipients\.\*\.recipient | string |  `domain` 
action\_result\.data\.\*\.mail\_destination\_domain\_detail\.data\.total\_recipients\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_destination\_domain\_detail\.data\.total\_recipients\.\*\.recipient | string |  `domain` 
action\_result\.data\.\*\.mail\_destination\_domain\_detail\.data\.total\_recipients\_processed\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_destination\_domain\_detail\.data\.total\_recipients\_processed\.\*\.recipient | string |  `domain` 
action\_result\.data\.\*\.mail\_destination\_domain\_detail\.data\.total\_threat\_recipients\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_destination\_domain\_detail\.data\.total\_threat\_recipients\.\*\.recipient | string |  `domain` 
action\_result\.data\.\*\.mail\_destination\_domain\_detail\.uri | string | 
action\_result\.data\.\*\.mail\_dlp\_outgoing\_policy\_detail\.data\.dlp\_action\_delivered\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_dlp\_outgoing\_policy\_detail\.data\.dlp\_action\_delivered\.\*\.recipient | string | 
action\_result\.data\.\*\.mail\_dlp\_outgoing\_policy\_detail\.data\.dlp\_action\_dropped\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_dlp\_outgoing\_policy\_detail\.data\.dlp\_action\_dropped\.\*\.recipient | string | 
action\_result\.data\.\*\.mail\_dlp\_outgoing\_policy\_detail\.data\.dlp\_action\_encrypted\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_dlp\_outgoing\_policy\_detail\.data\.dlp\_action\_encrypted\.\*\.recipient | string | 
action\_result\.data\.\*\.mail\_dlp\_outgoing\_policy\_detail\.data\.dlp\_incidents\_critical\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_dlp\_outgoing\_policy\_detail\.data\.dlp\_incidents\_critical\.\*\.recipient | string | 
action\_result\.data\.\*\.mail\_dlp\_outgoing\_policy\_detail\.data\.dlp\_incidents\_high\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_dlp\_outgoing\_policy\_detail\.data\.dlp\_incidents\_high\.\*\.recipient | string | 
action\_result\.data\.\*\.mail\_dlp\_outgoing\_policy\_detail\.data\.dlp\_incidents\_low\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_dlp\_outgoing\_policy\_detail\.data\.dlp\_incidents\_low\.\*\.recipient | string | 
action\_result\.data\.\*\.mail\_dlp\_outgoing\_policy\_detail\.data\.dlp\_incidents\_medium\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_dlp\_outgoing\_policy\_detail\.data\.dlp\_incidents\_medium\.\*\.recipient | string | 
action\_result\.data\.\*\.mail\_dlp\_outgoing\_policy\_detail\.data\.total\_dlp\_incidents\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_dlp\_outgoing\_policy\_detail\.data\.total\_dlp\_incidents\.\*\.recipient | string | 
action\_result\.data\.\*\.mail\_dlp\_outgoing\_policy\_detail\.uri | string | 
action\_result\.data\.\*\.mail\_incoming\_domain\_detail\.data\.blocked\_dmarc\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_incoming\_domain\_detail\.data\.blocked\_dmarc\.\*\.recipient | string |  `domain` 
action\_result\.data\.\*\.mail\_incoming\_domain\_detail\.data\.blocked\_invalid\_recipient\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_incoming\_domain\_detail\.data\.blocked\_invalid\_recipient\.\*\.recipient | string |  `domain` 
action\_result\.data\.\*\.mail\_incoming\_domain\_detail\.data\.blocked\_reputation\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_incoming\_domain\_detail\.data\.blocked\_reputation\.\*\.recipient | string |  `domain` 
action\_result\.data\.\*\.mail\_incoming\_domain\_detail\.data\.bulk\_mail\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_incoming\_domain\_detail\.data\.bulk\_mail\.\*\.recipient | string |  `domain` 
action\_result\.data\.\*\.mail\_incoming\_domain\_detail\.data\.conn\_plain\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_incoming\_domain\_detail\.data\.conn\_plain\.\*\.recipient | string |  `domain` 
action\_result\.data\.\*\.mail\_incoming\_domain\_detail\.data\.conn\_tls\_fail\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_incoming\_domain\_detail\.data\.conn\_tls\_fail\.\*\.recipient | string |  `domain` 
action\_result\.data\.\*\.mail\_incoming\_domain\_detail\.data\.conn\_tls\_opt\_fail\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_incoming\_domain\_detail\.data\.conn\_tls\_opt\_fail\.\*\.recipient | string |  `domain` 
action\_result\.data\.\*\.mail\_incoming\_domain\_detail\.data\.conn\_tls\_opt\_success\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_incoming\_domain\_detail\.data\.conn\_tls\_opt\_success\.\*\.recipient | string |  `domain` 
action\_result\.data\.\*\.mail\_incoming\_domain\_detail\.data\.conn\_tls\_success\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_incoming\_domain\_detail\.data\.conn\_tls\_success\.\*\.recipient | string |  `domain` 
action\_result\.data\.\*\.mail\_incoming\_domain\_detail\.data\.conn\_tls\_total\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_incoming\_domain\_detail\.data\.conn\_tls\_total\.\*\.recipient | string |  `domain` 
action\_result\.data\.\*\.mail\_incoming\_domain\_detail\.data\.detected\_amp\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_incoming\_domain\_detail\.data\.detected\_amp\.\*\.recipient | string |  `domain` 
action\_result\.data\.\*\.mail\_incoming\_domain\_detail\.data\.detected\_spam\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_incoming\_domain\_detail\.data\.detected\_spam\.\*\.recipient | string |  `domain` 
action\_result\.data\.\*\.mail\_incoming\_domain\_detail\.data\.detected\_virus\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_incoming\_domain\_detail\.data\.detected\_virus\.\*\.recipient | string |  `domain` 
action\_result\.data\.\*\.mail\_incoming\_domain\_detail\.data\.encrypted\_tls\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_incoming\_domain\_detail\.data\.encrypted\_tls\.\*\.recipient | string |  `domain` 
action\_result\.data\.\*\.mail\_incoming\_domain\_detail\.data\.marketing\_mail\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_incoming\_domain\_detail\.data\.marketing\_mail\.\*\.recipient | string |  `domain` 
action\_result\.data\.\*\.mail\_incoming\_domain\_detail\.data\.social\_mail\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_incoming\_domain\_detail\.data\.social\_mail\.\*\.recipient | string |  `domain` 
action\_result\.data\.\*\.mail\_incoming\_domain\_detail\.data\.threat\_content\_filter\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_incoming\_domain\_detail\.data\.threat\_content\_filter\.\*\.recipient | string |  `domain` 
action\_result\.data\.\*\.mail\_incoming\_domain\_detail\.data\.total\_accepted\_connections\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_incoming\_domain\_detail\.data\.total\_accepted\_connections\.\*\.recipient | string |  `domain` 
action\_result\.data\.\*\.mail\_incoming\_domain\_detail\.data\.total\_clean\_recipients\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_incoming\_domain\_detail\.data\.total\_clean\_recipients\.\*\.recipient | string |  `domain` 
action\_result\.data\.\*\.mail\_incoming\_domain\_detail\.data\.total\_graymail\_recipients\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_incoming\_domain\_detail\.data\.total\_graymail\_recipients\.\*\.recipient | string |  `domain` 
action\_result\.data\.\*\.mail\_incoming\_domain\_detail\.data\.total\_recipients\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_incoming\_domain\_detail\.data\.total\_recipients\.\*\.recipient | string |  `domain` 
action\_result\.data\.\*\.mail\_incoming\_domain\_detail\.data\.total\_rejected\_connections\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_incoming\_domain\_detail\.data\.total\_rejected\_connections\.\*\.recipient | string |  `domain` 
action\_result\.data\.\*\.mail\_incoming\_domain\_detail\.data\.total\_threat\_recipients\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_incoming\_domain\_detail\.data\.total\_threat\_recipients\.\*\.recipient | string |  `domain` 
action\_result\.data\.\*\.mail\_incoming\_domain\_detail\.data\.total\_throttled\_recipients\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_incoming\_domain\_detail\.data\.total\_throttled\_recipients\.\*\.recipient | string |  `domain` 
action\_result\.data\.\*\.mail\_incoming\_domain\_detail\.uri | string | 
action\_result\.data\.\*\.mail\_incoming\_ip\_hostname\_detail\.data\.blocked\_dmarc\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_incoming\_ip\_hostname\_detail\.data\.blocked\_dmarc\.\*\.recipient | string |  `ip` 
action\_result\.data\.\*\.mail\_incoming\_ip\_hostname\_detail\.data\.blocked\_invalid\_recipient\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_incoming\_ip\_hostname\_detail\.data\.blocked\_invalid\_recipient\.\*\.recipient | string |  `ip` 
action\_result\.data\.\*\.mail\_incoming\_ip\_hostname\_detail\.data\.blocked\_reputation\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_incoming\_ip\_hostname\_detail\.data\.blocked\_reputation\.\*\.recipient | string |  `ip` 
action\_result\.data\.\*\.mail\_incoming\_ip\_hostname\_detail\.data\.bulk\_mail\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_incoming\_ip\_hostname\_detail\.data\.bulk\_mail\.\*\.recipient | string |  `ip` 
action\_result\.data\.\*\.mail\_incoming\_ip\_hostname\_detail\.data\.detected\_amp\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_incoming\_ip\_hostname\_detail\.data\.detected\_amp\.\*\.recipient | string |  `ip` 
action\_result\.data\.\*\.mail\_incoming\_ip\_hostname\_detail\.data\.detected\_spam\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_incoming\_ip\_hostname\_detail\.data\.detected\_spam\.\*\.recipient | string |  `ip` 
action\_result\.data\.\*\.mail\_incoming\_ip\_hostname\_detail\.data\.detected\_virus\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_incoming\_ip\_hostname\_detail\.data\.detected\_virus\.\*\.recipient | string |  `ip` 
action\_result\.data\.\*\.mail\_incoming\_ip\_hostname\_detail\.data\.dns\_verified\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_incoming\_ip\_hostname\_detail\.data\.dns\_verified\.\*\.recipient | string |  `ip` 
action\_result\.data\.\*\.mail\_incoming\_ip\_hostname\_detail\.data\.last\_sender\_group\_name\.\*\.count | string | 
action\_result\.data\.\*\.mail\_incoming\_ip\_hostname\_detail\.data\.last\_sender\_group\_name\.\*\.recipient | string |  `ip` 
action\_result\.data\.\*\.mail\_incoming\_ip\_hostname\_detail\.data\.marketing\_mail\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_incoming\_ip\_hostname\_detail\.data\.marketing\_mail\.\*\.recipient | string |  `ip` 
action\_result\.data\.\*\.mail\_incoming\_ip\_hostname\_detail\.data\.sbrs\_score\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_incoming\_ip\_hostname\_detail\.data\.sbrs\_score\.\*\.recipient | string |  `ip` 
action\_result\.data\.\*\.mail\_incoming\_ip\_hostname\_detail\.data\.social\_mail\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_incoming\_ip\_hostname\_detail\.data\.social\_mail\.\*\.recipient | string |  `ip` 
action\_result\.data\.\*\.mail\_incoming\_ip\_hostname\_detail\.data\.threat\_content\_filter\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_incoming\_ip\_hostname\_detail\.data\.threat\_content\_filter\.\*\.recipient | string |  `ip` 
action\_result\.data\.\*\.mail\_incoming\_ip\_hostname\_detail\.data\.total\_clean\_recipients\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_incoming\_ip\_hostname\_detail\.data\.total\_clean\_recipients\.\*\.recipient | string |  `ip` 
action\_result\.data\.\*\.mail\_incoming\_ip\_hostname\_detail\.data\.total\_graymail\_recipients\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_incoming\_ip\_hostname\_detail\.data\.total\_graymail\_recipients\.\*\.recipient | string |  `ip` 
action\_result\.data\.\*\.mail\_incoming\_ip\_hostname\_detail\.data\.total\_recipients\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_incoming\_ip\_hostname\_detail\.data\.total\_recipients\.\*\.recipient | string |  `ip` 
action\_result\.data\.\*\.mail\_incoming\_ip\_hostname\_detail\.data\.total\_threat\_recipients\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_incoming\_ip\_hostname\_detail\.data\.total\_threat\_recipients\.\*\.recipient | string |  `ip` 
action\_result\.data\.\*\.mail\_incoming\_ip\_hostname\_detail\.uri | string | 
action\_result\.data\.\*\.mail\_incoming\_network\_detail\.data\.blocked\_dmarc\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_incoming\_network\_detail\.data\.blocked\_dmarc\.\*\.recipient | string | 
action\_result\.data\.\*\.mail\_incoming\_network\_detail\.data\.blocked\_invalid\_recipient\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_incoming\_network\_detail\.data\.blocked\_invalid\_recipient\.\*\.recipient | string | 
action\_result\.data\.\*\.mail\_incoming\_network\_detail\.data\.blocked\_reputation\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_incoming\_network\_detail\.data\.blocked\_reputation\.\*\.recipient | string | 
action\_result\.data\.\*\.mail\_incoming\_network\_detail\.data\.bulk\_mail\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_incoming\_network\_detail\.data\.bulk\_mail\.\*\.recipient | string | 
action\_result\.data\.\*\.mail\_incoming\_network\_detail\.data\.detected\_amp\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_incoming\_network\_detail\.data\.detected\_amp\.\*\.recipient | string | 
action\_result\.data\.\*\.mail\_incoming\_network\_detail\.data\.detected\_spam\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_incoming\_network\_detail\.data\.detected\_spam\.\*\.recipient | string | 
action\_result\.data\.\*\.mail\_incoming\_network\_detail\.data\.detected\_virus\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_incoming\_network\_detail\.data\.detected\_virus\.\*\.recipient | string | 
action\_result\.data\.\*\.mail\_incoming\_network\_detail\.data\.marketing\_mail\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_incoming\_network\_detail\.data\.marketing\_mail\.\*\.recipient | string | 
action\_result\.data\.\*\.mail\_incoming\_network\_detail\.data\.social\_mail\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_incoming\_network\_detail\.data\.social\_mail\.\*\.recipient | string | 
action\_result\.data\.\*\.mail\_incoming\_network\_detail\.data\.threat\_content\_filter\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_incoming\_network\_detail\.data\.threat\_content\_filter\.\*\.recipient | string | 
action\_result\.data\.\*\.mail\_incoming\_network\_detail\.data\.total\_accepted\_connections\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_incoming\_network\_detail\.data\.total\_accepted\_connections\.\*\.recipient | string | 
action\_result\.data\.\*\.mail\_incoming\_network\_detail\.data\.total\_clean\_recipients\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_incoming\_network\_detail\.data\.total\_clean\_recipients\.\*\.recipient | string | 
action\_result\.data\.\*\.mail\_incoming\_network\_detail\.data\.total\_graymail\_recipients\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_incoming\_network\_detail\.data\.total\_graymail\_recipients\.\*\.recipient | string | 
action\_result\.data\.\*\.mail\_incoming\_network\_detail\.data\.total\_recipients\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_incoming\_network\_detail\.data\.total\_recipients\.\*\.recipient | string | 
action\_result\.data\.\*\.mail\_incoming\_network\_detail\.data\.total\_rejected\_connections\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_incoming\_network\_detail\.data\.total\_rejected\_connections\.\*\.recipient | string | 
action\_result\.data\.\*\.mail\_incoming\_network\_detail\.data\.total\_threat\_recipients\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_incoming\_network\_detail\.data\.total\_threat\_recipients\.\*\.recipient | string | 
action\_result\.data\.\*\.mail\_incoming\_network\_detail\.data\.total\_throttled\_recipients\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_incoming\_network\_detail\.data\.total\_throttled\_recipients\.\*\.recipient | string | 
action\_result\.data\.\*\.mail\_incoming\_network\_detail\.uri | string | 
action\_result\.data\.\*\.mail\_sender\_domain\_detail\.data\.detected\_spam\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_sender\_domain\_detail\.data\.detected\_spam\.\*\.recipient | string |  `domain` 
action\_result\.data\.\*\.mail\_sender\_domain\_detail\.data\.detected\_virus\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_sender\_domain\_detail\.data\.detected\_virus\.\*\.recipient | string |  `domain` 
action\_result\.data\.\*\.mail\_sender\_domain\_detail\.data\.threat\_content\_filter\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_sender\_domain\_detail\.data\.threat\_content\_filter\.\*\.recipient | string |  `domain` 
action\_result\.data\.\*\.mail\_sender\_domain\_detail\.data\.total\_clean\_recipients\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_sender\_domain\_detail\.data\.total\_clean\_recipients\.\*\.recipient | string |  `domain` 
action\_result\.data\.\*\.mail\_sender\_domain\_detail\.data\.total\_dlp\_incidents\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_sender\_domain\_detail\.data\.total\_dlp\_incidents\.\*\.recipient | string |  `domain` 
action\_result\.data\.\*\.mail\_sender\_domain\_detail\.data\.total\_recipients\_processed\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_sender\_domain\_detail\.data\.total\_recipients\_processed\.\*\.recipient | string |  `domain` 
action\_result\.data\.\*\.mail\_sender\_domain\_detail\.data\.total\_threat\_recipients\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_sender\_domain\_detail\.data\.total\_threat\_recipients\.\*\.recipient | string |  `domain` 
action\_result\.data\.\*\.mail\_sender\_domain\_detail\.uri | string | 
action\_result\.data\.\*\.mail\_sender\_ip\_hostname\_detail\.data\.detected\_spam\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_sender\_ip\_hostname\_detail\.data\.detected\_spam\.\*\.recipient | string |  `ip` 
action\_result\.data\.\*\.mail\_sender\_ip\_hostname\_detail\.data\.detected\_virus\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_sender\_ip\_hostname\_detail\.data\.detected\_virus\.\*\.recipient | string |  `ip` 
action\_result\.data\.\*\.mail\_sender\_ip\_hostname\_detail\.data\.threat\_content\_filter\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_sender\_ip\_hostname\_detail\.data\.threat\_content\_filter\.\*\.recipient | string |  `ip` 
action\_result\.data\.\*\.mail\_sender\_ip\_hostname\_detail\.data\.total\_clean\_recipients\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_sender\_ip\_hostname\_detail\.data\.total\_clean\_recipients\.\*\.recipient | string |  `ip` 
action\_result\.data\.\*\.mail\_sender\_ip\_hostname\_detail\.data\.total\_dlp\_incidents\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_sender\_ip\_hostname\_detail\.data\.total\_dlp\_incidents\.\*\.recipient | string |  `ip` 
action\_result\.data\.\*\.mail\_sender\_ip\_hostname\_detail\.data\.total\_recipients\_processed\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_sender\_ip\_hostname\_detail\.data\.total\_recipients\_processed\.\*\.recipient | string |  `ip` 
action\_result\.data\.\*\.mail\_sender\_ip\_hostname\_detail\.data\.total\_threat\_recipients\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_sender\_ip\_hostname\_detail\.data\.total\_threat\_recipients\.\*\.recipient | string |  `ip` 
action\_result\.data\.\*\.mail\_sender\_ip\_hostname\_detail\.uri | string | 
action\_result\.data\.\*\.mail\_users\_detail\.data\.incoming\_bulk\_mail\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_users\_detail\.data\.incoming\_bulk\_mail\.\*\.recipient | string |  `email` 
action\_result\.data\.\*\.mail\_users\_detail\.data\.incoming\_detected\_amp\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_users\_detail\.data\.incoming\_detected\_amp\.\*\.recipient | string |  `email` 
action\_result\.data\.\*\.mail\_users\_detail\.data\.incoming\_detected\_content\_filter\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_users\_detail\.data\.incoming\_detected\_content\_filter\.\*\.recipient | string |  `email` 
action\_result\.data\.\*\.mail\_users\_detail\.data\.incoming\_detected\_ims\_spam\_increment\_over\_case\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_users\_detail\.data\.incoming\_detected\_ims\_spam\_increment\_over\_case\.\*\.recipient | string |  `email` 
action\_result\.data\.\*\.mail\_users\_detail\.data\.incoming\_detected\_spam\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_users\_detail\.data\.incoming\_detected\_spam\.\*\.recipient | string |  `email` 
action\_result\.data\.\*\.mail\_users\_detail\.data\.incoming\_detected\_virus\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_users\_detail\.data\.incoming\_detected\_virus\.\*\.recipient | string |  `email` 
action\_result\.data\.\*\.mail\_users\_detail\.data\.incoming\_graymail\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_users\_detail\.data\.incoming\_graymail\.\*\.recipient | string |  `email` 
action\_result\.data\.\*\.mail\_users\_detail\.data\.incoming\_marketing\_mail\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_users\_detail\.data\.incoming\_marketing\_mail\.\*\.recipient | string |  `email` 
action\_result\.data\.\*\.mail\_users\_detail\.data\.incoming\_social\_mail\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_users\_detail\.data\.incoming\_social\_mail\.\*\.recipient | string |  `email` 
action\_result\.data\.\*\.mail\_users\_detail\.data\.incoming\_threat\_content\_filter\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_users\_detail\.data\.incoming\_threat\_content\_filter\.\*\.recipient | string |  `email` 
action\_result\.data\.\*\.mail\_users\_detail\.data\.incoming\_total\_clean\_recipients\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_users\_detail\.data\.incoming\_total\_clean\_recipients\.\*\.recipient | string |  `email` 
action\_result\.data\.\*\.mail\_users\_detail\.data\.outgoing\_detected\_content\_filter\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_users\_detail\.data\.outgoing\_detected\_content\_filter\.\*\.recipient | string |  `email` 
action\_result\.data\.\*\.mail\_users\_detail\.data\.outgoing\_detected\_ims\_spam\_increment\_over\_case\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_users\_detail\.data\.outgoing\_detected\_ims\_spam\_increment\_over\_case\.\*\.recipient | string |  `email` 
action\_result\.data\.\*\.mail\_users\_detail\.data\.outgoing\_detected\_spam\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_users\_detail\.data\.outgoing\_detected\_spam\.\*\.recipient | string |  `email` 
action\_result\.data\.\*\.mail\_users\_detail\.data\.outgoing\_detected\_virus\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_users\_detail\.data\.outgoing\_detected\_virus\.\*\.recipient | string |  `email` 
action\_result\.data\.\*\.mail\_users\_detail\.data\.outgoing\_threat\_content\_filter\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_users\_detail\.data\.outgoing\_threat\_content\_filter\.\*\.recipient | string |  `email` 
action\_result\.data\.\*\.mail\_users\_detail\.data\.outgoing\_total\_clean\_recipients\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_users\_detail\.data\.outgoing\_total\_clean\_recipients\.\*\.recipient | string |  `email` 
action\_result\.data\.\*\.mail\_users\_detail\.uri | string | 
action\_result\.data\.\*\.mail\_virus\_type\_detail\.data\.incoming\_total\_recipients\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_virus\_type\_detail\.data\.incoming\_total\_recipients\.\*\.recipient | string | 
action\_result\.data\.\*\.mail\_virus\_type\_detail\.data\.outgoing\_total\_recipients\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_virus\_type\_detail\.data\.outgoing\_total\_recipients\.\*\.recipient | string | 
action\_result\.data\.\*\.mail\_virus\_type\_detail\.data\.total\_recipients\.\*\.count | numeric | 
action\_result\.data\.\*\.mail\_virus\_type\_detail\.data\.total\_recipients\.\*\.recipient | string | 
action\_result\.data\.\*\.mail\_virus\_type\_detail\.uri | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 