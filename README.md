## ASIM from scratch

This is a tutorial to guide through writing your own ASIM parser for custom tables Sentinel.
We are going to use a custom table from a fictious network equipment: `BadRouter_CL`. Don't look for that table in your workspace, it doesn't exist. It's been populated in our lab environment just for the sake of this article.

🎯 The end goal is to include the data from the `BadRouter_CL` table when using ASIM parsers.

### The custom table

Our custom table is annoying 😤 It stores two types of records:
- Authentication events
- Network session events

You often don't choose what's in the table and its format. You can change it at ingestion time with a DCR, but that's a different topic altogether. Here we will make it work the way it is.

Here is the table schema:

```kql
BadRouter_CL
| getschema
```

|ColumnName|ColumnOrdinal|DataType|ColumnType|
|-|-|-|-|
|AuthType|0|System.String|string|
|Crypto|1|System.Int32|int|
|Realm|2|System.String|string|
|ResultCode|3|System.Int32|int|
|ResultReason|4|System.String|string|
|SourceIp|5|System.String|string|
|TimeGenerated|6|System.DateTime|datetime|
|User|7|System.String|string|
|Action|8|System.String|string|
|Protocol|9|System.String|string|
|DestinationIp|10|System.String|string|
|SourcePort|11|System.Int32|int|
|DestinationPort|12|System.Int32|int|
|SessionId|13|System.String|string|
|TenantId|14|System.String|string|
|Type|15|System.String|string|
|_ResourceId|16|System.String|string|

You know from the vendor that if the `isnotempty(AuthType)` is true that's an authentication event, and therefore is `isempty(AuthType)` is true it is a network session event.

Sample for authentication event:

```kql
BadRouter_CL
| where isnotempty(AuthType)
| take 1
```

|TimeGenerated|AuthType|Crypto|Realm|ResultCode|ResultReason|SourceIp|User|TenantId|Type|_ResourceId|
|-|-|-|-|-|-|-|-|-|-|-|
|2023-09-28T21:16:05.5139728Z|3 - Network|1|FFAWAY|0|-|24.212.237.110|piaudonn|2782cb21-db13-4253-a08e-005e54eb8db6|BadRouter_CL|/subscriptions/.../ffaway|

Sample for network session event:

```kql
BadRouter_CL
| where isempty(AuthType)
| take 1
```

|TimeGenerated|ResultCode|ResultReason|SourceIp|SourcePort|DestinationIp|DestinationPort|SessionId|Action|TenantId|Type|_ResourceId| 
|-|-|-|-|-|-|-|-|-|-|-|-|
|2023-09-29T12:37:19.1527966Z|0|Allowed|10.0.0.4|57872|20.38.146.158|443|4408|Allow|2782cb21-db13-4253-a08e-005e54eb8db6|BadRouter_CL|/subscriptions/.../ffaway|

### ASIM objectives

We want to make sure of these two things:
- Include `BadRouter_CL` authentication data when calling the parser `imAuthentication`
- Include `BadRouter_CL` network session data when calling the parser `_Im_NetworkSession`

It already gets a tad tricky as the first parser `imAuthentication` doesn't exist by default, you need to install it.
The second one `_Im_NetworkSession` is a built-in parser, so it will be there out of the box.

<details><summary>[Optional] ⚙️ Install the imAuthentication parser</summary>

The full documentation can be found on [GitHub](https://aka.ms/ASimAuthenticationDoc). Or you can click here:
[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://aka.ms/ASimAuthenticationARM)
</details>

### ASIM hierarchy 

If we want `imAuthentication` and `_Im_NetworkSession` to use the data from your custom table we need to find a way for those functions to call your tables. For that we need to understand where and when in the maze of the many parsers. ASIM parsers are functions that call other functions.

We will need to create a parser for each use case and then piggy back on the existing hierarchy to be called when using `imAuthentication` and `_Im_NetworkSession`.

- `imAuthentication` ➡️ calls **v**endors specific functions (such as `vimAuthenticationVectraXDRAudit`, `vimAuthenticationSigninLogs`, `vimAuthenticationAWSCloudTrail`...). As it is a workspace function, you can modify it to add our future parser for authentication.

- `_Im_NetworkSession`➡️ also calls three other functions.
    - `_Im_NetworkSessionBuiltIn` this calls other built-in parsers. We can't touch that one it's a built-in function.
    - `Im_NetworkSessionSolutions` this is a workspace function that, if created, calls other solution specific parsers (you would piggy back on that if you were creating a solution available in Content Hub).
    - `Im_NetworkSessionCustom` this is the one we need to piggy back on for our custom table. It doesn't exist by default but we will create it as a workspace function.

We will create two functions `vimAuthenticationBadRouter` and `vimNetworkSessionBadRouter` that will integrate in this hierarchy this way:

- `imAuthentication` ➡️ `vimAuthenticationBadRouter`
- `_Im_NetworkSession` ➡️ `Im_NetworkSessionCustom` ➡️ `vimNetworkSessionBadRouter`

There will be at least 3 new functions `vimAuthenticationBadRouter`, `Im_NetworkSessionCustom` and `vimNetworkSessionBadRouter`.

### Target schema

Our parser `vimAuthenticationBadRouter` will use the [Authentication schema](https://learn.microsoft.com/en-us/azure/sentinel/normalization-schema-authentication) and `vimNetworkSessionBadRouter` the [Network session schema](https://learn.microsoft.com/en-us/azure/sentinel/normalization-schema-network).

Looking at those schemas, it is important to realize that there are mandatory field. If there are missing, the integration with the rest of the ASIM of the same class might produce unexpected results.

We will need:

|Field|Type|Description|
|-|-|-|
|EventType|Enumerated|As per the schema it ought to be `Logon`, `Logoff` or `Elevate`.|
|EventSchemaVersion|string|The version of the schema. The version of the schema documented here is `0.1.3`.|
|EventSchema|string|The name of the schema documented here is `Authentication`.|
|EventProduct|string|For us it is `BadRouter`.|
|EventVendor|string|For us it is `BadVendor`.|
|EventCount|int|The number of events described by the record. For us it will always be `1`.|
|EventStartTime|datetime|In our case, that will be the same as `TimeGenerated`.|
|EventEndTime|datetime|In our case, that will be the same as `TimeGenerated`.|
|EventResult|Enumerated|One of the following values: Success, Partial, Failure, NA (Not Applicable).|
|Dvc|string|A unique identifier of the device on which the event occurred, or which reported the event, depending on the schema.|

There are plenty of another field we can use. And well, it is recommended to implement as many as the recommended fields to guarantee better results.

Let's start building it:

```kql
BadRouter_CL
| where isnotempty(AuthType)
| extend EventType = "Logon" ,
    EventSchemaVersion = "0.1.3",
    EventSchema = "Authentication",
    EventProduct = "BadRouter",
    EventVendor = "BadVendor" ,
    EventCount = 1,
    EventStartTime = TimeGenerated,
    EventEndTime = TimeGenerated,
    EventResult = "Success",
    Dvc = tostring(split(_ResourceId, "/")[-1])
```

That takes care of all the mandatory fields. Well, we think. We can put it to the test with ASimSchemaTester. This is a helper function you can deploy from [GitHub](https://github.com/Azure/Azure-Sentinel/tree/master/ASIM/dev/ASimTester).
Add the following to the query:

```kql
| getschema
| invoke ASimSchemaTester('Authentication')
```

This gives us the following output

```
(0) Error: type mismatch for column [EventCount]. It is currently long and should be int
(1) Warning: Missing recommended field [Dst]
(1) Warning: Missing recommended field [DvcAction]
(1) Warning: Missing recommended field [DvcDomain]
(1) Warning: Missing recommended field [DvcHostname]
(1) Warning: Missing recommended field [DvcIpAddr]
(1) Warning: Missing recommended field [EventResultDetails]
(1) Warning: Missing recommended field [EventSeverity]
(1) Warning: Missing recommended field [EventUid]
(1) Warning: Missing recommended field [SrcIpAddr]
(1) Warning: Missing recommended field [Src]
(1) Warning: Missing recommended field [TargetDomain]
(1) Warning: Missing recommended field [TargetHostname]
(2) Info: Missing optional alias [Application] aliasing non-existent column [TargetAppName]
(2) Info: Missing optional field [ActingAppId]
...
```

Interresting, the default typing for numbers are long, not integer. So we'll have to change `EventCount = 1` to `EventCount = int(1)`. We also see we have a munch of missing recommended field, and we are going to use some of them.

```kql
BadRouter_CL
| where isnotempty(AuthType)
| extend EventType = "Logon" ,
    EventSchemaVersion = "0.1.3",
    EventSchema = "Authentication",
    EventProduct = "BadRouter",
    EventVendor = "BadVendor" ,
    EventCount = int(1),
    EventStartTime = TimeGenerated,
    EventEndTime = TimeGenerated,
    EventResult = iif(ResultCode == 0, "Success", "Failure"),
    Dvc = tostring(split(_ResourceId, "/")[-1]),
    SrcIpAddress = iff(SourceIp != "-", SourceIp, "")
| project-rename TargetUsername = User,
    TargetDomain = Realm
| project TimeGenerated, EventType, EventSchemaVersion, EventSchema, EventCount, EventStartTime, EventEndTime, EventResult, Dvc, TargetUsername, TargetDomain,SrcIpAddress
```

Now we can test the data by adding:

```kql
| invoke ASimDataTester('Authentication')
```

It will tell you if you are using the wrong value for enumerated values or have other syntax issues. 

Same gymnastic with the Network Session schema. We will need:

|Field|Type|Description|
|-|-|-|
|EventType|Enumerated|In our case we are goign to use `NetworkSession`.|
|EventSchemaVersion|string|The version of the schema. The version of the schema documented here is `0.1.3`.|
|EventSchema|string|The name of the schema documented here is `Authentication`.|
|EventProduct|string|For us it is `BadRouter`.|
|EventVendor|string|For us it is `BadVendor`.|
|EventCount|int|The number of events described by the record. For us it will always be `1`.|
|EventStartTime|datetime|In our case, that will be the same as `TimeGenerated`.|
|EventEndTime|datetime|In our case, that will be the same as `TimeGenerated`.|
|EventResult|Enumerated|One of the following values: Success, Partial, Failure, NA (Not Applicable).|
|Dvc|string|A unique identifier of the device on which the event occurred or which reported the event, depending on the schema.|

Which gives us something like:

```kql
BadRouter_CL
| where isempty(AuthType)
| extend EventCount = int(1),
    EventStartTime = TimeGenerated,
    EventEndTime = TimeGenerated,
    EventType = "NetworkSession",
    EventVendor = "BadVendor",
    EventProduct = "BadProduct",
    EventSchema = "NetworkSession",
    EventSchemaVersion = "0.2.6",
    Dvc = tostring(split(_ResourceId,"/")[-1]),
    NetworkDirection = "Outbound",
    DvcAction = iff(ResultCode == 0, "Allow", "Drop"),
    EventResult = "Success",
    Type = "BadRouter_CL",
    IpAddr = DestinationIp
| project-rename SrcIpAddr = SourceIp,
    SrcPortNumber = SourcePort,
    DstIpAddr = DestinationIp,
    DstPortNumber = DestinationPort
| project TimeGenerated, EventCount, EventStartTime, EventEndTime, EventType, EventVendor, EventProduct, EventSchema, EventSchemaVersion, EventResult, Dvc, NetworkDirection, DvcAction, SrcIpAddr, SrcPortNumber, DstIpAddr, DstPortNumber, SessionId, IpAddr, Type
```

Note that here we are setting an alias `IpAddr` wiht the value of `DestinationIp` that's purely arbitrary.

### What about AS parsers?

There are two types of ASIM data parsers.

1. Parametrized parsers: `_Im*` (for built-in) or `im*` (for workspace functions).
2. Parameterless parsers: `_ASim*`(for built-in) or `ASim*` (for workspace functions).

The latter is only recommended to be used for testing queries or interactive queries on a small dataset as without parameters to filter, the query will likely not be performing well. As the first one is the way to go, this tutorial just focusses on that one.

Parameterized parsers need to support a range of parameters to accommodate filters. This is called **pre-filtering**. For the [authentication](https://learn.microsoft.com/en-us/azure/sentinel/normalization-schema-authentication) table, this will include the following:

| Name     | Type      | Description |
|-|-|-|
| **starttime** | datetime | Filter only authentication events that ran at or after this time. |
| **endtime** | datetime | Filter only authentication events that finished running at or before this time. |
| **targetusername_has** | string | Filter only authentication events that have any of the listed usernames. Default value should be *.|

It means our parser will include:
```kql
BadRouter_CL
| where 
    (isnull(starttime) or TimeGenerated >= starttime) 
    and (isnull(endtime) or TimeGenerated <= endtime)
    and isnotempty(AuthType)
    and (targetusername_has=='*' or (User has targetusername_has ))
```

> Note that we use `isempty(AuthType)` and the `User` field to filter.

For the [network sessions](https://learn.microsoft.com/en-us/azure/sentinel/normalization-schema-network) table, this will include the following:

| Name     | Type      | Description |
|----------|-----------|-------------|
| **starttime** | datetime | Filter only network sessions that *started* at or after this time. |
| **endtime** | datetime | Filter only network sessions that *started* running at or before this time. |
| **srcipaddr_has_any_prefix** | dynamic | Filter only network sessions for which the **source IP address field** prefix is in one of the listed values. Prefixes should end with a `.`, for example: `10.0.`. The length of the list is limited to 10,000 items.|
| **dstipaddr_has_any_prefix** | dynamic | Filter only network sessions for which the **destination IP address field** prefix is in one of the listed values. Prefixes should end with a `.`, for example: `10.0.`. The length of the list is limited to 10,000 items.|
| **ipaddr_has_any_prefix** | dynamic | Filter only network sessions for which the **destination IP address field** or **source IP address field** prefix is in one of the listed values. Prefixes should end with a `.`, for example: `10.0.`. The length of the list is limited to 10,000 items.<br><br>The field **ASimMatchingIpAddr** is set with the one of the values `SrcIpAddr`, `DstIpAddr`, or `Both` to reflect the matching fields or fields. |
| **dstportnumber** | Int | Filter only network sessions with the specified destination port number. |
| **hostname_has_any** | dynamic/string | Filter only network sessions for which the **destination hostname field** has any of the values listed. The length of the list is limited to 10,000 items.<br><br> The field **ASimMatchingHostname** is set with the one of the values `SrcHostname`, `DstHostname`, or `Both` to reflect the matching fields or fields. |
| **dvcaction** | dynamic/string | Filter only network sessions for which the **Device Action field** is any of the values listed. | 
| **eventresult** | String | Filter only network sessions with a specific **EventResult** value. |

It means our parser will include:
```kql
let src_or_any=set_union(srcipaddr_has_any_prefix, ipaddr_has_any_prefix); 
let dst_or_any=set_union(dstipaddr_has_any_prefix, ipaddr_has_any_prefix); 
let ip_any = set_union(srcipaddr_has_any_prefix, dstipaddr_has_any_prefix, ipaddr_has_any_prefix);    
BadRouter_CL
| where  
    (isnull(starttime) or TimeGenerated >= starttime) 
    and (isnull(endtime) or TimeGenerated <= endtime)
    and isempty(AuthType)
    and (isnull(dstportnumber) or (DestinationPort == dstportnumber))
    and ((array_length(dvcaction) == 0) or Action has_any (dvcaction))
    and ((eventresult == "*") or (EventResult == eventresult))
    and  (array_length(ip_any)==0 or has_any_ipv4_prefix(EventData ,ip_any)) 
| extend temp_isSrcMatch=has_any_ipv4_prefix(SourceIp,src_or_any), 
    temp_isDstMatch=has_any_ipv4_prefix(DestinationIp,dst_or_any)
| extend ASimMatchingIpAddr = case(
    array_length(src_or_any) == 0 and array_length(dst_or_any) == 0, "-", // match not requested
    (temp_isSrcMatch and temp_isDstMatch), "Both", // has to be checked before the individual 
    temp_isSrcMatch, "SourceIp",
    temp_isDstMatch, "DestinationIp",
    "No match"
)
| where ASimMatchingIpAddr != "No match"
| project-away temp_*
```
> Note that we use `isempty(AuthType)` as well as the `DestinationPort`,`Action`,`EventResult`,`SourceIp` and `DestinationIp` fields to filter. This is to match the name of the fields in our custom tables.

### Putting things together

We have the queries, we have the prefilter, now we need to turn them into fully functional parser.

In a new query tab in your Logs blade in Log Analytics, we are going to use the following:

```kql
let BadRouterAuthParser=(
    starttime: datetime=datetime(null),
    endtime: datetime=datetime(null), 
    targetusername_has: string="*", 
    disabled: bool=false) {
        BadRouter_CL
        | where isnotempty(AuthType)
        | extend EventType = "Logon" ,
            EventSchemaVersion = "0.1.3",
            EventSchema = "Authentication",
            EventProduct = "BadRouter",
            EventVendor = "BadVendor" ,
            EventCount = int(1),
            EventStartTime = TimeGenerated,
            EventEndTime = TimeGenerated,
            EventResult = iif(ResultCode == 0, "Success", "Failure"),
            Dvc = tostring(split(_ResourceId, "/")[-1]),
            SrcIpAddress = iff(SourceIp != "-", SourceIp, "")
        | project-rename TargetUsername = User,
            TargetDomain = Realm
        | project TimeGenerated, EventType, EventSchemaVersion, EventSchema, EventCount, EventStartTime, EventEndTime, EventResult, Dvc, TargetUsername, TargetDomain,SrcIpAddress
    };
BadRouterAuthParser(
  starttime=starttime, 
  endtime=endtime,
  targetusername_has=targetusername_has, 
  disabled=disabled
)
```

Then click Save as funtion, call it `vimAuthenticationBadRouter` and those 4 parameters to it:

|Type|Name|Default value|
|-|-|-|
|datetime|startime|`datetime(null)`|
|datetime|endtime|`datetime(null)`|
|string|targetusername_has|`'*'`|
|bool|disabled|False|

Now we need to modify the `imAuthentication` to add our parser to it. Load it in the Logs blade and add the following in the union:

```kql
, vimAuthenticationBadRouter               (starttime, endtime, (imAuthenticationDisabled or('ExcludevimAuthenticationBadRouter' in (DisabledParsers) )))
```

And click **Save** and confirm. 

Now when we run the following:

```kql
imAuthentication(starttime=now(), endtime=ago(7d))
```

It will return events from the `BadRouter_CL` table.
