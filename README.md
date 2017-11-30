

# BRAWL 

One of the challenging problems for cyber security researchers developing detection and response capabilities is finding a realistic environment in which to test their hypothesis and capabilities. 

The cheapest method is to test capabilities on a small lab network. But this environment is lacking the scale of real enterprise network and the noise of real environments that makes detection much harder. In many ways, the best environment would be testing on multiple enterprise scale networks with a controlled but realistic attacker and real noise from users, system administrators, and third party software/devices. The challenge with testing in this environment is that it is expensive and in some scenarios high risk.

BRAWL seeks to create a compromise by creating a system to automatically create an enterprise network inside a cloud environment. OpenStack is the only currently supported environment, but it is being designed in such a way as to easily support other cloud environments in the future. BRAWL also builds an analysis network containing a data ingest and processing pipeline using <a href="https://www.elastic.co/products/logstash">LogStash</a> and <a href="https://kafka.apache.org">Kafka</a>. As part of the analysis network, it creates an event storage and search system using <a href="https://www.elastic.co/products/elasticsearch">Elasticsearch</a> and <a href="test/test_process_raw_es_json.py">Kibana</a>. BRAWL spins up a enterprise network "Game Board" with Windows images. These images have Microsoft <a href="https://technet.microsoft.com/en-us/sysinternals/sysmon">Sysmon</a> and other sensors already installed and configured to forward logs into the data ingest framework.

BRAWL also has a concept of bots, which can be either Red, Blue, or Gray. Red bots are offensive, Blue bots are defensive, and Gray bots emulate legitimate user behavior in order to provide noise to make detection more difficult. When a user wants to test research hypotheses, they implement a BRAWL bot. The BRAWL bot registers itself with the BRAWL Controller, which then orchestrates games between BRAWL bots on the Game Board. 

## Data Release ##
This release consists of some data from a BRAWL prototype. We created a small enterprise network, described below. We then ran a single game using the MITRE <a href="https://github.com/mitre/caldera">CALDERA</a> research project as a red bot. 

CALDERA is a related MITRE research project that automates adversary emulation activity based on the information in <a href="https://attack.mitre.org">Adversarial Tactics, Techniques, and Common Knowledge (ATT&CK)</a> model. It implements a set of ATT&CK tactics and techniques and uses a planning system (https://dl.acm.org/citation.cfm?id=2991111) to automate the actuation of those techniques and generate post-compromise adversary behavior within an enterprise network.

This data is released under the <a href="https://creativecommons.org/licenses/by/4.0/legalcode">Creative Commons BY License</a>

# Network & Sensor Description

Our small enterprise network is a flat network that consists of a Domain Controller (`dc.brawlco.com`) and 16 workstations. Each PC has the name of the primary user in the pc name (e.g. user `beane` typically logs into `beane-pc`). That user has Local Administrator privileges on the computer.

All the PCs are running Windows 8.1. The Domain controller is running Windows Server 2012 R2. 

On the Windows 8 PCs, we made changes to enable <a href="https://blogs.technet.microsoft.com/askpfeplat/2016/04/18/the-importance-of-kb2871997-and-kb2928120-for-credential-protection/">WDigest to keep plaintext passwords in LSASS's memory</a> using the following registry command: `reg ADD HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\ /v UseLogonCredential /t REG_DWORD /d 1 /F`


# Scenario Description

For this exercise, CALDERA was the only BRAWL bot participating. While conceptually BRAWL can be used to test a variety of attacker behaviors and detection, many of MITRE's research efforts follow an "assume breach" philosophy. Therefore we give CALDERA a starting point as a Local Administrator on a box on the network at the beginning of the exercise. 

Also, without a Grey bot performing logon across different hosts, the BRAWL Game Board is sterile from the perspective of credentials that can be stolen and used by Red bots. To enable lateral movement, the BRAWL Controller uses <a href="https://technet.microsoft.com/en-us/sysinternals/bb897553.aspx?f=255&MSPPError=-2147217396">psexec</a> to create logon events on hosts with the credentials of other users from the network.

CALDERA Performed the following ATT&CK Techniques during the exercise:

* <a href="https://attack.mitre.org/wiki/Technique/T1087">Account Discovery</a>
* <a href="https://attack.mitre.org/wiki/Technique/T1003">Credential Dumping</a>
* <a href="https://attack.mitre.org/wiki/Technique/T1016">Local Network Configuration Discovery</a>
* <a href="https://attack.mitre.org/wiki/Technique/T1069">Permission Groups Discovery</a>
* <a href="https://attack.mitre.org/wiki/Technique/T1086">PowerShell</a>
* <a href="https://attack.mitre.org/wiki/Technique/T1060">Registry Run Keys / Start Folder</a>
* <a href="https://attack.mitre.org/wiki/Technique/T1105">Remote File Copy</a>
* <a href="https://attack.mitre.org/wiki/Technique/T1018">Remote System Discovery</a>
* <a href="https://attack.mitre.org/wiki/Technique/T1077">Windows Admin Shares</a>
* <a href="https://attack.mitre.org/wiki/Technique/T1047">Windows Management Instrumentation</a>


# Data #

There are five types of data in this repository. Each is contained in its own file in the `data/` folder.

| Data Type   | Description  |
|---|---|
| game_metadata | Data describing the BRAWL scenario |
| sysmon  | Data gathered from <a href="https://technet.microsoft.com/en-us/sysinternals/sysmon">Sysmon</a> running on each of the workstations   |
| win_event | Windows Event Logs   |
| computer_properties | Data gathered from custom scripts that provides some information about the computers in the network  |
| bsf |  Red bot actions in BRAWL Shared Format (BSF) |

## BRAWL Shared Format ##
Red bots and blue bots are encouraged to log information about their activities or detections in BRAWL Shared Format (BSF). The goal of this is to make it easier to compare blue bot detection/actions with red bot actions.

The format is currently in development and could change in future data sets.

The fields for BSF are described below in the Data Sources Detail section.

### Notes About Time ###
Different event sources in BRAWL handle time differently. The time is either the time that an event hit our logging ingest framework, the time the event was generated on the host/endpoint, or the time recorded by a bot on the network. In general those times should be within a few milliseconds of each other. When possible the logging ingest framework uses the event time stored in the event instead of the time of the event hitting the ingest nodes. The table below details the method used for each data type.

| Data Source | Time Notes |
|----- | --------- | 
| computer_properties | from the `time` field |
| game_metadata |  time it hits the ingest framework |
| sysmon |  from the utc_time field |
| win_event | pulled from the windows event time |
| bsf | The `@timestamp` field is time it hits the ingest framework. However the time related BSF fields (e.g. `happened_after`,`happened_before`, etc) are the times the events started or ended based on the time on CALDERA's command and control server. |

# Data Sources Detail ##

## game_metadata ##
| Field Name | Description |
| --- | ---
| @timestamp | Time related to the event. See note about time above. |
| @uuid | Unique Event ID |
| game_id | The unique game_id for this exercise. |
| type | Event Type. Always `game_metadata` for these records |
| hosts | A list of hosts that were a part of the exercise and "in bounds" for the red bot |
| randomization_seed | A seed that can be used by BRAWL Bot Participants to implement "random" behavior that is that same across executions of BRAWL |
| starting_host | host that the red bot starts on. |



## sysmon ##
| Field Name | Description |
| --- | ---
| @timestamp | Time related to the event. See note about time above. |
| @uuid | Unique Event ID |
| type | Event Type. Always `sysmon` for these records |
| game_id | The unique game_id for this exercise. |
| data_model.object | The <a href="https://car.mitre.org/wiki/Main_Page">CAR</a> <a href="https://car.mitre.org/wiki/Help:Data_Model#Objects">object</a> being acted on. |
| data_model.action | The <a href="https://car.mitre.org/wiki/Main_Page">CAR</a> <a href="https://car.mitre.org/wiki/Help:Data_Model#action">action</a> being performed on the object. This field is an array because some events can correspond to more than one action in the CAR data model. An example of this is remote thread creation events. |
| data_model.fields.* | The fields relevant for the given object/action pair. |
| game_id | The unique game_id for this exercise. |
| host | Hostname that the event was logged from. |

We are using Sysmon v3.11. `sysmon_config.txt` contains the output of the `sysmon -c` command detailing our configuration.


Sysmon generates many different kinds of events, that map to different <a href="https://car.mitre.org/wiki/Main_Page">CAR</a> object/action pairs. The fields for each type are explained in more detail on the CAR website: https://car.mitre.org/wiki/Data_Model

The object/action pairs that are generated by Sysmon in our configuration are:

* `driver/load`
* `file/attr_modify`
* `flow/start`
* `module/load`
* `process/create`
* `process/terminate`
* `thread/create`
* `threat/remote_create`

Use the <a href="https://car.mitre.org/wiki/Data_Model">CAR data model</a> to determine the field names and semantics for fields contained in data_model.fields.* for each object/action pair above.
 

## win_event ##
| Field Name | Description |
| --- | ---
| @timestamp | Time related to the event. See each event below for details on how this is calculated |
| @uuid | Unique Event ID |
| type | Event Type. Always `win_event` for these records |
| game_id | The unique game_id for this exercise. |
| host | Host that logged the event |
| raw | The windows event log entry in it's raw XML format | 
| data\_model.fields.log_name | Windows Log name (Application, System, or Security) |
| data\_model.fields.log_type | The log type for a given `log_name` |



## computer_properties ##
| Field Name | Description |
| --- | ---
| @timestamp | Time related to the event. See note about time above. |
| @uuid | Unique Event ID |
| type | Event Type. Always `computer_properties` for these records |
| game_id | The unique game_id for this exercise. |
| host | Name of computer that the script ran on |
| netinfo | Collection of netinfo objects |
| netinfo.DNSServers |  collection of DNS resolvers configured for this host |
| netinfo.Gateway | Gateway for this interface |
| netinfo.IPAddress | IPAddresses for this interface |
| netinfo.IsDHCPEnabled | Is DHCP Enabled? |
| netinfo.MACAddress | MAC Address for this interface |
| netinfo.SubnetMask | Subnet Mask for respective IP addresses |
| pcinfo | Object describing information about the PC |
| pcinfo.AssetTag | AssetTag if accessible  |
| pcinfo.CPU | Information about CPU(s)  |
| pcinfo.ChassisType | Not used in BRAWL. "Unknown"  |
| pcinfo.Disks |  Information about attached disk(s)  |
| pcinfo.DomainName | domain system is a part of  |
| pcinfo.LastBootUpTime | Time system booted  |
| pcinfo.Memory | Information about memory on the systems  |
| pcinfo.OS | Information about the running OS  |
| pcinfo.SerialNumber | HW Serial Number |
| time | Time that the script ran |
| userinfo | Array containing userinfo objects describing users who have logged onto the system since last boot |
| userinfo.AuthenticationPackage | Authentication Package used for authentication |
| userinfo.Domain | Domain (or local pc) account belongs to |
| userinfo.LogonId | LogonId |
| userinfo.LogonTime | Time of logon |
| userinfo.LogonType | Windows Logon <a href="https://technet.microsoft.com/en-us/library/cc787567(v=ws.10).aspx">Type Constants</a> |
| userinfo.LogonTypeName | Description of LogonType |
| userinfo.UserName | UserName of principal logging on |

This data was collected periodically using the unified_json.ps1 module from MITRE's <a href="https://github.com/mitre/ps_pc_props/">PowerShell Utilities for Security Situational Awareness</a>. The `userinfo` field can be useful in determining which credentials may have been compromised if a credential dumper such as Mimikatz was run on the system.  


## bsf ##
| Field Name | Description |
| --- | ---
| @timestamp | Time related to the event. See note about time above. |
| @uuid | Unique Event ID |
| type | Event Type. Always `bsf_events` for these records |
| game_id | The unique game_id for this exercise. |
| bsf | Array of BSF events describing bot activity. Fields for this array are described in more detail below. |
| bsf_version | Version of the BSF schema used for `bsf` array of events |
| producer_id | Bot that produced this BSF data. |

The objects inside of the `bsf` array field are of type `operation`, `step`, or `event`. All objects have a `nodetype` field that can be used to determine the object type

### `event` BSF Object ####
| Field | Description |
| ---- | ---- |
| id | A unique identifier for each event. |
| nodetype | This node's type. One of: {"operation", "step", "event"}. |
| host | Hostname or IP at which this event was enacted / detected. |
| time | Note: At least one of the following three time fields (i.e., "time", "happened\_after", or "happened\_before") must be reported. "time" is especially desired; all three are encouraged. Please see note 1 in General Notes below. <br><br> Note on time format: All time information must be in ISO 8601 format. More specifically as: 'yyyy-mm-ddThh:nn:ss.llll00'. Where y is year, m is month, d is day, h is hour, n is minute, s is second, l is millisecond (and there are two trailing zeros). For example: 2017-02-22T18:38:14.060000<br><br>Optional: Estimate of the time this event occurred. |
| happened_after | Optional: An early bound ("temporal left bracket") on uncertainty in "time".
| happened_before | Optional: A late bound ("temporal right bracket") on uncertainty in "time". |
| confidence | Optional: Enables blue bots to communicate confidence (a real number between 0.0 and 1.0) in this event's association with an attack. |
| object | Object acted upon; see table below for permissible values. Loosely based on the <a href="https://car.mitre.org/wiki/Help:Data_Model">CAR Data Model</a> |
| action | Actions for a given object. Loosely based on the <a href="https://car.mitre.org/wiki/Help:Data_Model">CAR Data Model</a> |
| specific\_field\_1 .. N | 1-N descriptive attributes (see below). Loosely based on the <a href="https://car.mitre.org/wiki/Help:Data_Model">CAR Data Model</a> |

#### Object/Action/Fields Information for Event Objects

| Object | Action | Required Field(s) | Optional Fields(s) |
| --- | --- | ---- | ---- |
| process | create<br>terminate<br>scanned | At least one of:<br>&nbsp;&nbsp;&nbsp;&nbsp;   {pid, command\_line, exe, image\_path} | fqdn<br>hostname<br>md5\_hash<br>parent\_exe<br>parent\_image\_path<br>ppid<br>sha1\_hash<br>sha256\_hash<br>sid<br>signer<br>user |
| flow | start<br>end<br>message | At least one of:<br>  &nbsp;&nbsp;&nbsp;&nbsp;{src\_hostname,src_ip}<br> At least one of:<br>&nbsp;&nbsp;&nbsp;&nbsp;{dest\_hostname,    dest\_ip}<br>At least one of:<br>&nbsp;&nbsp;&nbsp;&nbsp;  {src\_port,   dest\_port,   protocol} | content<br>dest\_fqdn<br>exe<br>flags<br>fqdn<br>hostname<br>image\_path<br>packet\_count<br>pid<br>ppid<br>proto\_info<br>src\_fqdn<br>user<br> |
| file | create<br>delete<br>modify<br>read<br>timestomp<br>write | file_path | company<br>file\_name<br>fqdn<br>hostname<br>image\_path<br>md5\_hash<br>pid<br>ppid<br>sha1\_hash<br>sha256\_hash<br>signer<br>user

You can read more about the semantics of the Required and Optional Fields by finding the associated object in the <a href="https://car.mitre.org/wiki/Help:Data_Model">CAR Data Model</a>

### `step` BSF Object ###
Step objects connect one or more events together into a higher level grouping of activity. Step objects also present a place for BSF emitters to label activity with ATT&CK labels.

| Field name | Description
| --- | --- |
|id | A unique identifier for operation steps. |
| nodetype | This node's type. One of: {"operation", "step", "event"}. |
| attack\_info | An array of technique objects (defined in the table directly below), describing how this step relates to the ATT&CK taxonomy. Why an array? Although a single technique often describes a step and all its events, in some cases, multiple techniques can be implemented. |
| attack\_info.technique_id | An ATT&CK technique ID (e.g., "T1059") describing the attack mechanism red employed in this step and its referenced events. |
| attack\_info.technique_name | A human readable string describing this technique (e.g., "Command-Line Interface"). |
| attack\_info.tactic | An array of one or more ATT&CK tactic labels describing the intent/strategy of this technique. (Note that a single technique can exercise multiple tactics.) For example: ["Lateral Movement", "Execution"]
| description | Optional: Notes or annotations for this step go here.| 
| events | An array of ids of the `event` objects comprising this step.

### `operation` BSF Object ###
Operation objects connect multiple step objects together. However there are no `Operation` objects present in this data set.

### General BSF Notes ###
Descriptions and Notes for Event Fields (especially "At least one of"s):


1.  Time fields.
  1.  Punctiliar Time.  Activities such as a file deletion are essentially punctiliar, having a single time of occurrence which can be provided via the time field.  However, it is possible that neither red nor blue will know this exact timestamp.  For example, red bots may spawn a process to accomplish some action within a time window, but the exact time the action occurs is unknown. Blue bots can use sensors which may involve detection delays.  Thus, BSF also provides two time fields happened\_after and happened\_before as temporal left and right brackets respectively, defining bounds on an uncertainty interval for the actual event.  At least one of these three fields (i.e., time, happened_after, happened_before) must be reported with each `event` object.  The other fields are optional, but should be reported as they are known.  In particular, bots are encouraged to report a value for "time" which is their best guess, even if they do not have an exact time.
  2. Durative Time.  Activities such as a flow are durative in nature, spanning a time period.  BSF generally addresses durative activities by recording the end points of their interval as punctiliar times.  Thus a flow start event requires one of {time, happened\_after, happened\_before}, as does the flow end event.  However, some blue sensors may detect a durative activity in mid-course (e.g., a scanner which periodically scans the state of all processes, and determines one has become malicious).  For flows, mid-course flow detections can be reported as "flow, message, time, ... (other fields)".  For processes, mid-course flow detections can be reported as "process, scanned, time, ... (other fields)".
1. Process identification.  Ideally, a pid is used to identify a process, however the pid is not always known, especially by the red bot.  Alternatively, the `command_line` spawning the process, or the `exe` / `image_path` which was executed can be provided.
1. Flow ports.  The source and destination ports in flows can be described by either a hostname or an IP address. 
1. In this data set, the only bot participating is CALDERA, therefore the only BSF records present are from CALDERA.



# Appendix #
Hosts on our BRAWL network for this game:

* beane-pc.brawlco.com
* colgan-pc.brawlco.com
* dc.brawlco.com
* escue-pc.brawlco.com
* fulco-pc.brawlco.com
* harley-pc.brawlco.com
* kressierer-pc.brawlco.com
* mims-pc.brawlco.com
* minahan-pc.brawlco.com
* ostermeyer-pc.brawlco.com
* peele-pc.brawlco.com
* platten-pc.brawlco.com
* santilli-pc.brawlco.com
* sespinosa-pc.brawlco.com
* sounder-pc.brawlco.com
* teston-pc.brawlco.com
* zissler-pc.brawlco.com




