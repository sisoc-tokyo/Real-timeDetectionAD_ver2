# Real-time detection of high-risk attacks leveraging Kerberos and SMB

This is a real-time detection tool for detecting attack against Active Directory.
The tools is the improved version of  <a href="https://github.com/sisoc-tokyo/Real-timeDetectionAD" target="_blank">the previous version</a>.
Our tool can useful for immediate incident response for targeted attacks.

The tool detects the following attack activities using Event logs and Kerberos/SMB packets. 
* Attacks leveraging the vulnerabilities fixed in MS14-068 and MS17-010
* Attacks using Golden Ticket
* Attacks using Silver Ticket

<img src="toolSummary.png" alt="Overview of the tool" title="Overview of the tool" width="50%" height="50%">

The tool is tested in Windows 2008 R2, 2012 R2, 2016. 
<a href="Real-timeDetectionOfHigh-riskAttacksLeveragingKerberosAndSMB-wp.pdf" target="_blank">Documentation of the tool is here</a>

## Tool detail
###	Function of the tool
Our tool consists of the following components:
* Detection Server: Detects attack activities leveraging Domain Administrator privileges using signature based detection and Machine Learning.  Detection programs are implemented by Web API.
* Log Server for Event Logs:  Log Server is implemented using Elactic Stack. It collects the Domain Controller’s Event logs in real-time and provide log search and visualization.
* Log Server for packets:  Collect Kerberos packets using tshark. Cpllected packets are sent to Elastic search using Logsrash.

Our method consists of the following functions.
* Event Log analysis
* Packet analysis
* Identification of tactics in ATT&CK

###	Event Log analysis
1.	If someone access to the Domain Controller including attacks, activities are recorded in the Event log.
2.	Each Event Log is sent to Logstash  in real-time by Winlogbeat.<br>
Logstash extracts input data from the Event log, then call the detection API on Detection Server.
3.	Detection API is launched. Firstly, analyze the log with signature detection.
4.	Next analyze the log with machine learning.
5.	If attack is detected, judge the log is recorded by attack activities.<br>
Send alert E-mail to the security administrator, and add a flag indicates attack to the log .
6.	Transfer the log to Elasticsearch . 

####	Input of the tools: Event logs of the Domain Controller. 
* 4672: An account assigned with special privileges logged on.
* 4674: An operation was attempted on a privileged object
* 4688: A new process was created
* 4768: A Kerberos authentication ticket (TGT) was requested
* 4769: A Kerberos service ticket was requested
* 5140: A network share object was accessed

###	Packet analysis
1.	If someone access to the Domain Controller including attacks, Kerberos packets are sent to Domain Controller.
2.	Tshark collects Kerberos packets.<br>
Logstash extracts input data from the packets, then call the detection API on Detection Server.
3.	Detection API is launched. Analyze wheter Golden Tickets and Silver Tickets are used from packets.
4.	If attack is detected, judge the log is recorded by attack activities.<br>
Send alert E-mail to the security administrator, and add a flag indicates attack to the packet .
6.	Transfer the packet to Elasticsearch . 

####	Input of the tools: Kerberos packets
The following is the Kerberos message type used for detection.
* 11: KRB_AS_REP
* 12: KRB_TGS_REQ
* 13: KRB_TGS_REP
* 14: KRB_AP_REQ 
* 32: KRB_AP_ERR_TKT_EXPIRED

###	Output (result) of the tool
* Distinguish logs recorded by attack activities from logs recorded by normal operations, and identity infected computers and accounts. <br>
The detection result can be checked using Kibana.
* If attacks are detected, send email alerts to the specific E-mail address.

###	System Requirements
We tested our tool in the following environment.

* Domain Controller (Windows 2008R2/ 2012 R2/ 2016)
    * Winlogbeat(5.4.2): Open-source log analysis platform
* Log Server: Open-source tools + Logstash pipeline
     * OS: CentOS 7
    * Logstash(6.5.0): Parse logs, launch the detection program, transfer logs to Elastic Search
    * Elastic Search(6.5.0): Collects logs and provides API interface for log detection
    * Kibana(6.5.0): Visualizes the detection results
* Detection Server: Custom detection programs
     * OS: CentOS 7
     * Python: 3.6.0
     * Flask: 0.12
     * scikit-learn: 0.19.1
     

###	How to implement
<a href="implementation.md">See implementation method</a>

  
