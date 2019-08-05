# Real-time detection of high-risk attacks leveraging Kerberos and SMB

## How to implement the tool
###	Tool detail
* <a href="https://github.com/sisoc-tokyo/Real-timeDetectionAD_ver2/tree/master/tools/detectionTools">Detection tools</a>
    * Files (programs)
        * rest_ocsvm_gt.py: REST API for Event Log analysis. It is called by Logstash for Event Logs.
        * signature_detection.py: Signature-based detection program using Event Logs. It is called by rest_ocsvm_gt.py.
        * es_ticket_detection_sql.py: REST API for packet analysis. It is called by Logstash for packet analysis.
        * detect_golden.py: a program for re-analysing the result of Event Log analysis.
        * send_alert.py: Program for sending alert mail. It is called by rest_ocsvm_gt.py.
        * identify_attack.py: Identify tactics of ATT&CK.
        * InputLog.py: data class for Event Logs.
        * machine_learning.py (optional): Machine learning detection program. It is called by rest_ocsvm_gt.py.
    * Files (data)
        * command.csv: A black list of commands which tend to be used for attacks
        * admin.csv: A list of administrator account used in daily operations
        * whitelist.csv  (optional): a white list of commands or tools used in daily operations
        * ocsvm_gt_XXXX.pkl files  (optional): Model files for Machine learning. They are created by Goldenticket_One-class_SVM.ipynb
        * data_dummies_XXXX.csv  (optional): One-Hot encoding dummy files for Machine learning. They are created by Goldenticket_One-class_SVM.ipynb
    * Location: Deploy on Detection Server
    * How to use: launch rest_ocsvm_gt.py and es_ticket_detection.py<br/>
    e.g.）python rest_ocsvm_gt.py <br/>
    python es_ticket_detection.py
    * Notes: REST API is running on Flask.

* <a href="https://github.com/sisoc-tokyo/Real-timeDetectionAD_ver2/tree/master/tools/logstash">Configuration files for Logstash for Event Logs</a>
    * Files
        * logstash_winlogbeat.conf: Configuration file of Logstash for Event Logs. Logs are sent through the pipline of Logstash. Logstash extract data for detection from logs and call the REST API "rest_ocsvm_gt.py".<br/>
        This file should be located in Log Server for Event Logs where Logstash is running. 
    * Location: Deploy on Log Server for Event Logs
    * How to use: 
        * Launch Logstash by specifing the conf file.<br/>
	    e.g.）logstash -f /etc/logstash/conf.d/logstash_winlogbeat.conf &<br/>

* <a href="https://github.com/sisoc-tokyo/Real-timeDetectionAD_ver2/tree/master/tools/logstash">Configuration files for Logstash for packets</a>
    * Files
        * tshark_ticket.conf: Configuration file of Logstash for packet analysis. Packets are sent through the pipline of Logstash. Logstash extract data for detection from logs and call the REST API "es_ticket_detection.py".<br/>
        This file should be located in Log Server for packets where Logstash is running. 
    * Location: Deploy on Log Server for packets
    * How to use: 
        * Launch Logstash by specifing the conf file.<br/>
	    e.g.）logstash -f /etc/logstash/conf.d/tshark_ticket.conf &<br/>
        * Launch tshark by the following command.<br/>
	    e.g.）tshark -i ens36 -l -Y 'kerberos.msg_type == 11 || kerberos.msg_type == 12 || kerberos.msg_type == 13 || kerberos.msg_type == 14 || kerberos.error_code == 32' -T ek  -e smb2.cmd -e smb2.credits.requested -e kerberos.cipher -e ip.dst -e ip.src -e kerberos.msg_type -e kerberos.error_code -e kerberos.CNameString -e kerberos.cipher -E occurrence=f  > /var/tmp/tshark_ticket.json &<br/>

* <a href="https://github.com/sisoc-tokyo/Real-timeDetectionAD_ver2/tree/master/tools/winlogbeat">Configuration files for Winlogbeat</a>
    * Files
        * winlogbeat.yml: Configuration file of Winlogbeat. This file should be located in Domain Controller where Winlogbeat is running. 
    * Location: Place in the install directory of Winlogbeat on Domain Controller
    * How to use: 
	    * Star Winlogbeat on Domain Controller
 
* <a href="https://github.com/sisoc-tokyo/Real-timeDetectionAD_ver2/tree/master/tools/learningTools">Machine learning tools (optional)</a>
Optionally, “Machine learning” can be used to reduce false positives through re-analyzing the signature-based detection. 
If the operational environment is stable, whitelists can be used instead of machine learning.
    * Files
        * ADLogParserForML: Java programs to prepare for creating input for Goldenticket_One-class_SVM.ipynb. This programs extract data from Event Logs exported as CSV files.<br/>
        We tested this program on Java 1.8 .
        * Goldenticket_One-class_SVM.ipynb : A Python program runnung on the Jupyter Notebook to create model and calculate detection rate.
    * Location: Deploy on Detection Server
    * How to use: 
        1. Export Domain Controller Event logs as CSV file format using built-in Windows function (Rigiht click Event Logs and save as csv file).
        
        2. Execute ADLogParserForML using the above Event Logs as inputs. Then parsed csv file (eventlog.csv) will be created.<br/>
        <pre>
        # cd ADLogParserForML/bin
        # java logparse/AuthLogParser /Users/Documents/tmp/input /Users/marikof/Documents/tmp/output  /Users/Documents/tmp/input/command.txt /Users/marikof/Documents/tmp/input/adminlist.txt
        </pre>
        
        3. Execute Goldenticket_One-class_SVM_create_model.ipynb.<br/>
        You will get model files (ocsvm_gt_XXXX.pkl) and One-Hot encoding dummy files (data_dummies_XXXX.csv). Please move or copy these file to "detectionTools" directory.
        
        4. If you want to see detection result, please check X_train_result4674.csv and X_train_result4688.csv files.The rightmost column shows result, "1" means normal and "-1" means outlier.
        
        
     * (Optional) If you want to evaluate with logs generated by attack, please refer below to create dataset. However created model files don't work, they are used for just check the result.:      
        1. Export Domain Controller Event logs as CSV file format using built-in Windows function (Rigiht click Event Logs and save as csv file).
        
        2. Execute ADLogParserForML using the above Event Logs as inputs. Then parsed csv file (eventlog.csv) will be created.<br/>
        <pre>
        # cd ADLogParserForML/bin
        # java logparse/AuthLogParser /Users/Documents/tmp/input /Users/marikof/Documents/tmp/output  /Users/Documents/tmp/input/command.txt /Users/marikof/Documents/tmp/input/adminlist.txt
        </pre>
          
        3. Open eventlog.csv and organize the value of "target" column as follows.
            * train
            * test
            * outlier
                        
            "train" data is training data and should be in normal states. Machine learning learns these data.<br/>
            "test" data means normal data. Machine lerning doe's not learn these data, they are used only for evaluation. Please change some target value from "train" to "test".<br/>
            "outlier" data means outlier data. Machine lerning doe's not learn these data, they are used only for evaluation. Please set target value "outlier" for logs of attack behavior.<br/>
                      
        4. Execute One-class_SVM.ipynb. You should specify the file path of eventlog.csv. <br/>
            You will get model files (ocsvm_gt_XXXX.pkl) and One-Hot encoding dummy files (data_dummies_XXXX.csv).
            
        5. If you want to see detection result, please check X_outliers_resultXXXX.csv, X_test_resultXXXX.csv and X_ourlier_resultXXXX.csv files.The rightmost column shows result, "1" means normal and "-1" means outlier.


  
