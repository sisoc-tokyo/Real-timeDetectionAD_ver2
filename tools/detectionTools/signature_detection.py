import csv
import io
import pandas as pd
import InputLog
import dateutil.parser
import time

class SignatureDetector:

    EVENT_TGT = "4768"
    EVENT_ST="4769"
    EVENT_PRIV = "4672"
    EVENT_PROCESS = "4688"
    EVENT_PRIV_SERVICE = "4673"
    EVENT_PRIV_OPE = "4674"
    EVENT_SHARE = "5140"
    SYSTEM_DIR = "c:\windows";
    SYSTEM_DIR2 = "c:\program files";
    PSEXESVC = "psexesvc";
    ADMINSHARE="\c$"
    ADMINSHARE_2 = "admin$"
    IPC = "\ipc$"
    SYSTEM="system"
    ANONYMOUS="anonymous logon"
    CMD="cmd.exe"
    RESULT_NORMAL="normal"
    RESULT_PRIV="attack: Unexpected privilege is used"
    RESULT_CMD="attack: command on blackList is used"
    RESULT_MAL_CMD = "attack: Abnormal command or tool is used"
    RESULT_ADMINSHARE = "attack: Admin share is used"
    RESULT_NOTGT="attack: Golden Ticket is used"
    RESULT_ROMANCE = "attack: Eternal Romance is used"
    WARN = "warning:ST without TGT"

    df=pd.DataFrame(data=None, index=None, columns=["datetime","eventid","accountname","clientaddr","servicename","processname","objectname","sharename", "securityid"], dtype=None, copy=False)
    df_admin = pd.DataFrame(data=None, index=None, columns=[ "accountname"], dtype=None, copy=False)
    df_cmd = pd.DataFrame(data=None, index=None, columns=["processname"], dtype=None, copy=False)
    df_cmd_white = pd.DataFrame(data=None, index=None, columns=["processname"], dtype=None, copy=False)


    def __init__(self):
        print("constructor called")

    def is_attack(self):
        print("is_attack called")

    @staticmethod
    def signature_detect(datetime, eventid, accountname, clientaddr, servicename, processname, objectname, sharedname, securityid):
        """ Detect attack using signature based detection.
        :param datetime: Datetime of the event
        :param eventid: EventID
        :param accountname: Accountname
        :param clientaddr: Source IP address
        :param servicename: Service name
        :param processname: Process name(command name)
        :param objectname: Object name
        :return : True(1) if attack, False(0) if normal
        """

        inputLog = InputLog.InputLog(datetime, eventid, accountname, clientaddr, servicename, processname, objectname, sharedname, securityid)
        return SignatureDetector.signature_detect(inputLog)

    @staticmethod
    def signature_detect(inputLog):
        """ Detect attack using signature based detection.
        :param inputLog: InputLog object of the event
        :return : True(1) if attack, False(0) if normal
        """

        #print(SignatureDetector.df)

        #SignatureDetector.df["accountname"] = SignatureDetector.df["accountname"].str.lower()

        result=SignatureDetector.RESULT_NORMAL


        if (inputLog.get_eventid()==SignatureDetector.EVENT_ST) :
            result=SignatureDetector.hasNoTGT(inputLog)

        elif (inputLog.get_eventid() == SignatureDetector.EVENT_PRIV):
            result =SignatureDetector.isNotAdmin(inputLog)

        elif (inputLog.get_eventid() == SignatureDetector.EVENT_PRIV_OPE
                or inputLog.get_eventid() == SignatureDetector.EVENT_PRIV_SERVICE):
            result = SignatureDetector.isSuspiciousProcess(inputLog)

        elif (inputLog.get_eventid() == SignatureDetector.EVENT_PROCESS):
            result = SignatureDetector.isEternalBlue(inputLog)
            if (result== SignatureDetector.RESULT_NORMAL ):
                result = SignatureDetector.isSuspiciousProcess(inputLog)

        elif (inputLog.get_eventid() == SignatureDetector.EVENT_SHARE):
            result = SignatureDetector.isEternalRomace(inputLog)
            if (result == SignatureDetector.RESULT_NORMAL):
                result =SignatureDetector.isAdminshare(inputLog)

        series = pd.Series([inputLog.get_datetime(),inputLog.get_eventid(),inputLog.get_accountname(),inputLog.get_clientaddr(),
                      inputLog.get_servicename(),inputLog.get_processname(),inputLog.get_objectname(), inputLog.get_sharedname(), inputLog.get_securityid()], index=SignatureDetector.df.columns)
        SignatureDetector.df=SignatureDetector.df.append(series, ignore_index = True)

        return result

    @staticmethod
    def hasNoTGT(inputLog):
        time.sleep(1)
        SignatureDetector.df["eventid"]=SignatureDetector.df["eventid"].astype(str)
        logs=SignatureDetector.df[(SignatureDetector.df.accountname == inputLog.get_accountname())
                                  &(SignatureDetector.df.clientaddr==inputLog.get_clientaddr())
                                  & (SignatureDetector.df.eventid == SignatureDetector.EVENT_TGT)
        ]
        if len(logs)==0:
            SignatureDetector.df.to_csv("df.csv")
            print("Signature D: " + SignatureDetector.WARN)
            return SignatureDetector.WARN
        else:
            return SignatureDetector.RESULT_NORMAL

    @staticmethod
    def isNotAdmin(inputLog):
        logs = SignatureDetector.df_admin[(SignatureDetector.df_admin.accountname == inputLog.get_accountname())]
        if len(logs) == 0:
            print("Signature A: " + SignatureDetector.RESULT_PRIV)
            return SignatureDetector.RESULT_PRIV
        else:
            return SignatureDetector.RESULT_NORMAL

    @staticmethod
    def isSuspiciousProcess(inputLog):

        logs = SignatureDetector.df[(SignatureDetector.df.accountname == inputLog.get_accountname())
                                    & (SignatureDetector.df.eventid == SignatureDetector.EVENT_ST)
                                    ]
        latestlog=logs.tail(1)
        if(len(latestlog)>0):
            clientaddr=latestlog.clientaddr.values[0]
            inputLog.set_clientaddr(clientaddr)

        #print(inputLog.get_clientaddr()+","+inputLog.get_accountname())

        if (inputLog.get_processname().find(SignatureDetector.SYSTEM_DIR)==-1 and inputLog.get_processname().find(SignatureDetector.SYSTEM_DIR2)==-1):
            print("Signature B: "+SignatureDetector.RESULT_MAL_CMD)
            return SignatureDetector.RESULT_MAL_CMD
        cmds=inputLog.get_processname().split("\\")
        cmd=cmds[len(cmds)-1]
        logs = SignatureDetector.df_cmd[SignatureDetector.df_cmd.processname.str.contains(cmd)]
        if len(logs)>0:
            print("Signature B: " + SignatureDetector.RESULT_CMD)
            return SignatureDetector.RESULT_CMD

        if inputLog.get_objectname().find(SignatureDetector.PSEXESVC)>=0:
            print("Signature B: " + SignatureDetector.RESULT_CMD)
            return SignatureDetector.RESULT_CMD

        return SignatureDetector.RESULT_NORMAL

    @staticmethod
    def check_cmd_whitelist(processname):
        logs = SignatureDetector.df_cmd_white[(SignatureDetector.df_cmd_white.processname == processname)]
        if len(logs) == 0:
            print("Signature B: " + SignatureDetector.RESULT_CMD)
            return SignatureDetector.RESULT_CMD
        else:
            return SignatureDetector.RESULT_NORMAL

    @staticmethod
    def isAdminshare(inputLog):
        if inputLog.get_sharedname().find(SignatureDetector.ADMINSHARE)>=0:
            print("Signature C: " + SignatureDetector.RESULT_ADMINSHARE)
            return SignatureDetector.RESULT_ADMINSHARE

        return SignatureDetector.RESULT_NORMAL

    @staticmethod
    def isEternalRomace(inputLog):
        time.sleep(1)
        logs=None
        # share name is 'IPC' and account is computer account
        if (inputLog.get_sharedname().find(SignatureDetector.IPC)>=0 and inputLog.get_accountname().endswith("$")):
                # Check whether admin share with computer account is used within 2 seconds
            logs = SignatureDetector.df[SignatureDetector.df.accountname.str.endswith("$")]
            logs = logs[(SignatureDetector.df.clientaddr == inputLog.get_clientaddr())
                        & ((SignatureDetector.df.sharename.str.endswith(SignatureDetector.ADMINSHARE)
                        |SignatureDetector.df.sharename.str.endswith(SignatureDetector.ADMINSHARE_2)))]

        if (inputLog.get_sharedname().find(SignatureDetector.ADMINSHARE)>=0 or inputLog.get_sharedname().find(SignatureDetector.ADMINSHARE_2)>=0):
                # account name ends with '$'
            if (inputLog.get_accountname().endswith("$")):
                logs = SignatureDetector.df[SignatureDetector.df.accountname.str.endswith("$")]
                logs = logs[(SignatureDetector.df.clientaddr == inputLog.get_clientaddr())
                                & (SignatureDetector.df.sharename.str.endswith(SignatureDetector.IPC))]

        if ((logs is not None) and len(logs) > 0):
            now=dateutil.parser.parse(inputLog.get_datetime())
            last_date=dateutil.parser.parse(logs.tail(1).datetime.str.cat())
            diff=(now-last_date).total_seconds()
            if(diff<2):
                print("Signature E: " + SignatureDetector.RESULT_ROMANCE)
                return SignatureDetector.RESULT_ROMANCE

        return SignatureDetector.RESULT_NORMAL


    @staticmethod
    def isEternalBlue(inputLog):
        time.sleep(1)
        # security id is system and process name is cmd.exe
        if (inputLog.get_securityid()==SignatureDetector.SYSTEM and inputLog.get_processname().endswith(SignatureDetector.CMD)):
                # Check whether ANONYMOUS IPC access is used within 2 seconds
            logs = SignatureDetector.df[(SignatureDetector.df.securityid == SignatureDetector.ANONYMOUS)
                        & (SignatureDetector.df.sharename.str.endswith(SignatureDetector.IPC))]

            if len(logs) > 0:
                now=dateutil.parser.parse(inputLog.get_datetime())
                last_date=dateutil.parser.parse(logs.tail(1).datetime.str.cat())
                diff=(now-last_date).total_seconds()
                if(diff<180):
                    print("Signature E: " + SignatureDetector.RESULT_ROMANCE)
                    return SignatureDetector.RESULT_ROMANCE

        return SignatureDetector.RESULT_NORMAL
