from signature_detection import SignatureDetector
import InputLog

class identify_attack:
    TACTICS={"TA0001": "Initial Access","TA0002":"Execution","TA0003":"Persistence","TA0004": "Privilege Escalation",
             "TA0005":"Defense Evasion","TA0006":"Credential Access","TA0007":"Discovery","TA0008": "Lateral Movement",
             "TA0009": "Collection","TA0010":"Exfiltration","TA0011":"Command and Control"}

    @staticmethod
    def identify_tactics(result, inputLog):
        if (result == SignatureDetector.RESULT_NOTGT or result == SignatureDetector.RESULT_SILVER):
            return identify_attack.TACTICS["TA0003"]

        if(result==SignatureDetector.RESULT_PRIV):
            return identify_attack.TACTICS["TA0004"]

        elif(result==SignatureDetector.RESULT_ADMINSHARE):
            return identify_attack.TACTICS["TA0009"]

        elif (result == SignatureDetector.RESULT_ROMANCE):
            return identify_attack.TACTICS["TA0008"]

        elif (result == SignatureDetector.RESULT_NOTGT):
            return identify_attack.TACTICS["TA0003"]

        elif (result == SignatureDetector.RESULT_SILVER):
            return identify_attack.TACTICS["TA0003"]

        elif (result == SignatureDetector.RESULT_CMD):
            if (inputLog.get_processname() == "c:\\windows\\system32\\services.exe"):
                cmd = inputLog.get_objectname()
            else:
                cmds = inputLog.get_processname().split("\\")
                cmd = cmds[len(cmds) - 1]

            log = SignatureDetector.df_cmd[(SignatureDetector.df_cmd.processname == cmd)].tail()
            if len(log) > 0:
                tactics=log["tactics"].iat[0]

                return tactics

        return ""
