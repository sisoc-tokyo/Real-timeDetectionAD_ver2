from signature_detection import SignatureDetector
import InputLog

class identify_attack:
    TACTICS={"TA0001": "Initial Access","TA0002":"Execution","TA0003":"Persistence","TA0004": "Privilege Escalation",
             "TA0005":"Defense Evasion","TA0006":"Credential Access","TA0007":"Discovery","TA0008": "Lateral Movement",
             "TA0009": "Collection","TA0010":"Exfiltration","TA0011":"Command and Control"}

    @staticmethod
    def identify_tactics(result, inputLog):
        if(result==SignatureDetector.RESULT_PRIV):
            return TACTICS["TA0004"]

        elif(result==SignatureDetector.RESULT_ADMINSHARE):
            return TACTICS["TA0009"]

        elif (result == SignatureDetector.RESULT_ROMANCE):
            return TACTICS["TA0008"]

        elif (result == SignatureDetector.RESULT_NOTGT):
            return TACTICS["TA0003"]

        elif (result == SignatureDetector.RESULT_SILVER):
            return TACTICS["TA0003"]

        elif (result == SignatureDetector.RESULT_CMD):
            cmds = inputLog.get_processname().split("\\")
            cmd = cmds[len(cmds) - 1]
            cmd = cmds[len(cmds) - 1]
            log = SignatureDetector.df_cmd[(SignatureDetector.df_cmd.processname == cmd)].tail()
            tactics=log["tactics"].iat[0]
            return tactics

        return ""