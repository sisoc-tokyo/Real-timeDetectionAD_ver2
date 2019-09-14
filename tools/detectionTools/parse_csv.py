import csv
import os
import sys
import glob
from signature_detection import SignatureDetector
import InputLog
#from machine_learning import ML
#from sklearn.externals import joblib
import pandas as pd

RESULT_FILE='result.csv'
DOMAIN_NAME='example2'
MODE_ML='ml'
MODE_WHITE='whitelist'
TARGET_EVT=[SignatureDetector.EVENT_TGT,SignatureDetector.EVENT_ST,SignatureDetector.EVENT_PRIV,SignatureDetector.EVENT_PROCESS,
            SignatureDetector.EVENT_PRIV_SERVICE,SignatureDetector.EVENT_PRIV_OPE,SignatureDetector.EVENT_SHARE,SignatureDetector.EVENT_LOGIN,SignatureDetector.EVENT_NTLM]

# clf_4674 = joblib.load('ocsvm_gt_4674.pkl')
# base_dummies_4674 = pd.read_csv('data_dummies_4674.csv')
# clf_4688 = joblib.load('ocsvm_gt_4688.pkl')
# base_dummies_4688 = pd.read_csv('data_dummies_4688.csv')

SignatureDetector.df_admin = pd.read_csv("./admin.csv")
SignatureDetector.df_cmd = pd.read_csv("./command.csv")
SignatureDetector.df_cmd_white = pd.read_csv("./whitelist.csv")

mode=MODE_WHITE

logfile="err.log"
file=None

def preds(row,file):
    global logfile
    datetime=''
    eventid=''
    accountname=''
    clientaddr=''
    servicename=''
    processname=''
    objectname=''
    sharedname=''
    result=''
    file=''
    try:
        datetime = row[1]
        eventid = row[3]
        msg=row[5]
        item=msg.split("\n")
        org_accountname =""
        clientaddr=""
        sharedname=""
        servicename = ""
        processname = ""
        objectname = ""
        securityid=""
        if (eventid in TARGET_EVT):
            if eventid == SignatureDetector.EVENT_NTLM:
                item_account = [s for s in item if 'ログオン アカウント' in s]
                org_accountname = item_account[0].split(":")[1]
            else:
                item_account = [s for s in item if 'アカウント名' in s]
                org_accountname = item_account[0].split(":")[1]
            if eventid == SignatureDetector.EVENT_LOGIN:
                org_accountname = item_account[1].split(":")[1]

            item_clientaddr=""
            item_clientaddr = [s for s in item if '送信元アドレス' in s]
            if len(item_clientaddr) == 0:
                item_clientaddr = [s for s in item if 'クライアント アドレス' in s]
            if len(item_clientaddr) == 0:
                item_clientaddr = [s for s in item if 'ソース ネットワーク アドレス' in s]
            if len(item_clientaddr) == 0:
                item_clientaddr = [s for s in item if 'ソース ワークステーション' in s]
            if(len(item_clientaddr)>=1):
                clientaddr = item_clientaddr[0].split(":")[len(item_clientaddr[0].split(":"))-1]

            item_service=""
            item_service = [s for s in item if 'サービス名' in s]
            if(len(item_service)>=2):
                servicename = item_service[0].split(":")[1]

            item_process = ""
            item_process = [s for s in item if 'プロセス名' in s]
            if (len(item_process) >= 2):
                processname = item_process[0].split("新しいプロセス名:")[1]
            elif (len(item_process) >=1):
                processname = item_process[0].split("プロセス名:")[1]

            item_obj = ""
            item_obj = [s for s in item if 'オブジェクト名' in s]
            if (len(item_obj) >= 2):
                objectname = item_obj[0].split(":")[1]

            item_id = ""
            item_id = [s for s in item if 'セキュリティ ID' in s]
            if (len(item_id) >= 1):
                securityid = item_id[0].split(":")[1]

            if (eventid==SignatureDetector.EVENT_SHARE):
                item_sharedname = [s for s in item if '共有名' in s]
                sharedname = item_sharedname[0].split(":")[1]

        else:
            return SignatureDetector.RESULT_NORMAL

        datetime = datetime.strip("'")
        eventid = eventid.strip("'")
        if org_accountname != None:
            accountname = org_accountname.strip("'")
            accountname = accountname.strip()
            accountname = accountname.strip('\t')
            accountname = accountname.lower()
            accountname = accountname.split('@')[0]
            if (accountname.find(DOMAIN_NAME)> -1 or len(accountname)==0):
                return SignatureDetector.RESULT_NORMAL
        if clientaddr != None:
            clientaddr = clientaddr.strip("'")
        if servicename != None:
            servicename = servicename.strip("'")
            servicename = servicename.lower()
        if processname != None:
            processname = processname.strip("'")
            processname = processname.lower()
        if objectname != None:
            objectname = objectname.strip("'")
            objectname = objectname.lower()
        if sharedname != None:
            sharedname = sharedname.strip("'")
            sharedname = sharedname.lower()
        if securityid != None:
            securityid = securityid.strip("'")
            securityid = securityid.strip()
            securityid = securityid.strip('\t')
            securityid = securityid.lower()

        # To specify parameter as Object
        inputLog = InputLog.InputLog(datetime, eventid, accountname, clientaddr, servicename, processname, objectname, sharedname,securityid)
        # update start by gam
        result = SignatureDetector.signature_detect(inputLog)

        # update end
        clientaddr = inputLog.get_clientaddr()
        processname=inputLog.get_processname()

        if (result == SignatureDetector.RESULT_CMD or result == SignatureDetector.RESULT_MAL_CMD):
            if(mode==MODE_ML):
                #result = ML.preds(eventid, accountname, processname, objectname, base_dummies_4674, clf_4674, base_dummies_4688, clf_4688)
                print()
            else:
                processname = processname.strip().strip("'")
                result = SignatureDetector.check_cmd_whitelist(processname)

        if (result != SignatureDetector.RESULT_NORMAL
                #and result != ML.RESULT_WARN
        ):
            print(result)
            print(msg)
            #send_alert.Send_alert(result, datetime, eventid, accountname, clientaddr, servicename, processname, objectname, sharedname)

    except Exception as e:
        file = open(logfile, 'a')
        file.write(msg)
        file.write(e)

    with open(RESULT_FILE, 'a') as f:
        writer = csv.writer(f)
        writer.writerow([datetime, eventid, accountname, clientaddr, servicename, processname, objectname, sharedname,result,file])

    return result

def read_csv(inputdir):

    files = glob.glob(inputdir+"/*.csv")
    for file in files:
        #print(file)
        with open(file, 'r') as f:
            reader = csv.reader(f)
            header = next(reader)
            for row in reader:
                if row:
                    preds(row,file)


read_csv(sys.argv[1])