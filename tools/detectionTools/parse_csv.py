import csv
import sys
from signature_detection import SignatureDetector
import InputLog
from machine_learning import ML

DOMAIN_NAME='example2.local'

def preds(row):
    #print(row)
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
    if (eventid==SignatureDetector.EVENT_SHARE):
        item_account = [s for s in item if 'Account Name' in s]
        org_accountname = item_account[0].split(":")[1]

        item_clientaddr = [s for s in item if 'Source Address' in s]
        clientaddr = item_clientaddr[0].split(":")[1]

        item_sharedname = [s for s in item if 'Share Name' in s]
        sharedname = item_sharedname[0].split(":")[1]

    else:
        return SignatureDetector.RESULT_NORMAL

    datetime = datetime.strip("'")
    eventid = eventid.strip("'")
    if org_accountname != None:
        accountname = org_accountname.strip("'")
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

    # To specify parameter as Object
    inputLog = InputLog.InputLog(datetime, eventid, accountname, clientaddr, servicename, processname, objectname, sharedname)
    # update start by gam
    result = SignatureDetector.signature_detect(inputLog)

    # update end
    clientaddr = inputLog.get_clientaddr()
    processname=inputLog.get_processname()

    #print(inputLog.get_eventid()+","+inputLog.get_accountname()+","+inputLog.get_clientaddr()+","+inputLog.get_processname())

    if (result == SignatureDetector.RESULT_CMD or result == SignatureDetector.RESULT_MAL_CMD):
        result = ML.preds(eventid, accountname, processname, objectname, base_dummies_4674, clf_4674, base_dummies_4688, clf_4688)
    if (result != SignatureDetector.RESULT_NORMAL and result != ML.RESULT_WARN):
        print(datetime+ ',' +accountname + ',' + ',' + clientaddr + ',' + sharedname)
        print("send alert!!")
        #send_alert.Send_alert(result, datetime, eventid, accountname, clientaddr, servicename, processname, objectname, sharedname)

    return result

def read_csv(file_name):

    with open(file_name, 'r') as f:
        reader = csv.reader(f)
        header = next(reader)

        for row in reader:
            if row:
                print(preds(row))

if __name__ == '__main__':
    print(sys.argv[1])
    read_csv(sys.argv[1])