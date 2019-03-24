import smtplib
from email.mime.text import MIMEText
from email.utils import formatdate

FROM_ADDRESS = 'change here'
MY_PASSWORD = 'change here'
TO_ADDRESS = 'change here'
BCC = ''
SUBJECT = 'change here'

class Send_alert:

    def create_message(self, from_addr, to_addr, bcc_addrs, subject, result, datetime, eventid, accountname, clientaddr, servicename, processname, objectname, sharedname):
        body = 'Suspicious activity was detected.\n' + str(result) + '\nTime: ' + str(datetime) + '\nAccount: ' + str(accountname) + '\nIP address: ' + str(clientaddr) + '\nService name: ' + str(servicename) + '\nProcess name : ' + str(processname) + '\nObject name: ' + str(objectname) + '\nShared name: ' + str(sharedname)
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = from_addr
        msg['To'] = to_addr
        msg['Bcc'] = bcc_addrs
        msg['Date'] = formatdate()
        return msg


    def send(self,from_addr, to_addrs, msg):
        smtpobj = smtplib.SMTP('smtp.gmail.com', 587)
        smtpobj.ehlo()
        smtpobj.starttls()
        smtpobj.ehlo()
        smtpobj.login(FROM_ADDRESS, MY_PASSWORD)
        smtpobj.sendmail(from_addr, to_addrs, msg.as_string())
        smtpobj.close()

    def __init__(self, result, datetime, eventid, accountname, clientaddr, servicename, processname, objectname, sharedname):
        to_addr = TO_ADDRESS
        subject = SUBJECT
        msg = self.create_message(FROM_ADDRESS, to_addr, BCC, subject, result, datetime, eventid, accountname, clientaddr, servicename, processname, objectname, sharedname)
        self.send(FROM_ADDRESS, to_addr, msg)