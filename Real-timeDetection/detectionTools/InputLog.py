
class InputLog:

    __datetime = None
    __eventid=0
    __accountname=""
    __clientaddr=""
    __servicename=""
    __processname=""
    __objectname=""
    __sharedname=""
    __timecnt=0
    __isattack=False

    def __init__(self, datetime, eventid, accountname, clientaddr, servicename, processname, objectname, sharedname):
        self.__datetime = datetime
        self.__eventid=eventid
        self.__accountname=accountname
        self.__clientaddr=clientaddr
        self.__servicename=servicename
        self.__processname=processname
        self.__objectname=objectname
        self.__sharedname=sharedname

        #print(self.__datetime+","+str(self.__eventid)+", "+self.__accountname+", "+self.__clientaddr+""+self.__servicename+""+self.__processname+""+self.__objectname)

    def get_datetime(self):
        return self.__datetime

    def get_eventid(self):
        return self.__eventid

    def get_accountname(self):
        return self.__accountname

    def get_clientaddr(self):
        return self.__clientaddr

    def set_clientaddr(self,clientaddr):
        self.__clientaddr=clientaddr

    def get_servicename(self):
        return self.__servicename

    def get_processname(self):
        return self.__processname

    def set_processname(self, processname):
        self.__processname = processname

    def get_objectname(self):
        return self.__objectname

    def get_sharedname(self):
        return self.__sharedname