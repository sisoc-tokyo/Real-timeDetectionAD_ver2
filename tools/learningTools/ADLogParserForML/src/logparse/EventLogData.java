package logparse;

import logparse.AuthLogUtil.Alert;
import logparse.AuthLogUtil.AlertType;

public class EventLogData {
	
	private String date="";
	private String accountName="";
	private String clientAddress="";
	private int eventID;
	private int clientPort;
	private String serviceName = "";
	private String processName = "";
	private String shredName = "";
	private String objectName = "";
	private String privilege="";
	private long timeCnt;
	private short isGolden=0;
	private Alert alertLevel=Alert.NONE;
	private AlertType alertType=AlertType.NONE;
	
	EventLogData(String date, String clientAddress, String accountName, int eventID, int clientPort, String serviceName, 
			String processName,long timeCnt){
		this.date=date;
		this.accountName=accountName;
		this.clientAddress=clientAddress;
		this.eventID=eventID;
		this.clientPort=clientPort;
		this.serviceName=serviceName;
		this.processName=processName;
		this.timeCnt=timeCnt;
	}
	
	public void setDate(String date){
		this.date=date;
	}
	
	public void setAccountName(String accountName){
		this.accountName=accountName;
	}
	
	public String getDate(){
		return this.date;
	}
	
	public String getAccountName(){
		return this.accountName;
	}
	public String getClientAddress(){
		return this.clientAddress;
	}
	public void setClientAddress(String clientAddres){
		this.clientAddress=clientAddres;
	}
	public int getEventID(){
		return this.eventID;
	}
	public int getClientPort(){
		return this.clientPort;
	}
	public String getServiceName(){
		return this.serviceName;
	}
	public void setServiceName(String serviceName){
		this.serviceName=serviceName;
	}
	public String getProcessName(){
		return this.processName;
	}
	public long getTimeCnt(){
		return this.timeCnt;
	}
	public short isGolden(){
		return this.isGolden;
	}
	public void setIsGolden(short isGolden){
		this.isGolden=isGolden;
	}
	public void settimeCnt(long timeCnt){
		this.timeCnt=timeCnt;
	}
	public Alert getAlertLevel(){
		return this.alertLevel;
	}
	public void setAlertLevel(Alert alertLevel){
		this.alertLevel=alertLevel;
	}
	public AlertType getAlertType(){
		return this.alertType;
	}
	public void setAlertType(AlertType alertType){
		this.alertType=alertType;
	}
	public void setSharedName(String shredName){
		this.shredName=shredName;
	}
	public String getSharedName(){
		return this.shredName;
	}
	public void setObjectName(String objectName){
		this.objectName=objectName;
	}
	public String getObjectName(){
		return this.objectName;
	}
	public void setPrivilege(String privilege){
		this.privilege=privilege;
	}
	public String getPrivilege(){
		return this.privilege;
	}
}
