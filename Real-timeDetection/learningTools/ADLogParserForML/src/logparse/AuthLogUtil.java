package logparse;

public class AuthLogUtil {
	// Alert Level
	protected enum Alert {
		SEVERE, WARNING, NOTICE, NONE
	}
	// Alert type
	protected enum AlertType {
		NoTGT, MALCMD, ADMINSHARE, PSEXEC,NoADMIN, NoSystemCMD,NONE
	}
	
	// Command execution rate for alert
	protected static double ALERT_SEVIRE = 0.80;
	protected static double ALERT_WARNING = 0.2;
	
}
