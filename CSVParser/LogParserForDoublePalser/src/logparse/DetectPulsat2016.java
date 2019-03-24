package logparse;

import java.io.*;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.*;
import java.util.*;

import logparse.AuthLogUtil;
import logparse.AuthLogUtil.Alert;

/**
 * Golden Ticket detection using Windows Event log 4674.
 * 
 * @version 1.0
 * @author Mariko Fujimoto
 */
public class DetectPulsat2016 {
	// Initial value for timeCnt
	private static short TIME_CNT = Short.MAX_VALUE;
	
	private static Map<String, LinkedHashSet<EventLogData>> log;
	private static String outputDirName = null;
	private static int EVENT_SHARE = 5140;

	private static String ACCOUNT_SYSTEM = "system";
	private static String ACCOUNT_ANONYMOUS = "anonymous logon";
	private static String PRIV = "setcbprivilege";
	private static String PROCESS_NAME_1 = "rundll32.exe";
	private static String PROCESS_NAME_2 = "cmd.exe";
	private static String SHARE_NAME = "\\c$";
	private static String SHARE_NAME_ADMIN = "\\admin$";
	private static String SHARE_NAME_IPC = "\\ipc$";

	// account name for detection
	private Set<String> clients = new LinkedHashSet<String>();

	private FileWriter filewriter = null;
	private BufferedWriter bw = null;
	private PrintWriter pw = null;
	private short timeCnt = TIME_CNT;

	// Data format
	private static SimpleDateFormat sdf = new SimpleDateFormat(
			"yyyy/MM/dd HH:mm:ss");

	// private static boolean removeNoise = false;

	private void readCSV(String filename) {

		try {
			File f = new File(filename);
			BufferedReader br = new BufferedReader(new FileReader(f));
			String line;
			int eventID = -1;
			String date = "";
			LinkedHashSet<EventLogData> evSet = null;
			String accountName = "";
			String clientAddress = "";
			String serviceName = "";
			String processName = "";
			String shredName = "";
			String objectName = "";
			String privilege = "";
			boolean isTargetEvent = false;
			int limit = 0;

			// categorize same operations based on time stamp

			EventLogData ev = null;
			Date baseDate = null;
			Date logDate = null;
			while ((line = br.readLine()) != null) {
				int clientPort = 0;
				// Remove tab
				line = line.replaceAll("\\t", "");
				String[] data = line.split(",", 0);
				for (String elem : data) {
					if (line.contains("Microsoft-Windows-Security-Auditing,")) {
						date = data[1];
						eventID = Integer.parseInt(data[3]);
						if (
							line.contains(String.valueOf(EVENT_SHARE))) {
							isTargetEvent = true;

						} else {
							isTargetEvent = false;
						}
					} else if (isTargetEvent) {
						if (elem.contains("アカウント名:")
								|| elem.contains("Account Name:")) {
							accountName = parseElement(elem, ":", limit);
							if (accountName.isEmpty()) {
								continue;
							} else {
								accountName = accountName.split("@")[0]
										.toLowerCase();
							}

						} else if (elem.contains("サービス名:")
								|| elem.contains("Service Name:")) {
							serviceName = parseElement(elem, ":", limit);
						} else if (elem.contains("クライアント アドレス:")
								|| elem.contains("Client Address:")
								|| elem.contains("ソース ネットワーク アドレス:")
								|| elem.contains("Source Network Address:")
								|| elem.contains("送信元アドレス:")
								|| elem.contains("Source Address:")) {
							elem = elem.replaceAll("::ffff:", "");
							clientAddress = parseElement(elem, ":", limit);
							clients.add(clientAddress);
							if (null == log.get(clientAddress)) {
								evSet = new LinkedHashSet<EventLogData>();
							} else {
								evSet = log.get(clientAddress);
							}
						} else if (elem.contains("共有名:")
								|| elem.contains("Share Name:")) {
							
							shredName = parseElement(elem, ":", 2)
									.toLowerCase();
							try {
								// Get date
								if (shredName.endsWith(SHARE_NAME_IPC) && accountName.endsWith("$")) {
									baseDate = sdf.parse(date);
									timeCnt--;
								} 
								}catch (ParseException e) {
									e.printStackTrace();
								}
							ev = new EventLogData(date, clientAddress,
									accountName, eventID, clientPort,
									serviceName, processName, timeCnt);
							ev.setSharedName(shredName);
							evSet.add(ev);
							log.put(clientAddress, evSet);
							accountName="";
							shredName = "";
							clientAddress = "";
						} 
						try {
							logDate = sdf.parse(date);
							if (null != baseDate) {
								long logTime = logDate.getTime();
								long baseTime = baseDate.getTime();
								long timeDiff = (baseTime - logTime) / 1000;
								if (timeDiff > 2) {
									timeCnt--;
									baseDate = sdf.parse(date);
								}
							} 
						} catch (ParseException e) {
							e.printStackTrace();
						}
					}
				}
			}
			br.close();
		} catch (IOException e) {
			System.out.println(e);
		}

	}

	private String parseElement(String elem, String delimiter, int limit) {
		String value = "";
		try {
			String elems[] = elem.trim().split(delimiter, limit);
			if (elems.length >= 2) {
				value = elems[1];
				value = value.replaceAll("\t", "");
			}
		} catch (RuntimeException e) {
			System.out.println(elem);
			e.printStackTrace();
		}
		if (value.isEmpty()) {
			value = "";
		}
		return value;
	}

	private void outputResults(Map map, String outputFileName) {
		try {
			// normal result
			filewriter = new FileWriter(outputFileName, true);
			bw = new BufferedWriter(filewriter);
			pw = new PrintWriter(bw);
			pw.println("eventID,account,computer,process,sharename,privilege,attack,time,date");
			ArrayList<EventLogData> list = null;
			
			Map<String, LinkedHashSet> kerlog = new LinkedHashMap<String, LinkedHashSet>();
			Map<Long, LinkedHashSet> timeBasedlog = new LinkedHashMap<Long, LinkedHashSet>();

			for (String client : clients) {
				
				LinkedHashSet<EventLogData> evS = log.get(client);
				
				if (null == evS) {
					continue;
				}
/*
				for (EventLogData ev : evS) {
					if (null == ev) {
						continue;
					}
					LinkedHashSet<EventLogData> evSet;
					String clientAddress = ev.getClientAddress();
					if (null != kerlog.get(clientAddress)) {
						evSet = kerlog.get(clientAddress);
					} else {
						evSet = new LinkedHashSet<EventLogData>();
					}
					evSet.add(ev);
					kerlog.put(ev.getClientAddress(), evSet);
				}

				for (Iterator it = kerlog.entrySet().iterator(); it.hasNext();) {
					Map.Entry<String, LinkedHashSet> entry = (Map.Entry<String, LinkedHashSet>) it
							.next();
					String computer = entry.getKey();

				}
*/
				list = new ArrayList<EventLogData>(evS);
				Collections.reverse(list);
				for (EventLogData ev : list) {
					if (null == ev) {
						continue;
					}
					LinkedHashSet<EventLogData> evSet;
					if (null != timeBasedlog.get(ev.getTimeCnt())) {
						evSet = timeBasedlog.get(ev.getTimeCnt());
					} else {
						evSet = new LinkedHashSet<EventLogData>();
					}
					evSet.add(ev);
					timeBasedlog.put(ev.getTimeCnt(), evSet);
				}
			}
			isOutlier(timeBasedlog);
			outputLogs(timeBasedlog);
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			pw.close();
			try {
				bw.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}

	private void isOutlier(Map<Long, LinkedHashSet> timeBasedlog) {
		for (Iterator it = timeBasedlog.entrySet().iterator(); it.hasNext();) {
			Map.Entry<Long, LinkedHashSet> entry = (Map.Entry<Long, LinkedHashSet>) it
					.next();
			long key=(Long)entry.getKey();
			//System.out.println(key);
			LinkedHashSet<EventLogData> evS = (LinkedHashSet<EventLogData>) entry
					.getValue();
			boolean attackPriv=false;
			boolean attackProcess=false;
			boolean adminShare=false;
			boolean ipc=false;
			for (EventLogData ev : evS) {
				if (5140 == ev.getEventID()) {
					// sharename is c$ or admin$, and account is computer account
					if ((ev.getAccountName().endsWith("$") && ev.getSharedName().contains(SHARE_NAME))
							|| (ev.getAccountName().endsWith("$") && ev.getSharedName().contains(SHARE_NAME_ADMIN))) {
						adminShare=true;
						//System.out.println("adminShare:"+ev.getTimeCnt());
						//System.out.println("adminShare:"+ev.getSharedName()+","+ev.getAccountName());
					} 
					if (ev.getSharedName().contains(SHARE_NAME_IPC)) {
						ipc=true;
						//System.out.println("ipc:"+ev.getTimeCnt());
						//System.out.println("ipc:"+ev.getSharedName()+","+ev.getAccountName());
					} 
				}
			}
			//System.out.println(attackPriv+","+attackProcess+","+adminShare+",");
			if(ipc&&adminShare){
				System.out.println("attack!!");
				for (EventLogData ev : evS) {
					short isGolden = 1;
					ev.setIsGolden(isGolden);
				}
			}
		}

	}

	private void outputLogs(Map<Long, LinkedHashSet> kerlog) {
		for (Iterator it = kerlog.entrySet().iterator(); it.hasNext();) {
			Map.Entry<Long, LinkedHashSet> entry = (Map.Entry<Long, LinkedHashSet>) it
					.next();
			LinkedHashSet<EventLogData> evS = (LinkedHashSet<EventLogData>) entry
					.getValue();
			for (EventLogData ev : evS) {
				int eventID = ev.getEventID();
				if (eventID == EVENT_SHARE) {
					pw.println(ev.getEventID() + "," + ev.getAccountName() + "," 
							+ ev.getClientAddress()+ "," 
							+ ev.getProcessName() + "," + ev.getSharedName()
							+ "," + ev.getPrivilege()
							+ "," + ev.isGolden()+ "," + ev.getTimeCnt()+ "," + ev.getDate());
				}
			}
		}

	}

	/**
	 * Judge whether the log is outlier
	 * 
	 * @param inputDirname
	 */
	public void detectGolden(String inputDirname) {
		File dir = new File(inputDirname);
		File[] files = dir.listFiles();

		for (File file : files) {
			String filename = file.getName();
			if (filename.endsWith(".csv")) {
				readCSV(file.getAbsolutePath());
			} else {
				continue;
			}
		}
		outputResults(log, this.outputDirName + "/" + "eventlog.csv");
	}

	private void detelePrevFiles(String outDirname) {
		Path path = Paths.get(outDirname);
		try (DirectoryStream<Path> ds = Files.newDirectoryStream(path, "*.*")) {
			for (Path deleteFilePath : ds) {
				Files.delete(deleteFilePath);
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private static void printUseage() {
		System.out.println("Useage");
		System.out.println("{iputdirpath} {outputdirpath}");
	}

	public static void main(String args[]) throws ParseException {
		DetectPulsat2016 authLogParser = new DetectPulsat2016();
		String inputdirname = "";
		if (args.length < 2) {
			printUseage();
		} else
			inputdirname = args[0];
		outputDirName = args[1];
		log = new LinkedHashMap<String, LinkedHashSet<EventLogData>>();
		authLogParser.detelePrevFiles(outputDirName);
		authLogParser.detectGolden(inputdirname);
	}

}
