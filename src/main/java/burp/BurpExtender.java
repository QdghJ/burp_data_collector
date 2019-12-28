package burp;

import burp.datacollector.dao.*;
import burp.datacollector.gui.DataCollectorGui;

import java.awt.*;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class BurpExtender implements IBurpExtender, ITab, IExtensionStateListener {

    private final static String extensionName = "BurpDataCollector";
    public final static String FULL_PATH = "full_path";
    public final static String PATH = "path";
    public final static String FILE = "file";
    public final static String DIR = "dir";
    public final static String PARAMETER = "parameter";

    private DataCollectorGui dataCollectorGui;
    private IBurpExtenderCallbacks callbacks;

    private ScheduledExecutorService service;

    // memory cache to check repeat
    private HashMap<String, HashMap<String, HashSet<String>>> memoryHostValueMap = new HashMap<>();

    // insert queue
    private HashMap<String, HashMap<String, HashSet<String>>> insertHostValueMap = new HashMap<>();


    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;

        callbacks.setExtensionName(extensionName);


        dataCollectorGui = new DataCollectorGui(BurpExtender.this);
        callbacks.addSuiteTab(BurpExtender.this);
        callbacks.registerExtensionStateListener(BurpExtender.this);

        loadConfig();

        if (DatabaseUtil.getInstance().initConnection(callbacks, dataCollectorGui.getMysqlHost(), dataCollectorGui.getMysqlPort(),
                dataCollectorGui.getMysqlUser(), dataCollectorGui.getMysqlPassword())) {
            callbacks.printOutput("database connect success");
        } else {
            callbacks.printOutput("database connect fail! please check you mysql config !");
        }

        service = Executors.newSingleThreadScheduledExecutor();
        service.scheduleWithFixedDelay(() -> {
            BurpExtender.this.saveData();
            callbacks.printOutput("Scheduled export execution completed");
        }, 0, 3, TimeUnit.MINUTES);

        callbacks.printOutput("load BurpDataCollector success !");
    }


    public void saveConfig() {
        callbacks.saveExtensionSetting(DataCollectorGui.MYSQL_HOST, dataCollectorGui.getMysqlHost());
        callbacks.saveExtensionSetting(DataCollectorGui.MYSQL_PORT, dataCollectorGui.getMysqlPort());
        callbacks.saveExtensionSetting(DataCollectorGui.MYSQL_USER, dataCollectorGui.getMysqlUser());
        callbacks.saveExtensionSetting(DataCollectorGui.MYSQL_PASSWORD, dataCollectorGui.getMysqlPassword());
        callbacks.saveExtensionSetting(DataCollectorGui.BLACK_LIST_EXT, dataCollectorGui.getBlackListExtStr());
    }

    private void loadConfig() {
        String mysqlHost = callbacks.loadExtensionSetting(DataCollectorGui.MYSQL_HOST);
        String mysqlPort = callbacks.loadExtensionSetting(DataCollectorGui.MYSQL_PORT);
        String mysqlUser = callbacks.loadExtensionSetting(DataCollectorGui.MYSQL_USER);
        String mysqlPassword = callbacks.loadExtensionSetting(DataCollectorGui.MYSQL_PASSWORD);
        String blackListExt = callbacks.loadExtensionSetting(DataCollectorGui.BLACK_LIST_EXT);
        if (mysqlHost != null) {
            dataCollectorGui.setMysqlHost(mysqlHost);
        }
        if (mysqlPort != null) {
            dataCollectorGui.setMysqlPort(mysqlPort);
        }
        if (mysqlUser != null) {
            dataCollectorGui.setMysqlUser(mysqlUser);
        }
        if (mysqlPassword != null) {
            dataCollectorGui.setMysqlPassword(mysqlPassword);
        }
        if (blackListExt != null) {
            dataCollectorGui.setBlackListExt(blackListExt);
        }
    }

    public IBurpExtenderCallbacks getCallbacks() {
        return callbacks;
    }

    @Override
    public String getTabCaption() {
        return "DataCollector";
    }

    @Override
    public Component getUiComponent() {
        return dataCollectorGui.$$$getRootComponent$$$();
    }

    @Override
    public void extensionUnloaded() {
        saveConfig();
        saveData();
        service.shutdownNow();
        DatabaseUtil.getInstance().closeConnection();
    }

    private boolean checkBlackExt(String path) {
        String[] exts = dataCollectorGui.getblackListExts();
        for (String ext : exts) {
            ext = ext.trim();
            if (path.endsWith(ext)) {
                return true;
            }
        }
        return false;
    }

    private void addToInsertMap(String host, String value, String flag) {
        HashMap<String, HashSet<String>> hostHashMap = insertHostValueMap.get(host);
        if (hostHashMap == null) {
            hostHashMap = new HashMap<>();
            HashSet<String> hostHashSet = new HashSet<>();
            hostHashSet.add(value);
            hostHashMap.put(flag, hostHashSet);
            insertHostValueMap.put(host, hostHashMap);
        } else {
            HashSet<String> hostHashSet = hostHashMap.get(flag);
            if (hostHashSet == null) {
                hostHashSet = new HashSet<>();
                hostHashSet.add(value);
                hostHashMap.put(flag, hostHashSet);
            } else {
                if (!hostHashSet.contains(value)) {
                    hostHashSet.add(value);
                }
            }
        }
    }

    private void cleanInsertMap() {
        insertHostValueMap = new HashMap<>();
    }

    private HashSet<String> getInsertHashSet(String host, String flag) {
        return insertHostValueMap.get(host).get(flag);
    }

    private boolean addToMemory(String host, String value, String flag) {
        boolean result = true;
        HashMap<String, HashSet<String>> hostHashMap = memoryHostValueMap.get(host);
        if (hostHashMap == null) {
            hostHashMap = new HashMap<>();
            HashSet<String> hostHashSet = new HashSet<>();
            hostHashSet.add(value);
            hostHashMap.put(flag, hostHashSet);
            memoryHostValueMap.put(host, hostHashMap);
            result = false;
        } else {
            HashSet<String> hostHashSet = hostHashMap.get(flag);
            if (hostHashSet == null) {
                hostHashSet = new HashSet<>();
                hostHashSet.add(value);
                hostHashMap.put(flag, hostHashSet);
                result = false;
            } else {
                if (!hostHashSet.contains(value)) {
                    hostHashSet.add(value);
                    result = false;
                }
            }
        }

        return result;
    }

    private boolean checkFullPath(String host, String fullPath) {
        if (fullPath.length() > 256)
            return false;

        if (fullPath.equals("/"))
            return false;

        if (checkBlackExt(fullPath))
            return false;

        if (addToMemory(host, fullPath, FULL_PATH))
            return false;


        return true;
    }

    private boolean checkPath(String host, String path) {

        if (path.length() > 256)
            return false;

        if (path.equals("/"))
            return false;

        if (addToMemory(host, path, PATH))
            return false;

        return true;
    }

    private boolean checkDir(String host, String dir) {

        if (dir.length() > 32)
            return false;

        if (dir.equals("//"))
            return false;

        if (addToMemory(host, dir, DIR))
            return false;

        return true;
    }

    private boolean checkFile(String host, String fileName) {

        if (fileName.length() > 256)
            return false;

        if (fileName.equals(""))
            return false;

        if (checkBlackExt(fileName))
            return false;

        if (addToMemory(host, fileName, FILE))
            return false;

        return true;
    }

    private boolean checkParameter(String host, String parameterName) {

        if (parameterName.length() > 64)
            return false;

        if (parameterName.equals("") || parameterName.equals("_"))
            return false;

        // is a word ?
        String reg = "^\\w+$";
        Matcher matcher = Pattern.compile(reg).matcher(parameterName);
        if (!matcher.find())
            return false;

        if (addToMemory(host, parameterName, PARAMETER))
            return false;

        return true;
    }

    public void saveData() {

        IHttpRequestResponse[] httpRequestResponses = callbacks.getProxyHistory();
        IExtensionHelpers helpers = callbacks.getHelpers();

        for (IHttpRequestResponse httpRequestResponse : httpRequestResponses) {
            IRequestInfo requestInfo = helpers.analyzeRequest(httpRequestResponse);
            String host = requestInfo.getUrl().getHost();
            String fullPath = requestInfo.getUrl().getPath();

            // insert full path : /aaa/bbb/ccc.php
            if (checkFullPath(host, fullPath))
                addToInsertMap(host, fullPath, FULL_PATH);

            String path = fullPath.substring(0, fullPath.lastIndexOf('/') + 1);

            // insert path : /aaa/bbb/
            if (checkPath(host, path))
                addToInsertMap(host, path, PATH);

            String[] dirs = path.split("/");

            // insert dir : aaa, bbb
            for (String dir : dirs) {
                dir = "/" + dir + "/";
                if (checkDir(host, dir))
                    addToInsertMap(host, path, DIR);
            }

            String fileName = fullPath.substring(fullPath.lastIndexOf("/") + 1);

            if (checkFile(host, fileName))
                addToInsertMap(host, fileName, FILE);

            List<IParameter> parameters = requestInfo.getParameters();
            for (IParameter parameter : parameters) {
                if (parameter.getType() != 2) {
                    String parameterName = parameter.getName();

                    if (checkParameter(host, parameterName))
                        addToInsertMap(host, parameterName, PARAMETER);
                }
            }

        }

        callbacks.printOutput("add data to insert queue finish");

        HostFileMapDao hostFileMapDao = new HostFileMapDao();
        HostFullPathMapDao hostFullPathMapDao = new HostFullPathMapDao();
        HostPathMapDao hostPathMapDao = new HostPathMapDao();
        HostDirMapDao hostDirMapDao = new HostDirMapDao();
        HostParameterMapDao hostParameterMapDao = new HostParameterMapDao();

        Set<String> hostSet = insertHostValueMap.keySet();
        for (String host : hostSet) {
            try {
                HashSet<String> fullPathSet = getInsertHashSet(host, FULL_PATH);
                if (fullPathSet != null)
                    hostFullPathMapDao.insertIgnoreHostFullPath(host, fullPathSet);

                HashSet<String> pathSet = getInsertHashSet(host, PATH);
                if (pathSet != null)
                    hostPathMapDao.insertIgnoreHostPath(host, pathSet);

                HashSet<String> dirSet = getInsertHashSet(host, DIR);
                if (dirSet != null)
                    hostDirMapDao.insertIgnoreHostDir(host, dirSet);

                HashSet<String> fileSet = getInsertHashSet(host, FILE);
                if (fileSet != null)
                    hostFileMapDao.insertIgnoreHostFile(host, fileSet);

                HashSet<String> parameterSet = getInsertHashSet(host, PARAMETER);
                if (parameterSet != null)
                    hostParameterMapDao.insertIgnoreHostParameter(host, parameterSet);

            } catch (Exception e) {
                e.printStackTrace();
                callbacks.printOutput(e.toString());
                dataCollectorGui.appendOutput(e.toString());
            }
        }

        // clear insert queue
        cleanInsertMap();

        callbacks.printOutput("export finish!");
        dataCollectorGui.appendOutput("export finish!");
    }


}
