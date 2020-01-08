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
    public final static String SUB = "sub";

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
        service.scheduleWithFixedDelay(new Runnable() {
            @Override
            public void run() {
                BurpExtender.this.saveData();
                callbacks.printOutput("Scheduled export execution completed");
            }
        }, 0, 10, TimeUnit.MINUTES);

        callbacks.printOutput("load " + extensionName + " success !");
    }


    public void saveConfig() {
        callbacks.saveExtensionSetting(DataCollectorGui.MYSQL_HOST, dataCollectorGui.getMysqlHost());
        callbacks.saveExtensionSetting(DataCollectorGui.MYSQL_PORT, dataCollectorGui.getMysqlPort());
        callbacks.saveExtensionSetting(DataCollectorGui.MYSQL_USER, dataCollectorGui.getMysqlUser());
        callbacks.saveExtensionSetting(DataCollectorGui.MYSQL_PASSWORD, dataCollectorGui.getMysqlPassword());
        callbacks.saveExtensionSetting(DataCollectorGui.BLACK_LIST_EXT, dataCollectorGui.getBlackListExtStr());
        callbacks.saveExtensionSetting(DataCollectorGui.PATH_COUNT, String.valueOf(dataCollectorGui.getPathCount()));
        callbacks.saveExtensionSetting(DataCollectorGui.FULL_PATH_COUNT, String.valueOf(dataCollectorGui.getFullPathCount()));
        callbacks.saveExtensionSetting(DataCollectorGui.DIR_COUNT, String.valueOf(dataCollectorGui.getDirCount()));
        callbacks.saveExtensionSetting(DataCollectorGui.FILE_COUNT, String.valueOf(dataCollectorGui.getFileCount()));
        callbacks.saveExtensionSetting(DataCollectorGui.PARAMETER_COUNT, String.valueOf(dataCollectorGui.getParameterCount()));
        callbacks.saveExtensionSetting(DataCollectorGui.SUB_COUNT, String.valueOf(dataCollectorGui.getSubCount()));

    }

    private void loadConfig() {
        String mysqlHost = callbacks.loadExtensionSetting(DataCollectorGui.MYSQL_HOST);
        String mysqlPort = callbacks.loadExtensionSetting(DataCollectorGui.MYSQL_PORT);
        String mysqlUser = callbacks.loadExtensionSetting(DataCollectorGui.MYSQL_USER);
        String mysqlPassword = callbacks.loadExtensionSetting(DataCollectorGui.MYSQL_PASSWORD);
        String blackListExt = callbacks.loadExtensionSetting(DataCollectorGui.BLACK_LIST_EXT);
        String pathCount = callbacks.loadExtensionSetting(DataCollectorGui.PATH_COUNT);
        String fullPathCount = callbacks.loadExtensionSetting(DataCollectorGui.FULL_PATH_COUNT);
        String dirCount = callbacks.loadExtensionSetting(DataCollectorGui.DIR_COUNT);
        String fileCount = callbacks.loadExtensionSetting(DataCollectorGui.FILE_COUNT);
        String parameterCount = callbacks.loadExtensionSetting(DataCollectorGui.PARAMETER_COUNT);
        String subCount = callbacks.loadExtensionSetting(DataCollectorGui.SUB_COUNT);

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
        if (pathCount != null) {
            dataCollectorGui.setPathCount(pathCount);
        }
        if (fullPathCount != null) {
            dataCollectorGui.setFullPathCount(fullPathCount);
        }
        if (dirCount != null) {
            dataCollectorGui.setDirCount(dirCount);
        }
        if (fileCount != null) {
            dataCollectorGui.setFileCount(fileCount);
        }
        if (parameterCount != null) {
            dataCollectorGui.setParameterCount(parameterCount);
        }
        if (subCount != null) {
            dataCollectorGui.setSubCount(subCount);
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

        if (path.equals("/") || path.equals("//"))
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

    private boolean checkSub(String host, String sub) {

        if (sub.length() > 64)
            return false;

        // host is ip ?
        String reg = "^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$";
        Matcher matcher = Pattern.compile(reg).matcher(host);
        if (matcher.find()) {
            return false;
        }

        if (addToMemory(host, sub, SUB))
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

            // insert path : /aaa/bbb/cc/, /aaa/bbb/, /aaa/
            String[] paths = path.split("/");
            int len = paths.length;
            if (checkPath(host, path)) {
                for (int i = 1; i < len - 1; i++) {
                    StringBuilder stringBuilder = new StringBuilder();
                    for (int j = 1; j <= i; j++) {
                        stringBuilder.append("/");
                        stringBuilder.append(paths[j]);
                    }
                    stringBuilder.append("/");
                    String resultPath = stringBuilder.toString();
                    if (checkPath(host, resultPath))
                        addToInsertMap(host, resultPath, PATH);
                }
                addToInsertMap(host, path, PATH);
            }

            String[] dirs = path.split("/");

            // insert dir : aaa, bbb
            for (String dir : dirs) {
                dir = "/" + dir + "/";
                if (checkDir(host, dir))
                    addToInsertMap(host, dir, DIR);
            }

            String fileName = fullPath.substring(fullPath.lastIndexOf("/") + 1);

            if (checkFile(host, fileName))
                addToInsertMap(host, fileName, FILE);

            // host = aa.bb.cc.dd.ee
            String[] subs = host.split("\\.");
            int subLength = subs.length;
            if (subLength > 2) {

                // insert aa,bb,cc
                for (int l = 0; l < subLength - 3; l++) {
                    if (checkSub(host, subs[l]))
                        addToInsertMap(host, subs[l], SUB);

                }
                // insert aa.bb.cc , bb.cc , cc
                for (int i = subLength - 3, j = 0; j <= i; j++) {
                    StringBuilder stringBuilder = new StringBuilder();
                    for (int k = j; k < i; k++) {
                        stringBuilder.append(subs[k]);
                        stringBuilder.append(".");
                    }
                    stringBuilder.append(subs[i]);
                    String sub = stringBuilder.toString();
                    if (checkSub(host, sub))
                        addToInsertMap(host, sub, SUB);
                }

            }
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
        HostSubDao hostSubDao = new HostSubDao();

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

                HashSet<String> subSet = getInsertHashSet(host, SUB);
                if (subSet != null)
                    hostSubDao.insertIgnoreHostSub(host, subSet);

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
