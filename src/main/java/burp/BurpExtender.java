package burp;

import burp.datacollector.dao.*;
import burp.datacollector.gui.DataCollectorGui;

import java.awt.*;
import java.sql.SQLException;
import java.util.List;


public class BurpExtender implements IBurpExtender, ITab, IExtensionStateListener {

    private final static String extensionName = "BurpDataCollector";

    private DataCollectorGui dataCollectorGui;
    private IBurpExtenderCallbacks callbacks;

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
        DatabaseUtil.getInstance().closeConnection();
    }

    public boolean checkBlackExt(String path) {
        String[] exts = dataCollectorGui.getblackListExts();
        for (String ext : exts) {
            ext = ext.trim();
            if (path.endsWith(ext)) {
                return true;
            }
        }
        return false;
    }

    public void saveData() {

        IHttpRequestResponse[] httpRequestResponses = callbacks.getProxyHistory();
        IExtensionHelpers helpers = callbacks.getHelpers();

        FileDao fileDao = new FileDao();
        HostFileMapDao hostFileMapDao = new HostFileMapDao();
        FullPathDao fullPathDao = new FullPathDao();
        HostFullPathMapDao hostFullPathMapDao = new HostFullPathMapDao();
        PathDao pathDao = new PathDao();
        HostPathMapDao hostPathMapDao = new HostPathMapDao();
        DirDao dirDao = new DirDao();
        HostDirMapDao hostDirMapDao = new HostDirMapDao();
        ParameterDao parameterDao = new ParameterDao();
        HostParameterMapDao hostParameterMapDao = new HostParameterMapDao();

        for (IHttpRequestResponse httpRequestResponse : httpRequestResponses) {
            try {
                IRequestInfo requestInfo = helpers.analyzeRequest(httpRequestResponse);
                String host = requestInfo.getUrl().getHost();
                String fullPath = requestInfo.getUrl().getPath();


                // insert full path : /aaa/bbb/ccc.php
                if (!fullPath.equals("/") && !checkBlackExt(fullPath) && hostFullPathMapDao.hostFullPathNotExist(host, fullPath)) {
                    if (fullPathDao.fullPathNotExist(fullPath)) {
                        fullPathDao.insertFullPath(fullPath);
                        hostFullPathMapDao.insertHostFullPath(host, fullPath);
                    } else {
                        fullPathDao.updateFullPathCount(fullPath);
                        hostFullPathMapDao.insertHostFullPath(host, fullPath);
                    }
                }

                String path = fullPath.substring(0, fullPath.lastIndexOf('/') + 1);

                // insert path : /aaa/bbb/
                if (!path.equals("/") && hostPathMapDao.hostPathNotExist(host, path)) {
                    if (pathDao.pathNotExist(path)) {
                        pathDao.insertPath(path);
                        hostPathMapDao.insertHostPath(host, path);
                    } else {
                        pathDao.updatePathCount(path);
                        hostPathMapDao.insertHostPath(host, path);
                    }
                }

                String[] dirs = path.split("/");

                // insert dir : aaa, bbb
                for (String dir : dirs) {
                    if (dir.equals(""))
                        continue;
                    dir = "/" + dir + "/";
                    if (hostDirMapDao.hostDirNotExist(host, dir)) {
                        if (dirDao.dirNotExist(dir)) {
                            dirDao.insertDir(dir);
                            hostDirMapDao.insertHostDir(host, dir);
                        } else {
                            dirDao.updateDirCount(dir);
                            hostDirMapDao.insertHostDir(host, dir);
                        }
                    }
                }

                String fileName = fullPath.substring(fullPath.lastIndexOf("/") + 1);

                if (!fileName.equals("") && !checkBlackExt(fileName) && hostFileMapDao.hostFileNotExist(host, fileName)) {
                    if (fileDao.fileNotExist(fileName)) {
                        fileDao.insertFile(fileName);
                        hostFileMapDao.insertHostFile(host, fileName);
                    } else {
                        fileDao.updateFileCount(fileName);
                        hostFileMapDao.insertHostFile(host, fileName);
                    }
                }

                List<IParameter> parameters = requestInfo.getParameters();
                for (IParameter parameter : parameters) {
                    if (parameter.getType() != 2) {
                        String parameterName = parameter.getName();

                        if (!parameterName.equals("_") && hostParameterMapDao.hostParameterNotExist(host, parameterName)) {
                            if (parameterDao.parameterNotExist(parameterName)) {
                                parameterDao.insertParameter(parameterName);
                                hostParameterMapDao.insertHostParameter(host, parameterName);
                            } else {
                                parameterDao.updateParameterCount(parameterName);
                                hostParameterMapDao.insertHostParameter(host, parameterName);
                            }
                        }
                    }
                }
            } catch (SQLException e) {
                e.printStackTrace();
                callbacks.printOutput(e.toString());
                dataCollectorGui.appendOutput(e.toString());
            }
        }
        dataCollectorGui.appendOutput("export finish!");
    }

}
