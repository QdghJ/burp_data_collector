package burp.datacollector.dao;

import burp.IBurpExtenderCallbacks;
import burp.datacollector.gui.DataCollectorGui;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;

public class DatabaseUtil {

    private Connection connection;

    private static DatabaseUtil instance = null;


    static {
        try {
            Class.forName("com.mysql.jdbc.Driver");
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
    }

    private DatabaseUtil() {

    }


    public static DatabaseUtil getInstance() {
        if (instance == null) {
            synchronized (DatabaseUtil.class) {
                if (instance == null) {
                    instance = new DatabaseUtil();
                }
            }
        }
        return instance;
    }

    public boolean initConnection(IBurpExtenderCallbacks callbacks, String host, String port, String user, String password) {
        String url = "jdbc:mysql://" + host + ":" + port + "/?serverTimezone=Asia/Shanghai";
        boolean result = false;
        try {
            connection = DriverManager.getConnection(url, user, password);
            result = true;
            initDatabase(callbacks);
        } catch (SQLException e) {
            e.printStackTrace();
            callbacks.printOutput(e.toString());
            callbacks.printOutput(String.valueOf(e.getErrorCode()));
            result = false;
        }
        return result;
    }

    private void initDatabase(IBurpExtenderCallbacks callbacks) {
        try {
            Statement statement = connection.createStatement();

            String createDatabase = "CREATE DATABASE IF NOT EXISTS `data_collect` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;";
            statement.execute(createDatabase);

            String useDatabase = "use data_collect;";
            statement.execute(useDatabase);

            String createFileTable = "CREATE TABLE IF NOT EXISTS `file` (\n" +
                    "  `filename` varchar(256) NOT NULL,\n" +
                    "  `count` int(11) NOT NULL,\n" +
                    "  PRIMARY KEY (`filename`) \n" +
                    ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;";
            statement.execute(createFileTable);

            String createHostFileTable = "CREATE TABLE IF NOT EXISTS `host_file_map` (\n" +
                    "  `host` varchar(128) NOT NULL,\n" +
                    "  `filename` varchar(256) NOT NULL,\n" +
                    "  PRIMARY KEY (`host`, `filename`) \n" +
                    ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;";
            statement.execute(createHostFileTable);

            String createPathTable = "CREATE TABLE IF NOT EXISTS `path` (\n" +
                    "  `path` varchar(256) NOT NULL,\n" +
                    "  `count` int(11) NOT NULL,\n" +
                    "  PRIMARY KEY (`path`)\n" +
                    ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;";
            statement.execute(createPathTable);

            String createHostPathTable = "CREATE TABLE IF NOT EXISTS `host_path_map` (\n" +
                    "  `host` varchar(128) NOT NULL,\n" +
                    "  `path` varchar(256) NOT NULL,\n" +
                    "  PRIMARY KEY (`host`, `path`)\n" +
                    ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;";
            statement.execute(createHostPathTable);

            String createParameterTable = "CREATE TABLE IF NOT EXISTS `parameter` (\n" +
                    "  `parameter` varchar(64) NOT NULL,\n" +
                    "  `count` int(11) NOT NULL,\n" +
                    "  PRIMARY KEY (`parameter`)\n" +
                    ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;";
            statement.execute(createParameterTable);

            String createHostParameterTable = "CREATE TABLE IF NOT EXISTS `host_parameter_map` (\n" +
                    "  `host` varchar(128) NOT NULL,\n" +
                    "  `parameter` varchar(64) NOT NULL,\n" +
                    "  PRIMARY KEY (`host`, `parameter`)\n" +
                    ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;";
            statement.execute(createHostParameterTable);

            String createFullPathTable = "CREATE TABLE IF NOT EXISTS `full_path` (\n" +
                    "  `full_path` varchar(256) NOT NULL,\n" +
                    "  `count` int(11) NOT NULL,\n" +
                    "  PRIMARY KEY (`full_path`)\n" +
                    ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;";
            statement.execute(createFullPathTable);

            String createHostFullPathTable = "CREATE TABLE IF NOT EXISTS `host_full_path_map` (\n" +
                    "  `host` varchar(128) NOT NULL,\n" +
                    "  `full_path` varchar(256) NOT NULL,\n" +
                    "  PRIMARY KEY (`host`, `full_path`)\n" +
                    ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;";
            statement.execute(createHostFullPathTable);

            String createDirTable = "CREATE TABLE IF NOT EXISTS `dir` (\n" +
                    "  `dir` varchar(32) NOT NULL,\n" +
                    "  `count` int(11) NOT NULL,\n" +
                    "  PRIMARY KEY (`dir`)\n" +
                    ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;";
            statement.execute(createDirTable);

            String createHostDirTable = "CREATE TABLE IF NOT EXISTS `host_dir_map` (\n" +
                    "  `host` varchar(128) NOT NULL,\n" +
                    "  `dir` varchar(32) NOT NULL,\n" +
                    "  PRIMARY KEY (`host`, `dir`)\n" +
                    ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;";
            statement.execute(createHostDirTable);

            String createSubTable = "CREATE TABLE IF NOT EXISTS `sub` (\n" +
                    "  `sub` varchar(64) NOT NULL,\n" +
                    "  `count` int(11) NOT NULL,\n" +
                    "  PRIMARY KEY (`sub`)\n" +
                    ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;";
            statement.execute(createSubTable);

            String createHostSubDomainTable = "CREATE TABLE IF NOT EXISTS `host_sub_map` (\n" +
                    "  `host` varchar(128) NOT NULL,\n" +
                    "  `sub` varchar(64) NOT NULL,\n" +
                    "  PRIMARY KEY (`host`, `sub`)\n" +
                    ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;";
            statement.execute(createHostSubDomainTable);


            callbacks.printOutput("init database success!");
        } catch (SQLException e) {
            e.printStackTrace();
            callbacks.printOutput(e.toString());
            callbacks.printOutput(String.valueOf(e.getErrorCode()));
            callbacks.printOutput("something wrong when init database");
        }


    }

    public void connectTest(DataCollectorGui dataCollectorGui, IBurpExtenderCallbacks callbacks, String host, String port, String user, String password) {
        String url = "jdbc:mysql://" + host + ":" + port + "/?serverTimezone=Asia/Shanghai";
        try {
            if (connection != null) {
                try {
                    connection.close();
                } catch (SQLException e) {
                    //e.printStackTrace();
                }
                connection = DriverManager.getConnection(url, user, password);
            } else {
                connection = DriverManager.getConnection(url, user, password);
            }
            initDatabase(callbacks);
            dataCollectorGui.appendOutput("connect success!");
        } catch (SQLException e) {
            e.printStackTrace();
            dataCollectorGui.appendOutput(e.toString());
        }
    }

    public Connection getConnection() {
        return connection;
    }

    public void closeConnection() {
        try {
            if (connection != null) {
                connection.close();
            }
        } catch (SQLException e) {
            //e.printStackTrace();
        }
    }
}
