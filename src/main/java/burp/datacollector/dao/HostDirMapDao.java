package burp.datacollector.dao;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashSet;

public class HostDirMapDao extends BaseDao {

    public final static String DIR_IMPORT_FILE = "/dir_import.csv";
    public final static String DIR_FILE = "/dir.txt";

    public void insertIgnoreHostDir(String host, HashSet<String> dirSet) throws SQLException {

        StringBuilder sqlStringBuilder = new StringBuilder("INSERT IGNORE INTO host_dir_map(host, dir) VALUES");

        int n = dirSet.size();

        for (int i = 0; i < n - 1; i++)
            sqlStringBuilder.append("(?,?), ");
        sqlStringBuilder.append("(?,?)");

        String sql = sqlStringBuilder.toString();
        PreparedStatement preparedStatement = getPreparedStatement(sql);

        int length = 1;
        int hostIndex = 1;
        int index = 2;

        for (String dir : dirSet) {
            preparedStatement.setString(hostIndex, host);
            preparedStatement.setString(index, dir);
            length += 2;
            hostIndex = length;
            index = hostIndex + 1;
        }

        preparedStatement.executeUpdate();
        preparedStatement.close();
    }


    public void exportDir(String dirName) throws SQLException, IOException {
        String sql = "SELECT stat.dir, sum(dirCount) AS allCount\n" +
                "FROM ((SELECT hdm.dir, count(*) AS dirCount FROM host_dir_map hdm GROUP BY hdm.dir)\n" +
                "      UNION ALL\n" +
                "      (SELECT dir, count AS dirCount FROM dir)) stat\n" +
                "GROUP BY stat.dir\n" +
                "ORDER BY allCount DESC";
        PreparedStatement preparedStatement = getPreparedStatement(sql);
        ResultSet resultSet = preparedStatement.executeQuery();

        File dirFile = new File(dirName + DIR_FILE);
        File dirImportFile = new File(dirName + DIR_IMPORT_FILE);
        FileOutputStream dirFileOutputStream = new FileOutputStream(dirFile);
        FileOutputStream dirImportFileOutputStream = new FileOutputStream(dirImportFile);
        String fileHead = "dir,count\n";
        dirImportFileOutputStream.write(fileHead.getBytes());
        while (resultSet.next()) {
            String dir = resultSet.getString(1);
            String row = dir + "\n";
            int count = resultSet.getInt(2);
            dirFileOutputStream.write(row.getBytes());
            String importRow = dir + "," + String.valueOf(count) + "\n";
            dirImportFileOutputStream.write(importRow.getBytes());
        }
        dirFileOutputStream.close();
        dirImportFileOutputStream.close();
    }
}
