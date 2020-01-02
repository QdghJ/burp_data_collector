package burp.datacollector.dao;

import com.opencsv.CSVWriter;

import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashSet;

public class HostFullPathMapDao extends BaseDao {

    public final static String FULL_PATH_IMPORT_FILE = "/full_path_import.csv";
    public final static String FULL_PATH_FILE = "/full_path.txt";

    public void insertIgnoreHostFullPath(String host, HashSet<String> fullPathSet) throws SQLException {
        StringBuilder sqlStringBuilder = new StringBuilder("INSERT IGNORE INTO host_full_path_map(host, full_path) VALUES");

        int n = fullPathSet.size();
        for (int i = 0; i < n - 1; i++)
            sqlStringBuilder.append("(?,?), ");
        sqlStringBuilder.append("(?,?)");

        String sql = sqlStringBuilder.toString();
        PreparedStatement preparedStatement = getPreparedStatement(sql);

        int length = 1;
        int hostIndex = 1;
        int index = 2;

        for (String fullPath : fullPathSet) {
            preparedStatement.setString(hostIndex, host);
            preparedStatement.setString(index, fullPath);
            length += 2;
            hostIndex = length;
            index = hostIndex + 1;
        }

        preparedStatement.executeUpdate();
        preparedStatement.close();

    }

    public void exportFullPath(String dirName, int fullPathCount) throws SQLException, IOException {
        String sql = "SELECT stat.full_path, sum(fullPathCount) AS allCount\n" +
                "FROM ((SELECT hfpm.full_path, count(*) AS fullPathCount FROM host_full_path_map hfpm GROUP BY hfpm.full_path)\n" +
                "      UNION ALL\n" +
                "      (SELECT full_path, count AS fullPathCount FROM full_path)) stat\n" +
                "GROUP BY stat.full_path\n" +
                "HAVING allCount >= ?\n" +
                "ORDER BY allCount DESC";
        PreparedStatement preparedStatement = getPreparedStatement(sql);
        preparedStatement.setInt(1, fullPathCount);
        ResultSet resultSet = preparedStatement.executeQuery();

        File fullPathFile = new File(dirName + FULL_PATH_FILE);
        File fullPathImportFile = new File(dirName + FULL_PATH_IMPORT_FILE);
        FileOutputStream fullPathOutputStream = new FileOutputStream(fullPathFile);
        FileWriter fileWriter = new FileWriter(fullPathImportFile);
        CSVWriter csvWriter = new CSVWriter(fileWriter);
        String[] fileHead = new String[]{"full_path", "count"};
        csvWriter.writeNext(fileHead);
        while (resultSet.next()) {
            String fullPath = resultSet.getString(1);
            String row = fullPath + "\n";
            int count = resultSet.getInt(2);
            fullPathOutputStream.write(row.getBytes());
            csvWriter.writeNext(new String[]{fullPath, String.valueOf(count)}, true);
        }
        fullPathOutputStream.close();
        csvWriter.close();
    }
}
