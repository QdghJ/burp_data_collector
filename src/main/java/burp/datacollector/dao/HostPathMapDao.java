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

public class HostPathMapDao extends BaseDao {

    public final static String PATH_FILE = "/path.txt";
    public final static String PATH_IMPORT_FILE = "/path_import.csv";


    public void insertIgnoreHostPath(String host, HashSet<String> pathSet) throws SQLException {

        StringBuilder sqlStringBuilder = new StringBuilder("INSERT IGNORE INTO host_path_map(host, path) VALUES");

        int n = pathSet.size();
        for (int i = 0; i < n - 1; i++)
            sqlStringBuilder.append("(?,?), ");
        sqlStringBuilder.append("(?,?)");

        String sql = sqlStringBuilder.toString();
        PreparedStatement preparedStatement = getPreparedStatement(sql);

        int length = 1;
        int hostIndex = 1;
        int index = 2;

        for (String path : pathSet) {
            preparedStatement.setString(hostIndex, host);
            preparedStatement.setString(index, path);
            length += 2;
            hostIndex = length;
            index = hostIndex + 1;
        }

        preparedStatement.executeUpdate();
        preparedStatement.close();
    }

    public void exportPath(String dirName) throws SQLException, IOException {
        String sql = "SELECT stat.path, sum(pathCount) AS allCount\n" +
                "FROM ((SELECT hpm.path, count(*) AS pathCount FROM host_path_map hpm GROUP BY hpm.path)\n" +
                "      UNION ALL\n" +
                "      (SELECT path, count AS pathCount FROM path)) stat\n" +
                "GROUP BY stat.path\n" +
                "ORDER BY allCount DESC";
        PreparedStatement preparedStatement = getPreparedStatement(sql);
        ResultSet resultSet = preparedStatement.executeQuery();

        File pathFile = new File(dirName + PATH_FILE);
        File pathImportFile = new File(dirName + PATH_IMPORT_FILE);
        FileOutputStream pathOutputStream = new FileOutputStream(pathFile);
        FileWriter fileWriter = new FileWriter(pathImportFile);
        CSVWriter csvWriter = new CSVWriter(fileWriter);
        String[] fileHead = {"path", "count"};
        csvWriter.writeNext(fileHead);
        while (resultSet.next()) {
            String path = resultSet.getString(1);
            String row = path + "\n";
            int count = resultSet.getInt(2);
            pathOutputStream.write(row.getBytes());
            csvWriter.writeNext(new String[]{path, String.valueOf(count)}, true);
        }
        pathOutputStream.close();
        csvWriter.close();
    }
}
