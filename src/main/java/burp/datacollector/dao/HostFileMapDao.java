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

public class HostFileMapDao extends BaseDao {

    public final static String FILE_IMPORT_FILE = "/file_import.csv";
    public final static String FILE_FILE = "/file.txt";


    public void insertIgnoreHostFile(String host, HashSet<String> fileNameSet) throws SQLException {
        StringBuilder sqlStringBuilder = new StringBuilder("INSERT IGNORE INTO host_file_map(host, filename) VALUES");

        int n = fileNameSet.size();
        for (int i = 0; i < n - 1; i++)
            sqlStringBuilder.append("(?,?), ");
        sqlStringBuilder.append("(?,?)");

        String sql = sqlStringBuilder.toString();
        PreparedStatement preparedStatement = getPreparedStatement(sql);

        int length = 1;
        int hostIndex = 1;
        int index = 2;

        for (String fileName : fileNameSet) {
            preparedStatement.setString(hostIndex, host);
            preparedStatement.setString(index, fileName);
            length += 2;
            hostIndex = length;
            index = hostIndex + 1;
        }

        preparedStatement.executeUpdate();
        preparedStatement.close();
    }

    public void exportFile(String dirName) throws SQLException, IOException {
        String sql = "SELECT stat.filename, sum(fileCount) AS allCount\n" +
                "FROM ((SELECT hfm.filename, count(*) AS fileCount FROM host_file_map hfm GROUP BY hfm.filename)\n" +
                "      UNION ALL\n" +
                "      (SELECT filename, count AS fileCount FROM file)) stat\n" +
                "GROUP BY stat.filename\n" +
                "ORDER BY allCount DESC";
        PreparedStatement preparedStatement = getPreparedStatement(sql);
        ResultSet resultSet = preparedStatement.executeQuery();

        File file = new File(dirName + FILE_FILE);
        File fileImportFile = new File(dirName + FILE_IMPORT_FILE);
        FileOutputStream fileOutputStream = new FileOutputStream(file);
        FileWriter fileWriter = new FileWriter(fileImportFile);
        CSVWriter csvWriter = new CSVWriter(fileWriter);
        String[] fileHead = new String[]{"file", "count"};
        csvWriter.writeNext(fileHead);
        while (resultSet.next()) {
            String fileName = resultSet.getString(1);
            String row = fileName + "\n";
            int count = resultSet.getInt(2);
            fileOutputStream.write(row.getBytes());
            csvWriter.writeNext(new String[]{fileName, String.valueOf(count)}, true);
        }
        fileOutputStream.close();
        csvWriter.close();
    }
}
