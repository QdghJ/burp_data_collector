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

public class HostSubDao extends BaseDao {

    public final static String SUB_FILE = "/sub.txt";
    public final static String SUB_IMPORT_FILE = "/sub_import.csv";


    public void insertIgnoreHostSub(String host, HashSet<String> subSet) throws SQLException {

        StringBuilder sqlStringBuilder = new StringBuilder("INSERT IGNORE INTO host_sub_map(host, sub) VALUES");

        int n = subSet.size();
        for (int i = 0; i < n - 1; i++)
            sqlStringBuilder.append("(?,?), ");
        sqlStringBuilder.append("(?,?)");

        String sql = sqlStringBuilder.toString();
        PreparedStatement preparedStatement = getPreparedStatement(sql);

        int length = 1;
        int hostIndex = 1;
        int index = 2;

        for (String sub : subSet) {
            preparedStatement.setString(hostIndex, host);
            preparedStatement.setString(index, sub);
            length += 2;
            hostIndex = length;
            index = hostIndex + 1;
        }

        preparedStatement.executeUpdate();
        preparedStatement.close();
    }

    public void exportSub(String dirName, int subCount) throws SQLException, IOException {
        String sql = "SELECT stat.sub, sum(subCount) AS allCount\n" +
                "FROM ((SELECT hsm.sub, count(*) AS subCount FROM host_sub_map hsm GROUP BY hsm.sub)\n" +
                "      UNION ALL\n" +
                "      (SELECT sub, count AS subCount FROM sub)) stat\n" +
                "GROUP BY stat.sub\n" +
                "HAVING allCount >= ?\n" +
                "ORDER BY allCount DESC";
        PreparedStatement preparedStatement = getPreparedStatement(sql);
        preparedStatement.setInt(1, subCount);
        ResultSet resultSet = preparedStatement.executeQuery();

        File subFile = new File(dirName + SUB_FILE);
        File subImportFile = new File(dirName + SUB_IMPORT_FILE);
        FileOutputStream pathOutputStream = new FileOutputStream(subFile);
        FileWriter fileWriter = new FileWriter(subImportFile);
        CSVWriter csvWriter = new CSVWriter(fileWriter);
        String[] fileHead = {"sub", "count"};
        csvWriter.writeNext(fileHead);
        while (resultSet.next()) {
            String sub = resultSet.getString(1);
            String row = sub + "\n";
            int count = resultSet.getInt(2);
            pathOutputStream.write(row.getBytes());
            csvWriter.writeNext(new String[]{sub, String.valueOf(count)}, true);
        }
        pathOutputStream.close();
        csvWriter.close();
    }
}
