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

public class HostParameterMapDao extends BaseDao {

    public final static String PARAMETER_IMPORT_FILE = "/parameter_import.csv";
    public final static String PARAMETER_FILE = "/parameter.txt";


    public void insertIgnoreHostParameter(String host, HashSet<String> parameterSet) throws SQLException {

        StringBuilder sqlStringBuilder = new StringBuilder("INSERT IGNORE INTO host_parameter_map(host, parameter) VALUES");

        int n = parameterSet.size();
        for (int i = 0; i < n - 1; i++)
            sqlStringBuilder.append("(?,?), ");
        sqlStringBuilder.append("(?,?)");

        String sql = sqlStringBuilder.toString();
        PreparedStatement preparedStatement = getPreparedStatement(sql);

        int length = 1;
        int hostIndex = 1;
        int index = 2;

        for (String parameter : parameterSet) {
            preparedStatement.setString(hostIndex, host);
            preparedStatement.setString(index, parameter);
            length += 2;
            hostIndex = length;
            index = hostIndex + 1;
        }

        preparedStatement.executeUpdate();
        preparedStatement.close();
    }

    public void exportParameter(String dirName) throws SQLException, IOException {
        String sql = "SELECT stat.parameter, sum(parameterPathCount) AS allCount\n" +
                "FROM ((SELECT hpm.parameter, count(*) AS parameterPathCount FROM host_parameter_map hpm GROUP BY hpm.parameter)\n" +
                "      UNION ALL\n" +
                "      (SELECT parameter, count AS parameterPathCount FROM parameter)) stat\n" +
                "GROUP BY stat.parameter\n" +
                "ORDER BY allCount DESC";
        PreparedStatement preparedStatement = getPreparedStatement(sql);
        ResultSet resultSet = preparedStatement.executeQuery();

        File parameterFile = new File(dirName + PARAMETER_FILE);
        File parameterImportFile = new File(dirName + PARAMETER_IMPORT_FILE);
        FileOutputStream parameterOutputStream = new FileOutputStream(parameterFile);
        FileWriter fileWriter = new FileWriter(parameterImportFile);
        CSVWriter csvWriter = new CSVWriter(fileWriter);
        String[] fileHead = new String[]{"parameter", "count"};
        csvWriter.writeNext(fileHead);
        while (resultSet.next()) {
            String parameter = resultSet.getString(1);
            String row = parameter + "\n";
            int count = resultSet.getInt(2);
            parameterOutputStream.write(row.getBytes());
            csvWriter.writeNext(new String[]{parameter, String.valueOf(count)}, true);
        }
        parameterOutputStream.close();
        csvWriter.close();
    }
}
