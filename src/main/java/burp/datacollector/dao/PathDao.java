package burp.datacollector.dao;

import java.io.*;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class PathDao extends BaseDao {

    public void importPathFromFile(String fileName) throws IOException, SQLException {

        File lineFile = new File(fileName);
        LineNumberReader lineNumberReader = new LineNumberReader(new FileReader(lineFile));
        long fileLength = lineFile.length();
        lineNumberReader.skip(fileLength);
        int lineLength = lineNumberReader.getLineNumber();
        lineNumberReader.close();
        if (lineLength < 2)
            return;

        StringBuilder sqlStringBuilder = new StringBuilder("INSERT INTO `path` (`path`, `count`) VALUES");
        int n = lineLength - 1;
        for (int i = 0; i < n - 1; i++) {
            sqlStringBuilder.append("(?, ?),");
        }
        sqlStringBuilder.append("(?, ?) ON DUPLICATE KEY UPDATE count = count + VALUES (count)");
        String sql = sqlStringBuilder.toString();
        PreparedStatement preparedStatement = getPreparedStatement(sql);

        FileReader fileReader = new FileReader(new File(fileName));
        BufferedReader bufferedReader = new BufferedReader(fileReader);
        String line = bufferedReader.readLine();
        if (line != null) {
            String head = line.split(",")[0].trim();
            if (head.equals("path")) {
                int length = 1;
                int index = 1;
                int countIndex = 2;
                while ((line = bufferedReader.readLine()) != null) {
                    String[] row = line.split(",");
                    String file = row[0];
                    int count = Integer.parseInt(row[1]);
                    preparedStatement.setString(index, file);
                    preparedStatement.setInt(countIndex, count);
                    length += 2;
                    index = length;
                    countIndex = index + 1;
                }
                preparedStatement.executeUpdate();
                preparedStatement.close();
            }
        }
        bufferedReader.close();
    }

}
