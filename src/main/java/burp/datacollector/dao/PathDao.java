package burp.datacollector.dao;

import com.opencsv.CSVReader;
import com.opencsv.exceptions.CsvValidationException;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.LineNumberReader;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class PathDao extends BaseDao {

    public void importPathFromFile(String fileName) throws IOException, SQLException, CsvValidationException {

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
        CSVReader csvReader = new CSVReader(fileReader);
        String[] line = csvReader.readNext();
        if (line != null) {
            String head = line[0];
            if (head.equals("path")) {
                int length = 1;
                int index = 1;
                int countIndex = 2;
                while ((line = csvReader.readNext()) != null) {
                    String path = line[0];
                    int count = Integer.parseInt(line[1]);
                    preparedStatement.setString(index, path);
                    preparedStatement.setInt(countIndex, count);
                    length += 2;
                    index = length;
                    countIndex = index + 1;
                }

            }
        }
        preparedStatement.executeUpdate();
        preparedStatement.close();
        csvReader.close();
    }

}
