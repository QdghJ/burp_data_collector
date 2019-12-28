package burp.datacollector.dao;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

public class FileDao extends BaseDao {

    public void insertFile(String fileName) throws SQLException {
        String sql = "INSERT INTO file(filename, count) VALUES (?, 1)";
        PreparedStatement preparedStatement = getPreparedStatement(sql);
        preparedStatement.setString(1, fileName);
        preparedStatement.execute();
        preparedStatement.close();
    }

    public boolean fileNotExist(String fileName) throws SQLException {
        boolean result = true;
        String sql = "SELECT filename FROM file WHERE filename = ?";
        PreparedStatement preparedStatement = getPreparedStatement(sql);
        preparedStatement.setString(1, fileName);
        ResultSet resultSet = preparedStatement.executeQuery();
        if (resultSet.next()) {
            result = false;
        }
        resultSet.close();
        preparedStatement.close();
        return result;
    }

    public void addFileCount(String fileName, int count) throws SQLException {
        String sql = "UPDATE file SET count = count + 1 WHERE filename = ?";
        PreparedStatement preparedStatement = getPreparedStatement(sql);
        preparedStatement.setString(1, fileName);
        preparedStatement.execute();
        preparedStatement.close();
    }

    public List<String> getAllFile() throws SQLException {
        List<String> files = new ArrayList<>();
        String sql = "SELECT filename FROM file ORDER BY count DESC";
        PreparedStatement preparedStatement = getPreparedStatement(sql);
        ResultSet resultSet = preparedStatement.executeQuery();
        while (resultSet.next()) {
            String dir = resultSet.getString("filename");
            files.add(dir);
        }
        resultSet.close();
        preparedStatement.close();
        return files;
    }
}
