package burp.datacollector.dao;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

public class FullPathDao extends BaseDao {

    public void insertFullPath(String fullPath) throws SQLException {
        String sql  = "INSERT INTO full_path(full_path, count) VALUES (?, 1)";
        PreparedStatement preparedStatement = getPreparedStatement(sql);
        preparedStatement.setString(1, fullPath);
        preparedStatement.execute();
        preparedStatement.close();
    }

    public boolean fullPathNotExist(String fullPath) throws SQLException {
        boolean result = true;
        String sql = "SELECT full_path FROM full_path WHERE full_path = ?";
        PreparedStatement preparedStatement = getPreparedStatement(sql);
        preparedStatement.setString(1, fullPath);
        ResultSet resultSet = preparedStatement.executeQuery();
        if(resultSet.next()){
            result = false;
        }
        resultSet.close();
        preparedStatement.close();
        return result;
    }

    public void updateFullPathCount(String fullPath) throws SQLException {
        String sql = "UPDATE full_path SET count = count + 1 WHERE full_path = ?";
        PreparedStatement preparedStatement = getPreparedStatement(sql);
        preparedStatement.setString(1, fullPath);
        preparedStatement.execute();
        preparedStatement.close();
    }

    public List<String> getAllFullPath() throws SQLException {
        List<String> fullPaths = new ArrayList<>();
        String sql = "SELECT full_path FROM full_path ORDER BY count DESC";
        PreparedStatement preparedStatement = getPreparedStatement(sql);
        ResultSet resultSet = preparedStatement.executeQuery();
        while (resultSet.next()) {
            String dir = resultSet.getString("full_path");
            fullPaths.add(dir);
        }
        resultSet.close();
        preparedStatement.close();
        return fullPaths;
    }
}
