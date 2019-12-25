package burp.datacollector.dao;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

public class PathDao extends BaseDao {
    public void insertPath(String path) throws SQLException {
        String sql  = "INSERT INTO path(path, count) VALUES (?, 1)";
        PreparedStatement preparedStatement = getPreparedStatement(sql);
        preparedStatement.setString(1, path);
        preparedStatement.execute();
        preparedStatement.close();
    }

    public boolean pathNotExist(String path) throws SQLException {
        boolean result = true;
        String sql = "SELECT path FROM path WHERE path = ?";
        PreparedStatement preparedStatement = getPreparedStatement(sql);
        preparedStatement.setString(1, path);
        ResultSet resultSet = preparedStatement.executeQuery();
        if(resultSet.next()){
            result = false;
        }
        resultSet.close();
        preparedStatement.close();
        return result;
    }

    public void updatePathCount(String path) throws SQLException {
        String sql = "UPDATE path SET count = count + 1 WHERE path = ?";
        PreparedStatement preparedStatement = getPreparedStatement(sql);
        preparedStatement.setString(1, path);
        preparedStatement.execute();
        preparedStatement.close();
    }

    public List<String> getAllPath() throws SQLException {
        List<String> paths = new ArrayList<>();
        String sql = "SELECT path FROM path ORDER BY count DESC";
        PreparedStatement preparedStatement = getPreparedStatement(sql);
        ResultSet resultSet = preparedStatement.executeQuery();
        while (resultSet.next()) {
            String dir = resultSet.getString("path");
            paths.add(dir);
        }
        resultSet.close();
        preparedStatement.close();
        return paths;
    }
}
