package burp.datacollector.dao;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

public class DirDao extends BaseDao {
    public void insertDir(String dir) throws SQLException {
        String sql  = "INSERT INTO dir(dir, count) VALUES (?, 1)";
        PreparedStatement preparedStatement = getPreparedStatement(sql);
        preparedStatement.setString(1, dir);
        preparedStatement.execute();
        preparedStatement.close();
    }

    public boolean dirNotExist(String dir) throws SQLException {
        boolean result = true;
        String sql = "SELECT dir FROM dir WHERE dir = ?";
        PreparedStatement preparedStatement = getPreparedStatement(sql);
        preparedStatement.setString(1, dir);
        ResultSet resultSet = preparedStatement.executeQuery();
        if(resultSet.next()){
            result = false;
        }
        resultSet.close();
        preparedStatement.close();
        return result;
    }

    public void updateDirCount(String dir) throws SQLException {
        String sql = "UPDATE dir SET count = count + 1 WHERE dir = ?";
        PreparedStatement preparedStatement = getPreparedStatement(sql);
        preparedStatement.setString(1, dir);
        preparedStatement.execute();
        preparedStatement.close();
    }

    public List<String> getAllDir() throws SQLException {
        List<String> dirs = new ArrayList<>();
        String sql = "SELECT dir FROM dir ORDER BY count DESC";
        PreparedStatement preparedStatement = getPreparedStatement(sql);
        ResultSet resultSet = preparedStatement.executeQuery();
        while (resultSet.next()) {
            String dir = resultSet.getString("dir");
            dirs.add(dir);
        }
        resultSet.close();
        preparedStatement.close();
        return dirs;
    }
}
