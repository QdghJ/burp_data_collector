package burp.datacollector.dao;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class HostFullPathMapDao extends BaseDao {

    public boolean hostFullPathNotExist(String host, String fullPath) throws SQLException {
        boolean result = true;
        String sql = "SELECT host, full_path FROM host_full_path_map WHERE host = ? and full_path = ?";
        PreparedStatement preparedStatement = getPreparedStatement(sql);
        preparedStatement.setString(1, host);
        preparedStatement.setString(2, fullPath);
        ResultSet resultSet = preparedStatement.executeQuery();
        if(resultSet.next()){
            result = false;
        }
        resultSet.close();
        preparedStatement.close();
        return result;
    }

    public void insertHostFullPath(String host, String fullPath) throws SQLException {
        String sql = "INSERT INTO host_full_path_map(host, full_path) VALUES(?,?)";
        PreparedStatement preparedStatement =  getPreparedStatement(sql);
        preparedStatement.setString(1, host);
        preparedStatement.setString(2, fullPath);
        preparedStatement.executeUpdate();
        preparedStatement.close();
    }
}
