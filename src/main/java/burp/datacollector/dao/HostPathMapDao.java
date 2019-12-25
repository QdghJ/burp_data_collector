package burp.datacollector.dao;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class HostPathMapDao extends BaseDao {

    public boolean hostPathNotExist(String host, String path) throws SQLException {
        boolean result = true;
        String sql = "SELECT host, path FROM host_path_map WHERE host = ? and path = ?";
        PreparedStatement preparedStatement = getPreparedStatement(sql);
        preparedStatement.setString(1, host);
        preparedStatement.setString(2, path);
        ResultSet resultSet = preparedStatement.executeQuery();
        if(resultSet.next()){
            result = false;
        }
        resultSet.close();
        preparedStatement.close();
        return result;
    }

    public void insertHostPath(String host, String path) throws SQLException {
        String sql = "INSERT INTO host_path_map(host, path) VALUES(?,?)";
        PreparedStatement preparedStatement =  getPreparedStatement(sql);
        preparedStatement.setString(1, host);
        preparedStatement.setString(2, path);
        preparedStatement.executeUpdate();
        preparedStatement.close();
    }
}
