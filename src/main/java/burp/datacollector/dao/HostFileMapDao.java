package burp.datacollector.dao;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class HostFileMapDao extends BaseDao {

    public boolean hostFileNotExist(String host, String fileName) throws SQLException {
        boolean result = true;
        String sql = "SELECT host, filename FROM host_file_map WHERE host = ? and filename = ?";
        PreparedStatement preparedStatement = getPreparedStatement(sql);
        preparedStatement.setString(1, host);
        preparedStatement.setString(2, fileName);
        ResultSet resultSet = preparedStatement.executeQuery();
        if(resultSet.next()){
            result = false;
        }
        resultSet.close();
        preparedStatement.close();
        return result;
    }

    public void insertHostFile(String host, String fileName) throws SQLException {
        String sql = "INSERT INTO host_file_map(host, filename) VALUES(?,?)";
        PreparedStatement preparedStatement =  getPreparedStatement(sql);
        preparedStatement.setString(1, host);
        preparedStatement.setString(2, fileName);
        preparedStatement.executeUpdate();
        preparedStatement.close();
    }
}
