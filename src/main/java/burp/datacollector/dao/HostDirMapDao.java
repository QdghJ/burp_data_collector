package burp.datacollector.dao;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class HostDirMapDao extends BaseDao {
    public boolean hostDirNotExist(String host, String dir) throws SQLException {
        boolean result = true;
        String sql = "SELECT host, dir FROM host_dir_map WHERE host = ? and dir = ?";
        PreparedStatement preparedStatement = getPreparedStatement(sql);
        preparedStatement.setString(1, host);
        preparedStatement.setString(2, dir);
        ResultSet resultSet = preparedStatement.executeQuery();
        if(resultSet.next()){
            result = false;
        }
        resultSet.close();
        preparedStatement.close();
        return result;
    }

    public void insertHostDir(String host, String dir) throws SQLException {
        String sql = "INSERT INTO host_dir_map(host, dir) VALUES(?,?)";
        PreparedStatement preparedStatement =  getPreparedStatement(sql);
        preparedStatement.setString(1, host);
        preparedStatement.setString(2, dir);
        preparedStatement.executeUpdate();
        preparedStatement.close();
    }
}
