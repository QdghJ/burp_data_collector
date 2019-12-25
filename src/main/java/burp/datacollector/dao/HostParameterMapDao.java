package burp.datacollector.dao;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class HostParameterMapDao extends BaseDao {

    public boolean hostParameterNotExist(String host, String parameter) throws SQLException {
        boolean result = true;
        String sql = "SELECT host, parameter FROM host_parameter_map WHERE host = ? and parameter = ?";
        PreparedStatement preparedStatement = getPreparedStatement(sql);
        preparedStatement.setString(1, host);
        preparedStatement.setString(2, parameter);
        ResultSet resultSet = preparedStatement.executeQuery();
        if(resultSet.next()){
            result = false;
        }
        resultSet.close();
        preparedStatement.close();
        return result;
    }

    public void insertHostParameter(String host, String parameter) throws SQLException {
        String sql = "INSERT INTO host_parameter_map(host, parameter) VALUES(?,?)";
        PreparedStatement preparedStatement =  getPreparedStatement(sql);
        preparedStatement.setString(1, host);
        preparedStatement.setString(2, parameter);
        preparedStatement.executeUpdate();
        preparedStatement.close();
    }
}
