package burp.datacollector.dao;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

public class ParameterDao extends BaseDao {

    public void insertParameter(String parameter) throws SQLException {
        String sql = "INSERT INTO parameter(parameter, count) VALUES (?, 1)";
        PreparedStatement preparedStatement = getPreparedStatement(sql);
        preparedStatement.setString(1, parameter);
        preparedStatement.execute();
        preparedStatement.close();
    }

    public boolean parameterNotExist(String parameter) throws SQLException {
        boolean result = true;
        String sql = "SELECT parameter FROM parameter WHERE parameter = ?";
        PreparedStatement preparedStatement = getPreparedStatement(sql);
        preparedStatement.setString(1, parameter);
        ResultSet resultSet = preparedStatement.executeQuery();
        if (resultSet.next()) {
            result = false;
        }
        resultSet.close();
        preparedStatement.close();
        return result;
    }

    public void addParameterCount(String parameter, int count) throws SQLException {
        String sql = "UPDATE parameter SET count = count + ? WHERE parameter = ?";
        PreparedStatement preparedStatement = getPreparedStatement(sql);
        preparedStatement.setInt(1, count);
        preparedStatement.setString(2, parameter);
        preparedStatement.execute();
        preparedStatement.close();
    }

    public List<String> getAllParameter() throws SQLException {
        List<String> parameters = new ArrayList<>();
        String sql = "SELECT parameter FROM parameter ORDER BY count DESC";
        PreparedStatement preparedStatement = getPreparedStatement(sql);
        ResultSet resultSet = preparedStatement.executeQuery();
        while (resultSet.next()) {
            String dir = resultSet.getString("parameter");
            parameters.add(dir);
        }
        resultSet.close();
        preparedStatement.close();
        return parameters;
    }
}
