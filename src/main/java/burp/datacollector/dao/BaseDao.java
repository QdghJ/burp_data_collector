package burp.datacollector.dao;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class BaseDao {


    public Connection getConnection() {
        return DatabaseUtil.getInstance().getConnection();
    }

    public PreparedStatement getPreparedStatement(String sql) throws SQLException {
        return getConnection().prepareStatement(sql);
    }
}
