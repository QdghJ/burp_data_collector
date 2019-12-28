package burp.datacollector.dao;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class AllDao extends BaseDao {

    public void exportAll(String dirName) throws SQLException, IOException {
        String sql = "SELECT all_stat.name, sum(allCount) AS allTheCount\n" +
                "FROM ((SELECT stat.path AS name, sum(pathCount) AS allCount\n" +
                "       FROM ((SELECT hpm.path, count(*) AS pathCount FROM host_path_map hpm GROUP BY hpm.path)\n" +
                "             UNION ALL\n" +
                "             (SELECT path, count AS pathCount FROM path)) stat\n" +
                "       GROUP BY stat.path)\n" +
                "\n" +
                "      UNION ALL\n" +
                "\n" +
                "      (SELECT stat.full_path AS name, sum(fullPathCount) AS allCount\n" +
                "       FROM ((SELECT hfpm.full_path, count(*) AS fullPathCount FROM host_full_path_map hfpm GROUP BY hfpm.full_path)\n" +
                "             UNION ALL\n" +
                "             (SELECT full_path, count AS fullPathCount FROM full_path)) stat\n" +
                "       GROUP BY stat.full_path)\n" +
                "\n" +
                "      UNION ALL\n" +
                "\n" +
                "      (SELECT stat.filename AS name, sum(fullPathCount) AS allCount\n" +
                "       FROM ((SELECT hfm.filename, count(*) AS fullPathCount FROM host_file_map hfm GROUP BY hfm.filename)\n" +
                "             UNION ALL\n" +
                "             (SELECT filename, count AS fullPathCount FROM file)) stat\n" +
                "       GROUP BY stat.filename)\n" +
                "\n" +
                "      UNION ALL\n" +
                "\n" +
                "      (SELECT stat.dir AS name, sum(dirCount) AS allCount\n" +
                "       FROM ((SELECT hdm.dir, count(*) AS dirCount FROM host_dir_map hdm GROUP BY hdm.dir)\n" +
                "             UNION ALL\n" +
                "             (SELECT dir, count AS dirCount FROM dir)) stat\n" +
                "       GROUP BY stat.dir)) all_stat\n" +
                "GROUP BY all_stat.name\n" +
                "ORDER BY allTheCount DESC";
        PreparedStatement preparedStatement = getPreparedStatement(sql);
        ResultSet resultSet = preparedStatement.executeQuery();

        File allFile = new File(dirName + "/all.txt");
        FileOutputStream allFileOutputStream = new FileOutputStream(allFile);
        while (resultSet.next()) {
            String name = resultSet.getString(1);
            String row = name + "\n";
            allFileOutputStream.write(row.getBytes());
        }
        allFileOutputStream.close();
    }
}
