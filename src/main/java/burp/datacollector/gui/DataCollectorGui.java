package burp.datacollector.gui;

import burp.BurpExtender;
import burp.datacollector.dao.*;
import com.intellij.uiDesigner.core.GridConstraints;
import com.intellij.uiDesigner.core.GridLayoutManager;
import com.intellij.uiDesigner.core.Spacer;


import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.sql.SQLException;
import java.util.List;

public class DataCollectorGui {
    private JPanel jPanel;
    private JTextField mysqlHostTextField;
    private JTextField mysqlPortTextField;
    private JTextField mysqlUserTextField;
    private JTextField mysqlPasswordTextField;
    private JButton connectionTestButton;
    private JButton exportDataToDatabaseButton;
    private JTextArea outputTextArea;
    private JButton saveConfigButton;
    private JButton clearMessageButton;
    private JTextField blackListExtsTextField;
    private JButton exportDataToFilesButton;
    private StringBuilder output;

    public final static String MYSQL_HOST = "mysqlHost";
    public final static String MYSQL_PORT = "mysqlPort";
    public final static String MYSQL_USER = "mysqlUser";
    public final static String MYSQL_PASSWORD = "mysqlPassword";
    public final static String BLACK_LIST_EXT = "black_list_ext";

    public DataCollectorGui(BurpExtender burpExtender) {

        output = new StringBuilder();

        $$$setupUI$$$();
        connectionTestButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                DatabaseUtil.getInstance().connectTest(DataCollectorGui.this, burpExtender.getCallbacks(), getMysqlHost(), getMysqlPort(), getMysqlUser(), getMysqlPassword());
            }
        });
        exportDataToDatabaseButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                burpExtender.saveData();
            }
        });
        saveConfigButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                burpExtender.saveConfig();
                appendOutput("save config success!");
            }
        });

        clearMessageButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                output = new StringBuilder();
                outputTextArea.setText("");
            }
        });
        exportDataToFilesButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                JFileChooser fileChooser = new JFileChooser();
                fileChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
                fileChooser.showDialog(new JLabel(), "select folder to export data");
                File dataDir = fileChooser.getSelectedFile();
                String absolutePath = dataDir.getAbsolutePath();
                try {
                    File dirFile = new File(absolutePath + "/dir.txt");
                    FileOutputStream dirFileOutputStream = new FileOutputStream(dirFile);
                    DirDao dirDao = new DirDao();
                    List<String> dirs = dirDao.getAllDir();
                    for(String dir : dirs) {
                        dir = dir + "\n";
                        dirFileOutputStream.write(dir.getBytes());
                    }
                    dirFileOutputStream.close();
                    appendOutput("dirs write to " + dirFile.getAbsolutePath());

                    File filesFile = new File(absolutePath + "/file.txt");
                    FileOutputStream filesFileOutputStream = new FileOutputStream(filesFile);
                    FileDao fileDao = new FileDao();
                    List<String> files = fileDao.getAllFile();
                    for(String file : files) {
                        file = file + "\n";
                        filesFileOutputStream.write(file.getBytes());
                    }
                    filesFileOutputStream.close();
                    appendOutput("files write to " + filesFile.getAbsolutePath());

                    File fullPathFile = new File(absolutePath + "/full_path.txt");
                    FileOutputStream fullPathFileOutputStream = new FileOutputStream(fullPathFile);
                    FullPathDao fullPathDao = new FullPathDao();
                    List<String> fullPaths = fullPathDao.getAllFullPath();
                    for(String fullPath : fullPaths) {
                        fullPath = fullPath + "\n";
                        fullPathFileOutputStream.write(fullPath.getBytes());
                    }
                    fullPathFileOutputStream.close();
                    appendOutput("full paths write to " + fullPathFile.getAbsolutePath());

                    File pathFile = new File(absolutePath + "/path.txt");
                    FileOutputStream pathFileOutputStream = new FileOutputStream(pathFile);
                    PathDao pathDao = new PathDao();
                    List<String> paths = pathDao.getAllPath();
                    for(String path : paths) {
                        path = path + "\n";
                        pathFileOutputStream.write(path.getBytes());
                    }
                    pathFileOutputStream.close();
                    appendOutput("paths write to " + pathFile.getAbsolutePath());

                    File parameterFile = new File(absolutePath + "/parameter.txt");
                    FileOutputStream parameterFileOutputStream = new FileOutputStream(parameterFile);
                    ParameterDao parameterDao = new ParameterDao();
                    List<String> parameters = parameterDao.getAllParameter();
                    for(String parameter: parameters) {
                        parameter = parameter + "\n";
                        parameterFileOutputStream.write(parameter.getBytes());
                    }
                    parameterFileOutputStream.close();
                    appendOutput("parameters write to " + parameterFile.getAbsolutePath());

                    File allFile = new File(absolutePath + "/all.txt");
                    FileOutputStream allFileOutputStream = new FileOutputStream(allFile);
                    for(String dir : dirs) {
                        dir = dir + "\n";
                        allFileOutputStream.write(dir.getBytes());
                    }
                    for(String file : files) {
                        file = file + "\n";
                        allFileOutputStream.write(file.getBytes());
                    }
                    for(String fullPath : fullPaths) {
                        fullPath = fullPath + "\n";
                        allFileOutputStream.write(fullPath.getBytes());
                    }
                    for(String path : paths) {
                        path = path + "\n";
                        allFileOutputStream.write(path.getBytes());
                    }
                    allFileOutputStream.close();
                    appendOutput("all write to " + allFile.getAbsolutePath());

                } catch (SQLException | IOException ex) {
                    ex.printStackTrace();
                    appendOutput(ex.toString());
                }


            }
        });
    }


    public String getMysqlHost() {
        return mysqlHostTextField.getText();
    }

    public void setMysqlHost(String mysqlHost) {
        mysqlHostTextField.setText(mysqlHost);
    }

    public String getMysqlPort() {
        return mysqlPortTextField.getText();
    }

    public void setMysqlPort(String mysqlPort) {
        mysqlPortTextField.setText(mysqlPort);
    }

    public String getMysqlUser() {
        return mysqlUserTextField.getText();
    }

    public void setMysqlUser(String mysqlUser) {
        mysqlUserTextField.setText(mysqlUser);
    }

    public String getMysqlPassword() {
        return mysqlPasswordTextField.getText();
    }

    public void setMysqlPassword(String mysqlPassword) {
        mysqlPasswordTextField.setText(mysqlPassword);
    }

    public String[] getblackListExts() {
        String exts = blackListExtsTextField.getText();
        String[] extsList = exts.split(",");
        return extsList;
    }

    public String getBlackListExtStr() {
        return blackListExtsTextField.getText();
    }

    public void setBlackListExt(String blackListExt) {
        blackListExtsTextField.setText(blackListExt);
    }

    public void appendOutput(String message) {
        output.append(message);
        output.append("\n");
        outputTextArea.setText(output.toString());
    }

    /**
     * Method generated by IntelliJ IDEA GUI Designer
     * >>> IMPORTANT!! <<<
     * DO NOT edit this method OR call it in your code!
     *
     * @noinspection ALL
     */
    private void $$$setupUI$$$() {
        jPanel = new JPanel();
        jPanel.setLayout(new GridLayoutManager(10, 2, new Insets(0, 0, 0, 0), -1, -1));
        final Spacer spacer1 = new Spacer();
        jPanel.add(spacer1, new GridConstraints(9, 0, 1, 2, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_VERTICAL, 1, GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
        final JLabel label1 = new JLabel();
        label1.setText("mysql host:");
        jPanel.add(label1, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        mysqlHostTextField = new JTextField();
        mysqlHostTextField.setText("127.0.0.1");
        jPanel.add(mysqlHostTextField, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        final JLabel label2 = new JLabel();
        label2.setText("mysql port:");
        jPanel.add(label2, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        mysqlPortTextField = new JTextField();
        mysqlPortTextField.setText("3306");
        jPanel.add(mysqlPortTextField, new GridConstraints(1, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        final JLabel label3 = new JLabel();
        label3.setText("mysql user:");
        jPanel.add(label3, new GridConstraints(2, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        mysqlUserTextField = new JTextField();
        mysqlUserTextField.setText("root");
        jPanel.add(mysqlUserTextField, new GridConstraints(2, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        final JLabel label4 = new JLabel();
        label4.setText("mysql password:");
        jPanel.add(label4, new GridConstraints(3, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        mysqlPasswordTextField = new JTextField();
        mysqlPasswordTextField.setText("root");
        jPanel.add(mysqlPasswordTextField, new GridConstraints(3, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        connectionTestButton = new JButton();
        connectionTestButton.setText("connection test");
        jPanel.add(connectionTestButton, new GridConstraints(5, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        exportDataToDatabaseButton = new JButton();
        exportDataToDatabaseButton.setEnabled(true);
        exportDataToDatabaseButton.setText("export data to database");
        jPanel.add(exportDataToDatabaseButton, new GridConstraints(5, 1, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JScrollPane scrollPane1 = new JScrollPane();
        jPanel.add(scrollPane1, new GridConstraints(8, 0, 1, 2, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
        outputTextArea = new JTextArea();
        outputTextArea.setEditable(false);
        outputTextArea.setEnabled(true);
        outputTextArea.setText("");
        scrollPane1.setViewportView(outputTextArea);
        final JLabel label5 = new JLabel();
        label5.setText("black list ext");
        jPanel.add(label5, new GridConstraints(4, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        blackListExtsTextField = new JTextField();
        blackListExtsTextField.setText("png, jpg, gif, jpeg, css");
        jPanel.add(blackListExtsTextField, new GridConstraints(4, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        exportDataToFilesButton = new JButton();
        exportDataToFilesButton.setText("export data to files");
        jPanel.add(exportDataToFilesButton, new GridConstraints(6, 1, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        saveConfigButton = new JButton();
        saveConfigButton.setText("save config");
        jPanel.add(saveConfigButton, new GridConstraints(6, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        clearMessageButton = new JButton();
        clearMessageButton.setText("clear message");
        jPanel.add(clearMessageButton, new GridConstraints(7, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
    }

    /**
     * @noinspection ALL
     */
    public JComponent $$$getRootComponent$$$() {
        return jPanel;
    }

    private void createUIComponents() {
        // TODO: place custom component creation code here
    }
}
