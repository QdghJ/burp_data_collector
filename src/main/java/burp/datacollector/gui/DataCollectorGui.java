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
import java.io.IOException;
import java.sql.SQLException;

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
    private JButton importDirtFromFilesButton;
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
                new Thread(
                        new Runnable() {
                            @Override
                            public void run() {
                                burpExtender.saveData();
                            }
                        }
                ).start();
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
                new Thread(new Runnable() {
                    @Override
                    public void run() {
                        try {
                            HostDirMapDao hostDirMapDao = new HostDirMapDao();
                            hostDirMapDao.exportDir(absolutePath);
                            appendOutput("dir export to  " + absolutePath + HostDirMapDao.DIR_FILE);
                            appendOutput("dir import file export to  " + absolutePath + HostDirMapDao.DIR_IMPORT_FILE);

                            HostFullPathMapDao hostFullPathMapDao = new HostFullPathMapDao();
                            hostFullPathMapDao.exportFullPath(absolutePath);
                            appendOutput("full path export to  " + absolutePath + HostFullPathMapDao.FULL_PATH_FILE);
                            appendOutput("full path import file export to  " + absolutePath + HostFullPathMapDao.FULL_PATH_IMPORT_FILE);

                            HostPathMapDao hostPathMapDao = new HostPathMapDao();
                            hostPathMapDao.exportPath(absolutePath);
                            appendOutput("path export to  " + absolutePath + HostPathMapDao.PATH_FILE);
                            appendOutput("path import file export to  " + absolutePath + HostPathMapDao.PATH_IMPORT_FILE);

                            HostFileMapDao hostFileMapDao = new HostFileMapDao();
                            hostFileMapDao.exportFile(absolutePath);
                            appendOutput("file export to  " + absolutePath + HostFileMapDao.FILE_FILE);
                            appendOutput("file import file export to  " + absolutePath + HostFileMapDao.FILE_IMPORT_FILE);

                            HostParameterMapDao hostParameterMapDao = new HostParameterMapDao();
                            hostParameterMapDao.exportParameter(absolutePath);
                            appendOutput("parameter export to  " + absolutePath + HostParameterMapDao.PARAMETER_FILE);
                            appendOutput("parameter import file export to  " + absolutePath + HostParameterMapDao.PARAMETER_IMPORT_FILE);

                            AllDao allDao = new AllDao();
                            allDao.exportAll(absolutePath);
                            appendOutput("all export to  " + absolutePath + "/all.txt");

                        } catch (SQLException | IOException ex) {
                            ex.printStackTrace();
                            appendOutput(ex.toString());
                        }
                    }
                }).start();


            }
        });
        importDirtFromFilesButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {

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
        jPanel.add(spacer1, new GridConstraints(9, 0, 1, 2, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_VERTICAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
        final JLabel label1 = new JLabel();
        label1.setText("mysql host:");
        jPanel.add(label1, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(222, 16), null, 0, false));
        mysqlHostTextField = new JTextField();
        mysqlHostTextField.setText("127.0.0.1");
        jPanel.add(mysqlHostTextField, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        final JLabel label2 = new JLabel();
        label2.setText("mysql port:");
        jPanel.add(label2, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(222, 16), null, 0, false));
        mysqlPortTextField = new JTextField();
        mysqlPortTextField.setText("3306");
        jPanel.add(mysqlPortTextField, new GridConstraints(1, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        final JLabel label3 = new JLabel();
        label3.setText("mysql user:");
        jPanel.add(label3, new GridConstraints(2, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(222, 16), null, 0, false));
        mysqlUserTextField = new JTextField();
        mysqlUserTextField.setText("root");
        jPanel.add(mysqlUserTextField, new GridConstraints(2, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        final JLabel label4 = new JLabel();
        label4.setText("mysql password:");
        jPanel.add(label4, new GridConstraints(3, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(222, 16), null, 0, false));
        mysqlPasswordTextField = new JTextField();
        mysqlPasswordTextField.setText("root");
        jPanel.add(mysqlPasswordTextField, new GridConstraints(3, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        connectionTestButton = new JButton();
        connectionTestButton.setText("connection test");
        jPanel.add(connectionTestButton, new GridConstraints(5, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(222, 27), null, 0, false));
        exportDataToDatabaseButton = new JButton();
        exportDataToDatabaseButton.setEnabled(true);
        exportDataToDatabaseButton.setText("export data to database");
        jPanel.add(exportDataToDatabaseButton, new GridConstraints(5, 1, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JScrollPane scrollPane1 = new JScrollPane();
        jPanel.add(scrollPane1, new GridConstraints(8, 0, 1, 2, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_WANT_GROW, null, new Dimension(1, 121), null, 0, false));
        outputTextArea = new JTextArea();
        outputTextArea.setEditable(false);
        outputTextArea.setEnabled(true);
        outputTextArea.setText("");
        scrollPane1.setViewportView(outputTextArea);
        final JLabel label5 = new JLabel();
        label5.setText("black list ext");
        jPanel.add(label5, new GridConstraints(4, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(222, 16), null, 0, false));
        blackListExtsTextField = new JTextField();
        blackListExtsTextField.setText("png, jpg, gif, jpeg, css, ico, mp4");
        jPanel.add(blackListExtsTextField, new GridConstraints(4, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        exportDataToFilesButton = new JButton();
        exportDataToFilesButton.setText("export data to files");
        jPanel.add(exportDataToFilesButton, new GridConstraints(6, 1, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        saveConfigButton = new JButton();
        saveConfigButton.setText("save config");
        jPanel.add(saveConfigButton, new GridConstraints(6, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(222, 27), null, 0, false));
        clearMessageButton = new JButton();
        clearMessageButton.setText("clear message");
        jPanel.add(clearMessageButton, new GridConstraints(7, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(222, 27), null, 0, false));
        importDirtFromFilesButton = new JButton();
        importDirtFromFilesButton.setText("import dirt from files");
        jPanel.add(importDirtFromFilesButton, new GridConstraints(7, 1, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
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
