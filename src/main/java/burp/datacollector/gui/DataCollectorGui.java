package burp.datacollector.gui;

import burp.BurpExtender;
import burp.datacollector.dao.*;
import com.intellij.uiDesigner.core.GridConstraints;
import com.intellij.uiDesigner.core.GridLayoutManager;
import com.intellij.uiDesigner.core.Spacer;
import com.opencsv.CSVReader;
import com.opencsv.exceptions.CsvValidationException;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileReader;
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
    private JTextField pathCountTextField;
    private JTextField fileCountTextField;
    private JTextField dirCountTextField;
    private JTextField parameterCountTextField;
    private JTextField fullPathCountTextField;
    private StringBuilder output;

    public final static String MYSQL_HOST = "mysqlHost";
    public final static String MYSQL_PORT = "mysqlPort";
    public final static String MYSQL_USER = "mysqlUser";
    public final static String MYSQL_PASSWORD = "mysqlPassword";
    public final static String BLACK_LIST_EXT = "black_list_ext";
    public final static String PATH_COUNT = "path_count";
    public final static String FULL_PATH_COUNT = "full_path_count";
    public final static String FILE_COUNT = "file_count";
    public final static String PARAMETER_COUNT = "parameter_count";
    public final static String DIR_COUNT = "dir_count";

    public final static String[] IMPORT_HEADS = new String[]{
            "full_path", "path", "file", "dir", "parameter"
    };

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
                int selected = fileChooser.showDialog(new JLabel(), "select folder to export data");
                if (selected == JFileChooser.APPROVE_OPTION) {
                    File dataDir = fileChooser.getSelectedFile();
                    String absolutePath = dataDir.getAbsolutePath();

                    try {
                        int fullPathCount = getFullPathCount();
                        int pathCount = getPathCount();
                        int fileCount = getFileCount();
                        int dirCount = getDirCount();
                        int parameterCount = getParameterCount();
                        HostDirMapDao hostDirMapDao = new HostDirMapDao();
                        hostDirMapDao.exportDir(absolutePath, dirCount);
                        appendOutput("dir export to  " + absolutePath + HostDirMapDao.DIR_FILE);
                        appendOutput("dir import file export to  " + absolutePath + HostDirMapDao.DIR_IMPORT_FILE);

                        HostFullPathMapDao hostFullPathMapDao = new HostFullPathMapDao();
                        hostFullPathMapDao.exportFullPath(absolutePath, fullPathCount);
                        appendOutput("full path export to  " + absolutePath + HostFullPathMapDao.FULL_PATH_FILE);
                        appendOutput("full path import file export to  " + absolutePath + HostFullPathMapDao.FULL_PATH_IMPORT_FILE);

                        HostPathMapDao hostPathMapDao = new HostPathMapDao();
                        hostPathMapDao.exportPath(absolutePath, pathCount);
                        appendOutput("path export to  " + absolutePath + HostPathMapDao.PATH_FILE);
                        appendOutput("path import file export to  " + absolutePath + HostPathMapDao.PATH_IMPORT_FILE);

                        HostFileMapDao hostFileMapDao = new HostFileMapDao();
                        hostFileMapDao.exportFile(absolutePath, fileCount);
                        appendOutput("file export to  " + absolutePath + HostFileMapDao.FILE_FILE);
                        appendOutput("file import file export to  " + absolutePath + HostFileMapDao.FILE_IMPORT_FILE);

                        HostParameterMapDao hostParameterMapDao = new HostParameterMapDao();
                        hostParameterMapDao.exportParameter(absolutePath, parameterCount);
                        appendOutput("parameter export to  " + absolutePath + HostParameterMapDao.PARAMETER_FILE);
                        appendOutput("parameter import file export to  " + absolutePath + HostParameterMapDao.PARAMETER_IMPORT_FILE);

                        AllDao allDao = new AllDao();
                        allDao.exportAll(absolutePath, fullPathCount, pathCount, dirCount, fileCount);
                        appendOutput("all export to  " + absolutePath + "/all.txt");

                    } catch (SQLException | IOException ex) {
                        ex.printStackTrace();
                        appendOutput(ex.toString());
                    }
                }

            }

        });
        importDirtFromFilesButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                JFileChooser fileChooser = new JFileChooser();
                fileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
                fileChooser.setMultiSelectionEnabled(true);
                int selected = fileChooser.showDialog(new JLabel(), "select files to import data");
                if (selected == JFileChooser.APPROVE_OPTION) {
                    File[] files = fileChooser.getSelectedFiles();
                    for (File file : files) {
                        String fileName = file.getAbsolutePath();
                        try {
                            String head = getFileHead(fileName);
                            if (checkFileHead(head)) {
                                switch (head) {
                                    case BurpExtender.FILE:
                                        FileDao fileDao = new FileDao();
                                        fileDao.importFileFromFile(fileName);
                                        break;
                                    case BurpExtender.DIR:
                                        DirDao dirDao = new DirDao();
                                        dirDao.importDirFromFile(fileName);
                                        break;
                                    case BurpExtender.FULL_PATH:
                                        FullPathDao fullPathDao = new FullPathDao();
                                        fullPathDao.importFullPathFromFile(fileName);
                                        break;
                                    case BurpExtender.PATH:
                                        PathDao pathDao = new PathDao();
                                        pathDao.importPathFromFile(fileName);
                                        break;
                                    case BurpExtender.PARAMETER:
                                        ParameterDao parameterDao = new ParameterDao();
                                        parameterDao.importParameterFromFile(fileName);
                                        break;
                                }
                                appendOutput("import " + fileName + " finish");
                            } else {
                                appendOutput("file head error");
                            }

                        } catch (IOException | SQLException | CsvValidationException ex) {
                            ex.printStackTrace();
                            appendOutput(ex.toString());
                        }
                    }
                }
            }
        });
    }

    public boolean checkFileHead(String head) {
        boolean result = false;
        for (String h : IMPORT_HEADS) {
            if (h.equals(head))
                result = true;
        }
        return result;
    }

    public String getFileHead(String fileName) throws IOException, CsvValidationException {
        String head = "";
        FileReader fileReader = new FileReader(new File(fileName));
        CSVReader csvReader = new CSVReader(fileReader);
        String[] line = csvReader.readNext();
        if (line != null) {
            head = line[0];
        }
        csvReader.close();
        return head;
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

    public int getPathCount() {
        int count = Integer.parseInt(pathCountTextField.getText());
        if (count < 1)
            count = 1;
        return count;
    }

    public void setPathCount(String pathCount) {
        pathCountTextField.setText(pathCount);
    }

    public int getFullPathCount() {
        int count = Integer.parseInt(fullPathCountTextField.getText());
        if (count < 1)
            count = 1;
        return count;
    }

    public void setFullPathCount(String fullPathCount) {
        fullPathCountTextField.setText(fullPathCount);
    }

    public int getDirCount() {
        int count = Integer.parseInt(dirCountTextField.getText());
        if (count < 1)
            count = 1;
        return count;
    }

    public void setDirCount(String dirCount) {
        dirCountTextField.setText(dirCount);
    }

    public int getFileCount() {
        int count = Integer.parseInt(fileCountTextField.getText());
        if (count < 1)
            count = 1;
        return count;
    }

    public void setFileCount(String fileCount) {
        fileCountTextField.setText(fileCount);
    }

    public int getParameterCount() {
        int count = Integer.parseInt(parameterCountTextField.getText());
        if (count < 1)
            count = 1;
        return count;
    }

    public void setParameterCount(String parameterCount) {
        parameterCountTextField.setText(parameterCount);
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
        jPanel.setLayout(new GridLayoutManager(12, 2, new Insets(0, 0, 0, 0), -1, -1));
        final Spacer spacer1 = new Spacer();
        jPanel.add(spacer1, new GridConstraints(11, 0, 1, 2, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_VERTICAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
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
        jPanel.add(connectionTestButton, new GridConstraints(7, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(222, 27), null, 0, false));
        exportDataToDatabaseButton = new JButton();
        exportDataToDatabaseButton.setEnabled(true);
        exportDataToDatabaseButton.setText("export data to database");
        jPanel.add(exportDataToDatabaseButton, new GridConstraints(7, 1, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JScrollPane scrollPane1 = new JScrollPane();
        jPanel.add(scrollPane1, new GridConstraints(10, 0, 1, 2, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_WANT_GROW, null, new Dimension(1, 121), null, 0, false));
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
        jPanel.add(exportDataToFilesButton, new GridConstraints(8, 1, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        saveConfigButton = new JButton();
        saveConfigButton.setText("save config");
        jPanel.add(saveConfigButton, new GridConstraints(8, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(222, 27), null, 0, false));
        clearMessageButton = new JButton();
        clearMessageButton.setText("clear message");
        jPanel.add(clearMessageButton, new GridConstraints(9, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(222, 27), null, 0, false));
        importDirtFromFilesButton = new JButton();
        importDirtFromFilesButton.setText("import dict from files");
        jPanel.add(importDirtFromFilesButton, new GridConstraints(9, 1, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JLabel label6 = new JLabel();
        label6.setText("the min count to export dict");
        jPanel.add(label6, new GridConstraints(5, 0, 1, 2, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JPanel panel1 = new JPanel();
        panel1.setLayout(new GridLayoutManager(2, 7, new Insets(0, 0, 0, 0), -1, -1));
        jPanel.add(panel1, new GridConstraints(6, 0, 1, 2, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        final JLabel label7 = new JLabel();
        label7.setText("path count:");
        panel1.add(label7, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        pathCountTextField = new JTextField();
        pathCountTextField.setText("2");
        panel1.add(pathCountTextField, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        fileCountTextField = new JTextField();
        fileCountTextField.setText("2");
        panel1.add(fileCountTextField, new GridConstraints(0, 6, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        final JLabel label8 = new JLabel();
        label8.setText("file count:");
        panel1.add(label8, new GridConstraints(0, 5, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        dirCountTextField = new JTextField();
        dirCountTextField.setText("2");
        panel1.add(dirCountTextField, new GridConstraints(0, 4, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        final JLabel label9 = new JLabel();
        label9.setText("parameter count:");
        panel1.add(label9, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        parameterCountTextField = new JTextField();
        parameterCountTextField.setText("2");
        panel1.add(parameterCountTextField, new GridConstraints(1, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        final JLabel label10 = new JLabel();
        label10.setText("full path count:");
        panel1.add(label10, new GridConstraints(1, 2, 1, 2, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        fullPathCountTextField = new JTextField();
        fullPathCountTextField.setText("2");
        panel1.add(fullPathCountTextField, new GridConstraints(1, 4, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        final JLabel label11 = new JLabel();
        label11.setText("dir count:");
        panel1.add(label11, new GridConstraints(0, 2, 1, 2, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
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
