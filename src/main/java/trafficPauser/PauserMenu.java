package trafficPauser;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.menu.Menu;
import burp.api.montoya.core.Registration;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.BurpExtension;
import burp.api.montoya.persistence.PersistedObject;
import javax.swing.*;
import javax.swing.event.MenuEvent;
import javax.swing.event.MenuListener;
import java.util.*;
import java.util.List;
import java.awt.*;
import java.io.PrintWriter;
import java.text.NumberFormat;
import javax.swing.text.NumberFormatter;
import java.awt.event.ActionEvent;

class PauserMenu implements MenuListener {

    private JMenu menuButton;
    public static Logging logging;
    public static MontoyaApi api;
    private Registration menu;
    public static ConfigurableSettings globalSettings;
    public static Set<ToolType> stopped_tools = new HashSet<>();

    public static boolean traffic_switch_string = false;
    public static boolean traffic_switch_regex = false;

    public static LinkedHashMap<String, Boolean> regex_match_tools = new LinkedHashMap<String, Boolean>();
    public static LinkedHashMap<String, Boolean> string_match_tools = new LinkedHashMap<String, Boolean>();

    public PauserMenu(MontoyaApi api) {
        this.logging = api.logging();
        this.api = api;
        populateTools();
        this.globalSettings = new ConfigurableSettings();
        this.menuButton = new JMenu("Traffic Pauser");
        this.menuButton.addMenuListener(this);
        this.menu = api.userInterface().menuBar().registerMenu(this.menuButton);
    }

    public void populateTools() {
        String[] tools = { "REPEATER", "INTRUDER", "SCANNER", "PROXY", "EXTENSIONS" };
        for (String s : tools) {
            regex_match_tools.put(s, false);
            string_match_tools.put(s, false);
        }
    }

    public void menuDeselected(MenuEvent e) {
    }

    public void menuCanceled(MenuEvent e) {
    }

    public void menuSelected(MenuEvent e) {
        globalSettings.showSettings();
    }

    public static void out(String message) {
        logging.logToOutput(message);
    }
}

class ConfigurableSettings {
    private LinkedHashMap<String, String> settings;
    public LinkedHashMap<JCheckBox, String> tools_regex = new LinkedHashMap<JCheckBox, String>();
    public LinkedHashMap<JCheckBox, String> tools_string = new LinkedHashMap<JCheckBox, String>();
    private NumberFormatter onlyInt;

    ConfigurableSettings() {
        settings = new LinkedHashMap<>();
        put("Pause all traffic", false);
        put("Pause all traffic on string match", false);
        put("String to match", "string");
        put("string_match_tools", false);
        put("Pause all traffic on Regex match", false);
        put("Regex to match", "regex");
        put("regex_match_tools", false);

        for (String key : settings.keySet()) {
            // load extension settings if set
            PersistedObject myExtensionData = PauserMenu.api.persistence().extensionData();
            String value = myExtensionData.getString(key);
            if (value != null) {
                putRaw(key, value);
            }
        }

        NumberFormat format = NumberFormat.getInstance();
        onlyInt = new NumberFormatter(format);
        onlyInt.setValueClass(Integer.class);
        onlyInt.setMinimum(-1);
        onlyInt.setMaximum(Integer.MAX_VALUE);
        onlyInt.setAllowsInvalid(false);

        init_tools_checkboxes();
    }

    private ConfigurableSettings(ConfigurableSettings base) {
        settings = new LinkedHashMap<>(base.settings);
        onlyInt = base.onlyInt;
    }

    private void printSettings() {
        for (String key : settings.keySet()) {
            PauserMenu.out(key + ": " + settings.get(key));
        }
    }

    private String encode(Object value) {
        String encoded;
        if (value instanceof Boolean) {
            encoded = String.valueOf(value);
        } else if (value instanceof Integer) {
            encoded = String.valueOf(value);
        } else {
            encoded = "\"" + ((String) value).replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
        }
        return encoded;
    }

    private void putRaw(String key, String value) {
        settings.put(key, value);
    }

    private void put(String key, Object value) {
        settings.put(key, encode(value));
        switch (key) {
            case "Pause all traffic on string match":
                if (!(Boolean) value) {
                    PauserMenu.traffic_switch_string = false;
                }
            case "Pause all traffic on Regex match":
                if (!(Boolean) value) {
                    PauserMenu.traffic_switch_regex = false;
                }
        }
    }

    String getString(String key) {
        String decoded = settings.get(key);
        decoded = decoded.substring(1, decoded.length() - 1).replace("\\\"", "\"").replace("\\\\", "\\");
        return decoded;
    }

    int getInt(String key) {
        return Integer.parseInt(settings.get(key));
    }

    boolean getBoolean(String key) {
        String val = settings.get(key);
        if (val.equals("true")) {
            return true;
        } else if (val.equals("false")) {
            return false;
        }
        throw new RuntimeException();
    }

    String getType(String key) {
        String val = settings.get(key);
        if (val.equals("true") || val.equals("false")) {
            return "boolean";
        } else if (val.startsWith("\"")) {
            return "string";
        } else {
            return "number";
        }
    }

    public void init_tools_checkboxes() {
        JCheckBox box;
        for (String key : PauserMenu.regex_match_tools.keySet()) {
            box = new JCheckBox();
            box.setSelected(PauserMenu.regex_match_tools.get(key));
            tools_regex.put(box, key);
        }

        for (String key : PauserMenu.string_match_tools.keySet()) {
            box = new JCheckBox();
            box.setSelected(PauserMenu.regex_match_tools.get(key));
            tools_string.put(box, key);
        }
    }

    void setupTools(JPanel panel, GridBagConstraints c, Integer row, Boolean map_switch) {

        //map_switch 0 - regex hashmap
        //           1 - string hashmap

        // adding left most label to the grid
        c.gridx = 0;
        c.gridy = row;
        c.gridwidth = 1;
        JLabel label = new JLabel("Pause for: ");
        panel.add(label, c);

        // adding labels of tools to the grid
        c.gridx = 1;

        LinkedHashMap<JCheckBox, String> map = tools_regex;
        if(map_switch){
            map = tools_string;
        }

        for (JCheckBox key : map.keySet()) {
            label = new JLabel(map.get(key).substring(0, 1) + map.get(key).substring(1).toLowerCase());
            c.insets = new Insets(2, 0, 5, 0);
            panel.add(label, c);
            c.gridx += 2;
        }

        c.gridx = 2;

        // adding checkboxes to the grid

        for (JCheckBox key : map.keySet()) {
            c.insets = new Insets(2, 0, 5, 20);
            panel.add(key, c);
            c.gridx += 2;
        }

        // for (String key : PauserMenu.regex_match_tools.keySet()) {
        //     label = new JLabel(key.substring(0, 1) + key.substring(1).toLowerCase());
        //     c.insets = new Insets(2, 0, 5, 0);
        //     panel.add(label, c);
        //     c.gridx += 2;

        // }
        // c.gridx = 2;
        // // adding checkboxes to the grid
        // JCheckBox box;
        // for (Boolean value : PauserMenu.regex_match_tools.values()) {
        //     box = new JCheckBox();
        //     box.setSelected(value);
        //     c.insets = new Insets(2, 0, 5, 20);
        //     panel.add(box, c);

        //     c.gridx += 2;
        // }
    }

    ConfigurableSettings showSettings() {

        Integer row = 0;
        Integer column = 0;
        JPanel panel = new JPanel();
        panel.setLayout(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();
        JLabel label;

        HashMap<String, Object> configured = new HashMap<>();
        for (String key : settings.keySet()) {
            String type = getType(key);

            if(key.equals("regex_match_tools")){
                setupTools(panel, c, row, false);
                row++;
                continue;
            }
            else if(key.equals("string_match_tools")){
                setupTools(panel, c, row, true);
                row++;
                continue;
            }

            label = new JLabel("\n" + key + ": ");

            c.fill = GridBagConstraints.HORIZONTAL;
            c.gridx = column;
            c.gridy = row;
            c.insets = new Insets(0, 0, 0, 100);
            panel.add(label, c);

            column++;

            // adding checkbox to the grid
            if (type.equals("boolean")) {
                JCheckBox box = new JCheckBox();
                box.setSelected(getBoolean(key));
                c.gridwidth = 10;
                // c.insets = new Insets(0,0,0,300);
                c.gridx = column;
                panel.add(box, c);

                configured.put(key, box);
            }
            // adding number to the grid
            else if (type.equals("number")) {
                JTextField box = new JFormattedTextField(onlyInt);
                box.setText(String.valueOf(getInt(key)));
                c.gridwidth = 10;
                // c.insets = new Insets(0,0,0,300);
                c.gridx = column;
                panel.add(box, c);

                configured.put(key, box);
            }
            // adding Text field to the grid
            else {
                JTextField box = new JTextField(getString(key));
                // c.insets = new Insets(0,0,0,0);
                c.gridx = column;
                panel.add(box, c);
                configured.put(key, box);
            }

            column = 0;
            row++;
        }

        int result = JOptionPane.showConfirmDialog(null, panel, "Traffic Pauser", JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.PLAIN_MESSAGE);
        if (result == JOptionPane.OK_OPTION) {
            for (String key : configured.keySet()) {
                Object val = configured.get(key);
                if (val instanceof JCheckBox) {
                    val = ((JCheckBox) val).isSelected();
                } else if (val instanceof JFormattedTextField) {
                    val = Integer.parseInt(((JFormattedTextField) val).getText().replace(",", ""));
                } else {
                    val = ((JTextField) val).getText();
                }
                put(key, val);
                // save extension settings
                PersistedObject myExtensionData = PauserMenu.api.persistence().extensionData();
                myExtensionData.setString(key, encode(val));
            }

            return new ConfigurableSettings(this);
        }

        return null;
    }

}