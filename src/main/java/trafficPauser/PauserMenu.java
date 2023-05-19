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


class PauserMenu implements MenuListener{

    private JMenu menuButton;
    public static Logging logging;
    public static MontoyaApi api;
    private Registration menu;
    public static ConfigurableSettings globalSettings;
    public static Set<ToolType> stopped_tools = new HashSet<>();  
    public static boolean traffic_switch_string = false;
    public static boolean traffic_switch_regex = false;  
    

    public PauserMenu(MontoyaApi api){
        this.logging = api.logging();
        this.api = api;
        this.globalSettings = new ConfigurableSettings();
        this.menuButton = new JMenu("Traffic Pauser");
        this.menuButton.addMenuListener(this);
        this.menu = api.userInterface().menuBar().registerMenu(this.menuButton);
    } 

    public void menuDeselected(MenuEvent e) { }

    public void menuCanceled(MenuEvent e) { }

    public void menuSelected(MenuEvent e) {
        globalSettings.showSettings();
    }

    public static void out(String message) {
        logging.logToOutput(message);
    }
}

class ConfigurableSettings {
    private LinkedHashMap<String, String> settings;
    private NumberFormatter onlyInt;

    ConfigurableSettings() {
        settings = new LinkedHashMap<>();
        put("Pause all traffic", false);
        put("Pause all traffic on string match", false);
        put("String to match", "string");
        put("Pause all traffic on Regex match", false);
        put("Regex to match", "regex");
        //Tools to exclude from the stop
        put("Exclude Intruder", false);
        put("Exclude Repeater", false);
        put("Exclude Scanner", false);
        put("Exclude Proxy", false);

        for(String key: settings.keySet()) {
            //load extension settings if set
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
    }

    private ConfigurableSettings(ConfigurableSettings base) {
        settings = new LinkedHashMap<>(base.settings);
        onlyInt = base.onlyInt;
    }

    private void printSettings() {
        for(String key: settings.keySet()) {
            PauserMenu.out(key + ": "+settings.get(key));
        }
    }

    private String encode(Object value) {
        String encoded;
        if (value instanceof Boolean) {
            encoded = String.valueOf(value);
        }
        else if (value instanceof Integer) {
            encoded = String.valueOf(value);
        }
        else {
            encoded = "\"" + ((String) value).replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
        }
        return encoded;
    }

    private void putRaw(String key, String value) {
        settings.put(key, value);
    }

    private void put(String key, Object value) {
        settings.put(key, encode(value));
        switch(key){
            case "Pause all traffic on string match":
                if(!(Boolean)value){
                    PauserMenu.traffic_switch_string = false;
                }
            case "Pause all traffic on Regex match":
                if(!(Boolean)value){
                    PauserMenu.traffic_switch_regex = false;
                }
            case "Exclude Intruder":
            case "Exclude Repeater":
            case "Exclude Scanner":
            case "Exclude Proxy":
        }
    }

    String getString(String key) {
        String decoded = settings.get(key);
        decoded = decoded.substring(1, decoded.length()-1).replace("\\\"", "\"").replace("\\\\", "\\");
        return decoded;
    }

    int getInt(String key) {
        return Integer.parseInt(settings.get(key));
    }

    boolean getBoolean(String key) {
        String val = settings.get(key);
        if (val.equals("true") ) {
            return true;
        }
        else if (val.equals("false")){
            return false;
        }
        throw new RuntimeException();
    }

    String getType(String key) {
        String val = settings.get(key);
        if (val.equals("true") || val.equals("false")) {
            return "boolean";
        }
        else if (val.startsWith("\"")) {
            return "string";
        }
        else {
            return "number";
        }
    }

    ConfigurableSettings showSettings() {

        JPanel panel = new JPanel();
        panel.setLayout(new GridLayout(0, 2));
        panel.setPreferredSize(new Dimension(600, 250));
        panel.setMaximumSize(panel.getPreferredSize()); 
        panel.setMinimumSize(panel.getPreferredSize());

        HashMap<String, Object> configured = new HashMap<>();
        for(String key: settings.keySet()) {
            String type = getType(key);
            panel.add(new JLabel("\n"+key+": "));

            if (type.equals("boolean")) {
                JCheckBox box = new JCheckBox();
                box.setSelected(getBoolean(key));
                panel.add(box);
                configured.put(key, box);
            }
            else if (type.equals("number")){
                JTextField box = new JFormattedTextField(onlyInt);
                box.setText(String.valueOf(getInt(key)));
                panel.add(box);
                configured.put(key, box);
            }
            else {
                JTextField box = new JTextField(getString(key));
                panel.add(box);
                configured.put(key, box);
            }
        }

        int result = JOptionPane.showConfirmDialog(null, panel, "Traffic Pauser", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (result == JOptionPane.OK_OPTION) {
            for(String key: configured.keySet()) {
                Object val = configured.get(key);
                if (val instanceof JCheckBox) {
                    val = ((JCheckBox) val).isSelected();
                }
                else if (val instanceof JFormattedTextField) {
                    val = Integer.parseInt(((JFormattedTextField) val).getText().replace(",", ""));
                }
                else {
                    val = ((JTextField) val).getText();
                }
                put(key, val);
                //save extension settings
                PersistedObject myExtensionData = PauserMenu.api.persistence().extensionData();
                myExtensionData.setString(key, encode(val));
            }

            return new ConfigurableSettings(this);
        }

        return null;
    }



}