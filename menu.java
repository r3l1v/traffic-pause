package burp;
import burp.*;
import javax.swing.*;
import javax.swing.event.MenuEvent;
import javax.swing.event.MenuListener;
import java.util.*;
import java.util.List;
import java.awt.*;
import java.io.PrintWriter;
import java.text.NumberFormat;
import javax.swing.text.NumberFormatter;


class Menu implements Runnable, MenuListener, IExtensionStateListener{

    private JMenu menuButton;
    public static PrintWriter stdout;
    public static IBurpExtenderCallbacks callbacks;
    public static IExtensionHelpers helpers;
    static ConfigurableSettings globalSettings;
    public static Set<Integer> THROTTLED_COMPONENTS = new HashSet<>();  
    public static boolean traffic_switch_string = false;
    public static boolean traffic_switch_regex = false;  
    

    public Menu(IBurpExtenderCallbacks callbacks){
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        this.callbacks.registerExtensionStateListener(this);

        this.globalSettings = new ConfigurableSettings();

        Integer[] to_throttle = {IBurpExtenderCallbacks.TOOL_TARGET, IBurpExtenderCallbacks.TOOL_SPIDER, IBurpExtenderCallbacks.TOOL_SCANNER, IBurpExtenderCallbacks.TOOL_INTRUDER, IBurpExtenderCallbacks.TOOL_SEQUENCER, IBurpExtenderCallbacks.TOOL_EXTENDER, IBurpExtenderCallbacks.TOOL_REPEATER};
        Collections.addAll(THROTTLED_COMPONENTS, to_throttle);
    } 

    public void run()
    {
        menuButton = new JMenu("Pause Traffic");
        menuButton.addMenuListener(this);
        JMenuBar burpMenuBar = Menu.getBurpFrame().getJMenuBar();
        burpMenuBar.add(menuButton);
    }

    public void menuSelected(MenuEvent e) {
        SwingUtilities.invokeLater(new Runnable() {
            public void run(){
                globalSettings.showSettings();
            }
        });
    }

    public void menuDeselected(MenuEvent e) { }

    public void menuCanceled(MenuEvent e) { }

    public void extensionUnloaded() {
        Menu.getBurpFrame().getJMenuBar().remove(menuButton);
    }

    static JFrame getBurpFrame()
    {
        for(Frame f : Frame.getFrames())
        {
            if(f.isVisible() && f.getTitle().startsWith(("Burp Suite")))
            {
                return (JFrame) f;
            }
        }
        return null;
    }

    public static void out(String message) {
        stdout.println(message);
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

        for(String key: settings.keySet()) {
            String value = Menu.callbacks.loadExtensionSetting(key);
            if (Menu.callbacks.loadExtensionSetting(key) != null) {
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

    void printSettings() {
        for(String key: settings.keySet()) {
            Menu.out(key + ": "+settings.get(key));
        }
    }

    static JFrame getBurpFrame()
    {
        for(Frame f : Frame.getFrames())
        {
            if(f.isVisible() && f.getTitle().startsWith(("Burp Suite")))
            {
                return (JFrame) f;
            }
        }
        return null;
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
        if(key == "Pause all traffic on string match" && !(Boolean)value){
            Menu.traffic_switch_string = false;
        }else if(key == "Pause all traffic on Regex match" && !(Boolean)value){
            Menu.traffic_switch_regex = false;
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
        panel.setPreferredSize(new Dimension(600, 120));
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

        int result = JOptionPane.showConfirmDialog(Menu.getBurpFrame(), panel, "Traffic Pause", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
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
                Menu.callbacks.saveExtensionSetting(key, encode(val));
            }

            return new ConfigurableSettings(this);
        }

        return null;
    }



}