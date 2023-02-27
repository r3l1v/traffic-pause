package burp;
import burp.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;
import javax.swing.*;
import burp.IMenuItemHandler;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import java.util.Arrays;
import java.util.regex.*;  

public class BurpExtender implements IBurpExtender, IHttpListener
{
    private IExtensionHelpers helpers;
    private IBurpExtenderCallbacks callbacks;
    private PrintWriter stdout;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        // reference to callback object
        this.callbacks = callbacks;
        // get helpers
        this.helpers = callbacks.getHelpers();
        // extension name
        callbacks.setExtensionName("Traffic Pause");
        // system output stream
        stdout = new PrintWriter(callbacks.getStdout(), true);
        // registering HTTP listener
        callbacks.registerHttpListener(this);

        SwingUtilities.invokeLater(new Menu(callbacks));
        Menu.globalSettings.printSettings();
    }

    public void pauseTraffic(int toolFlag, String option){
        if(Menu.THROTTLED_COMPONENTS.contains(toolFlag)){
            while (Menu.globalSettings.getBoolean(option)) {
                try {
                    stdout.println("Stopping traffic");
                    Thread.sleep(1000);
                } catch (java.lang.InterruptedException e) {
                    stdout.println("Error caused by interrupt exception");
                    return;
                }
            }
        }
    }

    public boolean regexFind(String request){
        Pattern p = Pattern.compile(Menu.globalSettings.getString("Regex to match"));
        Matcher m = p.matcher(request);
        boolean b = m.find();
        return b;
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo){

        if(Menu.globalSettings.getBoolean("Pause all traffic")){
            pauseTraffic(toolFlag, "Pause all traffic");
        }else if(messageIsRequest && Menu.traffic_switch_string){
            pauseTraffic(toolFlag, "Pause all traffic on string match");
        }else if(messageIsRequest && Menu.traffic_switch_regex){
            pauseTraffic(toolFlag, "Pause all traffic on Regex match");
        }

        if(!messageIsRequest && Menu.globalSettings.getBoolean("Pause all traffic on string match") && helpers.bytesToString(messageInfo.getResponse()).contains(Menu.globalSettings.getString("String to match"))){
            stdout.println("here");
            Menu.traffic_switch_string = true;
        }else if(!messageIsRequest && Menu.globalSettings.getBoolean("Pause all traffic on Regex match") && regexFind(helpers.bytesToString(messageInfo.getResponse()))){
            stdout.println("here2");
            Menu.traffic_switch_regex = true;
        }
    }
}