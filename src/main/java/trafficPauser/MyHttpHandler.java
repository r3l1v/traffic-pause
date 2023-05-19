package trafficPauser;

import static burp.api.montoya.http.handler.RequestToBeSentAction.continueWith;
import static burp.api.montoya.http.handler.ResponseReceivedAction.continueWith;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.core.ToolSource;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.logging.Logging;

class MyHttpHandler implements HttpHandler {
    private Logging logging;
    private MontoyaApi api;
    private PauserMenu menu;

    public MyHttpHandler(MontoyaApi api, PauserMenu menu) {
        this.logging = api.logging();
        this.api = api;
        this.menu = menu;
    }

    public void pauseTraffic(ToolType tool, String option){

        switch(tool){
            case REPEATER:
                if(menu.globalSettings.getBoolean("Exclude Repeater")){
                    return;
                }
            case INTRUDER:
                if(menu.globalSettings.getBoolean("Exclude Intruder")){
                    return;
                }
            case SCANNER:
                if(menu.globalSettings.getBoolean("Exclude Scanner")){
                    return;
                }
            case PROXY:
                if(menu.globalSettings.getBoolean("Exclude Proxy")){
                    return;
                }
        }

        while (PauserMenu.globalSettings.getBoolean(option)) {
        }
    }

    public boolean regexFind(String request){
        Pattern p = Pattern.compile(menu.globalSettings.getString("Regex to match"));
        Matcher m = p.matcher(request);
        return m.find();
    }

    //Invoked by Burp when an HTTP request is about to be sent.
    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        Annotations annotations = requestToBeSent.annotations();

        ToolType tool_type = requestToBeSent.toolSource().toolType();

        if(menu.globalSettings.getBoolean("Pause all traffic")){
            pauseTraffic(tool_type, "Pause all traffic");
        }else if(PauserMenu.traffic_switch_string){
            pauseTraffic(tool_type, "Pause all traffic on string match");
        }else if(menu.traffic_switch_regex){
            pauseTraffic(tool_type, "Pause all traffic on Regex match");
        }
        
        return continueWith(requestToBeSent, annotations);
    }

    //Invoked by Burp when an HTTP response has been received.
    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        Annotations annotations = responseReceived.annotations();

        //logging.logToOutput("Request to be received");

        if(menu.globalSettings.getBoolean("Pause all traffic on string match") && responseReceived.toString().contains(menu.globalSettings.getString("String to match"))){
            menu.traffic_switch_string = true;
        }else if(menu.globalSettings.getBoolean("Pause all traffic on Regex match") && regexFind(responseReceived.toString())){
            menu.traffic_switch_regex = true;
        }


        return continueWith(responseReceived, annotations);
    }

}
