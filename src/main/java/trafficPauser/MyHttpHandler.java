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

    public void pauseTraffic(String option){
        while (PauserMenu.globalSettings.getBoolean(option)) {
        }
    }

    public void pauseTrafficTool(ToolType tool_type, Integer map_switch,String option){
        // map_switch - which set of tools to check
        //           0 - regex hashmap 
        //           1 - string hashmap
        // Pause on regex match / pause on string match

        switch(map_switch){
            case 0:
                while (PauserMenu.globalSettings.getBoolean(option) && menu.regex_match_tools.get(tool_type.toString().toUpperCase())) {
                }
            case 1 :
                while (PauserMenu.globalSettings.getBoolean(option) && menu.string_match_tools.get(tool_type.toString().toUpperCase())) {
                }
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

            pauseTraffic("Pause all traffic");

        }else if(PauserMenu.traffic_switch_string && menu.string_match_tools.get(tool_type.toString().toUpperCase())){

            pauseTrafficTool(tool_type, 1,"Pause all traffic on string match");

        }else if(menu.traffic_switch_regex && menu.regex_match_tools.get(tool_type.toString().toUpperCase())){

            pauseTrafficTool(tool_type, 0,"Pause all traffic on Regex match");
        }
        
        return continueWith(requestToBeSent, annotations);
    }

    //Invoked by Burp when an HTTP response has been received.
    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        Annotations annotations = responseReceived.annotations();

        ToolType tool_type = responseReceived.toolSource().toolType();

        if(menu.globalSettings.getBoolean("Pause all traffic on string match") 
            && responseReceived.toString().contains(menu.globalSettings.getString("String to match"))
            && menu.string_match_tools.get(tool_type.toString().toUpperCase())
        ){
            menu.traffic_switch_string = true;
        }else if(menu.globalSettings.getBoolean("Pause all traffic on Regex match")
                && regexFind(responseReceived.toString())
                && menu.regex_match_tools.get(tool_type.toString().toUpperCase())
        ){
            menu.traffic_switch_regex = true;
        }


        return continueWith(responseReceived, annotations);
    }

}
