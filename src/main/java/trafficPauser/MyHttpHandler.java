package trafficPauser;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.logging.Logging;
import java.util.regex.*;  

import static burp.api.montoya.http.handler.RequestToBeSentAction.continueWith;
import static burp.api.montoya.http.handler.ResponseReceivedAction.continueWith;
import static burp.api.montoya.http.message.params.HttpParameter.urlParameter;

class MyHttpHandler implements HttpHandler {
    private Logging logging;
    private MontoyaApi api;
    private PauserMenu menu;

    public MyHttpHandler(MontoyaApi api, PauserMenu menu) {
        this.logging = api.logging();
        this.api = api;
        this.menu = menu;
    }

    public void pauseTraffic(int toolFlag, String option){
        while (menu.globalSettings.getBoolean(option)) {
            try {
                Thread.sleep(100000);
            } catch (java.lang.InterruptedException e) {
                logging.logToOutput("Error caused by interruped exception");
                return;
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

        //tool flag to be used later 
        Integer toolFlag = 0;
        logging.logToOutput("Request To be Sent");

        if(menu.globalSettings.getBoolean("Pause all traffic")){
            pauseTraffic(toolFlag, "Pause all traffic");
        }else if(menu.traffic_switch_string){
            pauseTraffic(toolFlag, "Pause all traffic on string match");
        }else if(menu.traffic_switch_regex){
            pauseTraffic(toolFlag, "Pause all traffic on Regex match");
        }
        
        return continueWith(requestToBeSent, annotations);
    }

    //Invoked by Burp when an HTTP response has been received.
    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        Annotations annotations = responseReceived.annotations();

        logging.logToOutput("Request to be received");

        if(menu.globalSettings.getBoolean("Pause all traffic on string match") && responseReceived.toString().contains(menu.globalSettings.getString("String to match"))){
            menu.traffic_switch_string = true;
        }else if(menu.globalSettings.getBoolean("Pause all traffic on Regex match") && regexFind(responseReceived.toString())){
            menu.traffic_switch_regex = true;
        }


        return continueWith(responseReceived, annotations);
    }

}
