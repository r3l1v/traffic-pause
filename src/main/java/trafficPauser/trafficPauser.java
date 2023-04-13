package trafficPauser;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
//import trafficPauser.MyHttpHandler;

public class trafficPauser implements BurpExtension {
    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("Traffic Pauser");
        
        //Menu button with setings
        PauserMenu menu = new PauserMenu(api);

        //Register our http handler with Burp.
        api.http().registerHttpHandler(new MyHttpHandler(api, menu));

    }
}