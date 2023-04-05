package reencrypt;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;


public class ProxyHandler implements ProxyRequestHandler {

    ReEncrypt reEncrypt;

    public ProxyHandler(ReEncrypt reEncrypt) {
        this.reEncrypt = reEncrypt;
    }

    @Override
    public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest interceptedRequest) {
        return ProxyRequestReceivedAction.continueWith(interceptedRequest);        
    }

    public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest interceptedRequest) {
        try {
            if (reEncrypt.shouldPatchProxyRequest(interceptedRequest.url())) {
                System.out.print("it will patch: ");
                System.out.println(interceptedRequest.url() + " " + interceptedRequest.httpVersion());
                
                byte[] requestContent = interceptedRequest.toByteArray().getBytes();
                String plainText = reEncrypt.searchAndDecrypt(true, requestContent, null);
                System.out.println(interceptedRequest.url() + "\n" + plainText);
    
                byte[] patchedContent = reEncrypt.encryptAndPatch(requestContent, true, plainText);
                HttpRequest newRequest = HttpRequest.httpRequest(interceptedRequest.httpService(), ByteArray.byteArray(patchedContent));
                System.out.print("after patch: ");
                System.out.println(interceptedRequest.url() + " " + interceptedRequest.httpVersion());
                return ProxyRequestToBeSentAction.continueWith(newRequest, 
                    Annotations.annotations().withNotes("Modified by " + App.name));
            }
        } catch (Exception e) {
            System.out.println("exception in handleRequest: " + e);
        }
        return ProxyRequestToBeSentAction.continueWith(interceptedRequest);
    }

}