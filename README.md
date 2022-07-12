# Re:Encrypt

This BApp allows send parts of requests to command-line tools, wait it be processed and get the answer back. The original use case is for testing apps with an extra encryption layer on top of HTTP. So, re:encode or re:encrypt parts of requests. 

![](decrypting)
![](config)

## Features 

### Config cache
When a request is processed successly, the original command-line config is saved in a cache file. This way, if each some minutes its needed set differents keys to decrypt, you can check the history later and show a message saying the request is been processed with a cached key. 

![](cache message)

## Building

```bash
./gradlew build
```

## TODO

- url filter
- big requests: java.io.IOException: Cannot run program "node": error=7, Argument list too long
- new methods to save the hashmap
- replace affecting plaintext
- search
- comment? https://github.com/PortSwigger/json-web-token-attacker/blob/80c34f5e669f6d2c032632930dce4c6b237481b1/src/main/java/eu/dety/burp/joseph/scanner/Marker.java
- site map using cached command without alerting this
- limit error message

## credits

- thanks `Jodson` for starting this extension 