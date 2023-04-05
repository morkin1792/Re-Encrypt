# Re:Encrypt

This BApp allows send parts of requests to command-line tools, wait it be processed and get the answer back. The original use case is for testing apps with an extra encryption layer on top of HTTP. So, re:encode or re:encrypt parts of requests. 

![](decrypting)
![](config)

## How to use

### 0) Install Re:Encrypt
- you can build this project with the command below, then load the jar (./build/libs/app.jar) in Burp Suite via Extensions > Installed:
```bash
./gradlew build
```

![](building.png)

- (soon) you can install through the BApp Store

### 1) Go to Re:Encrypt tab

![](installedExtensions.png)

### 2) Set request and/or response patterns that will define what should be patched.
Examples:
- capturing bodies with at least one character:
```re
\r\n\r\n(.+)
```

- capturing a json parameter called data:
```re
data":"(.*?)"
```

![](extensionTab00.png)

### 3) Define the commands to decode/decrypt and encode/encrypt the patterns captured before. 

- You can use `{arg}` to define what part should be replaced by the captured text: 

![](usingArg.png)

- You can use `{file}` to refer to a path of a temporary file containing the captured text:

![](usingFile.png)

### 4) Optionally, patch the proxy requests.
- If you are working with an app that uses an assymetric cryptography, maybe you want to mark the checkbox below, this way it is possible to automatically re:encrypt proxy requests:

![](proxyCheckbox.png)

You can find a script that helps make MiTM in RSA here.

## Functionalities

### Proxy

![](proxy.gif)

### Repeater

![](repeater.gif)

### Intruder

![](intruder.gif)

### Config cache
When a request is processed successly, the original command-line config is saved in a cache file. This way, if each some minutes its needed set differents keys to decrypt, you can check the history later and show a message saying the request is been processed with a cached key. 

![](cache message)


## TODO

- url filter
- stdin support
- new methods to save the hashmap
- replace affecting plaintext
- search
- site map using cached command without alerting this
- limit error message

## credits

- thanks `Jodson` for starting this extension 