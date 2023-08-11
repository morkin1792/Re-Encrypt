# Re:Encrypt

This BApp allows you send parts of the requests to command-line tools, and replace these parts by the tools outputs. The main use case is for testing apps with an extra encryption layer over HTTP. 

So, re:encode or re:encrypt them! 

Technically this extension requires Burp Suite v2023 or later (because of Montoya API). Nevertheless, <strong>v2023.7 or later is recommended</strong>, due to a bug in how Burp between v2023.4 and v2023.6 handles the editor tab created by the extension, sometimes showing outdated content in the tab. 

![](decrypting)
![](config)


## How to use

### 0) Install Re:Encrypt

- (soon) you can install through the BApp Store

- you can build this project with the command below, then load the jar (./app/build/libs/reencrypt.jar) in Burp Suite via Extensions > Installed:

```bash
./gradlew build
```

![](images/building.png)

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

### Save commands

![]()

## TODO
- recovery dates, ideas:
    - keep data in annotation
    - use a fast hash for each requests
- encode field cant be confused with response
- handle errors message errors for auto reencrypt
- breakline before Encode / Encrypt 
- replace/search over plaintext
- websockets support
    // api.userInterface().registerWebSocketMessageEditorProvider();
    // api.userInterface().createWebSocketMessageEditor
- save command history by time ?is it possible to get time from repeater and history requests?
- patterns pre defined
- encryption pre defined
- stdin support

## credits

- thanks to `Jodson` for starting this extension 