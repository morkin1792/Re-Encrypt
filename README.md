# Re:Encrypt

This BApp allows you send parts of the requests to command-line tools, and replace these parts by the tools outputs. The main use case is for testing apps with an extra encryption layer over HTTP. 

So, re:encode or re:encrypt them! 

It requires <strong>Burp Suite v2023 or later</strong> (it uses Montoya API).

⚠️ IMPORTANT ⚠️

Currently, this extension <b>MUST NOT</b> be used with Burp Suite <b>v2023.4 or later</b> (v2023.3 is recommended) due to a bug in how Burp Suite handles the editor tab created by the extension, sometimes showing a outdated content in the tab. When the bug be solved, this disclaimer will be updated!


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

- replace/search over plaintext
- websockets support
- save command history by time ?is it possible to get time from repeater and history requests?
- patterns pre defined
- encryption pre defined
- stdin support

## credits

- thanks to `Jodson` for starting this extension 