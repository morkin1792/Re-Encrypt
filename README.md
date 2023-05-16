# Re:Encrypt

This BApp allows you send parts of the requests to command-line tools, and replace these parts by the tools outputs. The main use case is for testing apps with an extra encryption layer over HTTP. So, re:encode or re:encrypt them! 

It requires <strong>Burp Suite v2023 or later</strong> (it uses Montoya API).

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

### Config cache
When a request is processed successly, the original command-line config is saved in a cache file. This way, if each some minutes its needed set differents keys to decrypt, you can check the history later and show a message saying the request is been processed with a cached key. 

![](cache message)


## TODO

- ?save command history by time, is it possible get time from repeater and history requests?
- patterns pre defined
- stdin support
- replace for plaintexts
- ?search in plaintext

## credits

- thanks to `Jodson` for starting this extension 