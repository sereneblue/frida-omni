# frida-omni

A minimal web app to analyze Android applications with Frida.

![image](https://user-images.githubusercontent.com/14242625/171037438-d306ec5d-f436-405b-8daf-512a0e670cab.png)

## How to use

Download a copy of frida-omni from the [releases](https://github.com/sereneblue/frida-omni/releases) page and extract to a directory. Start your device/emulator along with frida-server and connect to your computer via USB/network. 

Start frida-omni

```$ python omni.py```

Navigate to `localhost:8085`, select device and app. Click start button to launch app with frida-server attached.

## Features

#### View info for the following:

- Package Info
- Shared Preferences
- Crypto
- Hash
- HTTP
- SQLite
- File System

#### Download log data as SQLite database

Logged data is stored in an in memory SQLite database. Download a copy of data for later use by clicking the download button.

#### Search and filter logs

Search and filter log data for crypto, hash, HTTP, SQLite, and file system logs.

## Notes

This is beta software. Some apps crash after starting from frida-omni.

Pull requests are welcome.