# WAP Monitor (wapmon.py)

## Overview

**wapmon** is a cross-platform Python script designed to monitor surrounding Wi-Fi Access Points (WAPs) in real-time. It actively scans for networks and provides console and audio alerts for critical changes, such as the appearance of new networks or the disappearance of existing ones.

## Features

- **Cross-Platform Support**: Works on Windows, Linux, and macOS.
- **Real-Time Monitoring**: Continuously scans for network changes at a sub-second interval.
- **New & Removed WAP Alerts**: Get immediate notifications when a WAP appears or disappears.
- **Audio Alarms**: Plays distinct sounds for new and removed WAPs (if enabled).
- **Persistent Logging**: Saves a history of all events to a log file (if enabled).
- **Intelligent Scanning**: Uses the fastest available scanning tool for the OS (`lswifi` on Windows, `nmcli` on Linux, `airport` on macOS) with a fallback to slower, cached methods if needed.

## Requirements & Setup

This tool requires Python 3. The setup process varies slightly by operating system.

### Windows

For best performance, `wapmon` uses the `lswifi` library. It is highly recommended to use a Python virtual environment to manage this dependency.

1.  **Create and activate a virtual environment:**
    ```bash
    python -m venv .venv
    .venv\Scripts\activate
    ```
2.  **Install `lswifi`:**
    ```bash
    pip install lswifi==0.1.56
    ```
If `lswifi` is not found, the script will automatically fall back to the slower, cache-based `netsh` command.

### Linux

On Linux, `wapmon` requires `nmcli` for scanning and `aplay` for audio alerts. These are standard on most modern desktop distributions and do not require a virtual environment.

-   **To ensure they are installed on Debian/Ubuntu-based systems:**
    ```bash
    sudo apt-get update && sudo apt-get install network-manager alsa-utils
    ```
-   **To ensure they are installed on Fedora/CentOS/RHEL systems:**
    ```bash
    sudo dnf install NetworkManager alsa-utils
    ```

### macOS

No setup is required on macOS. `wapmon` uses the built-in `airport` utility for scanning and `afplay` for audio alerts, neither of which requires a virtual environment or any installation.

## Usage

Run the script from the command line, enabling features with flags. For the best experience, run with both logging (`-l`) and alarms (`-a`).

```bash
python3 wapmon.py -l -a
```

| Flag      | Argument  | Description                                                              |
| :-------- | :-------- | :----------------------------------------------------------------------- |
| `-l`      | `--log`   | Enables logging of scan results and alerts to `wap_monitor.log`.         |
| `-a`      | `--alarm` | Enables audio alerts for new and removed WAPs. WAV files are auto-generated. |
