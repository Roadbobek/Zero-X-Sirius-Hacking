# WAP Monitor - (wapmon.py)

## Overview

**wapmon** is a script designed to monitor surrounding Wi-Fi Access Points (WAPs) in real-time. It actively scans for networks and logs critical changes, such as the appearance of new BSSIDs or changes in signal strength.

## Setup

(edit this) This tool requires Python 3 and the `lswifi` library for Windows users. It is highly recommended to use a Python virtual environment when installing `lswifi`.

### Linux

On Linux systems **wapmon** requires (talk about aplay here and the scannign util nmcli)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip3 install lswifi==0.1.56
```

### Windows

(here talk about making venv toi install lswifi)

```bash
python3 -m venv .venv
.venv\Scripts\activate
pip3 install lswifi==0.1.56
```

## Running

The primary monitoring mode requires specifying both logging (`-l`) and alarm (`-a`) flags.

```bash
python3 wapmon.py -l -a
```

| Flag | Description                                                               | 
|:-----|:--------------------------------------------------------------------------| 
| `-l` | Enables logging of scan results and alerts to a **.log file**.            | 
| `-a` | Enables active monitoring and **audio alerts** for new/disappearing WAPs. | 