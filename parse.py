#!/usr/bin/env python3

import json

jsons = []

with open('host.json', 'r') as jsonFile:
    lines = jsonFile.readlines()
    for l in lines:
        jsons.append(json.loads(l))

sysmon = []
security = []
powershell_operational = []
powershell = []
system = []
wmi = []
remoteConnection = []
firewall = []
localSession = []
bitsClient = []

for j in jsons:
    channel = j['Channel']
    if channel == 'Microsoft-Windows-Sysmon/Operational':
        sysmon.append(j)
    elif channel == 'Security' or channel == 'security':
        security.append(j)
    elif channel == 'Microsoft-Windows-PowerShell/Operational':
        powershell_operational.append(j)
    elif channel == 'Windows PowerShell':
        powershell.append(j)
    elif channel == 'System':
        system.append(j)
    elif channel == 'Microsoft-Windows-WMI-Activity/Operational':
        wmi.append(j)
    elif channel == 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational':
        remoteConnection.append(j)
    elif channel == 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall':
        firewall.append(j)
    elif channel == 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational':
        localSession.append(j)
    elif channel == 'Microsoft-Windows-Bits-Client/Operational':
        bitsClient.append(j)

directory = [('sysmon', sysmon), ('security', security),
        ('powershell_operational', powershell_operational),
        ('powershell', powershell), ('system', system),
        ('wmi', wmi), ('remoteConnection', remoteConnection),
        ('firewall', firewall), ('localSession', localSession),
        ('bitsClient', bitsClient)]

for entry in directory:
    objects = []
    for e in entry[1]:
        objects.append(json.dumps(e))
    data = "\n".join(objects)
    with open('logs/'+entry[0]+'.json', 'w') as log:
        log.write(data)
