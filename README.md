# IDS-Intrusion-Detection-System-
Capture du trafic réseau (pcap), analyse de signatures simples (ex. scans de ports tentatives de login SSH), génération d’alertes.

### [Inspiration]((https://www.freecodecamp.org/news/build-a-real-time-intrusion-detection-system-with-python/))

Pour utiliser sniff sans donner tout l'accès (sudo) au script vous devez utiliser la commande setcap et assigner CAP_NET_RAW à votre interpréteur python :
```bash
    sudo setcap 'cap_net_raw=eip' ./packetcapture.py
```
cap_net_raw=eip: Grants the CAP_NET_RAW capability with:
e (Effective): The capability is active.
i (Inheritable): Child processes inherit the capability.
p (Permitted): The capability is allowed