import re
import logging

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

assets = [
    {"hostname": "pc1", "mac": ["12:12:12:12:12", "12:45:ff:ab:ab"]},
    {"hostname": "pc2", "mac": ["b4:6d:83:2b:6a:a6", "aa:bb:cc:dd:ee:ff"]},
    {"hostname": "pc3", "mac": ["11:22:33:44:55:66"]},
    {"hostname": "pc4", "mac": ["77:88:99:aa:bb:cc", "dd:ee:ff:00:11:22", "33:44:55:66:77:88", "99:aa:bb:cc:dd:ee"]},
]

dhcp_logs = [
    {"asdas":"asdasd","message":"Lease IP 192.168.1.163 renewed for MAC B4:6D:83:2B:6A:A6"},
    {"asdas":"asdasd","message":"Lease IP 192.168.1.144 renewed for MAC 33:44:55:66:77:88"},
    {"asdas":"asdasd","message":"Lease IP 192.168.1.124 renewed for MAC ff:ee:dd:cc:bb:aa"}
]

# def get_macs_from_dhcp_logs(dhcp_logs):
#     dhcp_macs = []
#     for log in dhcp_logs:
#         mac = log["message"].split('MAC')[1].lower().strip()
#         dhcp_macs.append(mac)
#     return dhcp_macs

def get_macs_from_dhcp_logs(dhcp_logs):
    dhcp_macs = []
    for log in dhcp_logs:
        match = re.search(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})", log['message'])
        if match:
            dhcp_macs.append(match.group(0).lower())
            logging.warning("Connected MAC: %s", match.group())
    return dhcp_macs

def get_unauthorized_macs(assets, dhcp_macs):
    authorized_macs = [] #TODO: Convert MACs to lowercase
    for asset in assets:
        for mac in asset["mac"]:
            authorized_macs.append(mac)
    logging.info("Authorized MACs: %s", authorized_macs)

    for dhcp_mac in dhcp_macs:
        if dhcp_mac not in authorized_macs:
            logging.critical("Unauthorized MAC: %s", dhcp_mac)

get_unauthorized_macs(assets, get_macs_from_dhcp_logs(dhcp_logs))