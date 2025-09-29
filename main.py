import re
import logging
from datetime import datetime
from elasticsearch import Elasticsearch

logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")

client = Elasticsearch(
    "https://es01:9200",
    # api_key="YXVPWGxKa0JQTUQxUTg5aVk5VzY6SVJqcTRPb3ptQVdTNWtzSkZBSk1pZw",
    ca_certs="./ca.crt",
    basic_auth=("elastic", "changeme"),
    )

response = client.search(
    index="dhcp-logs-stream",
    query={
        "range": {
            "@timestamp": {
                "gte": "now-24h"
            }
        }
    },
)

print(response)

print(client.indices.get_data_stream(
    name="dhcp-logs-stream"
))

def normalize_macs(mac):
    return mac.lower().replace("-", ":")

def main():
    assets = [
        {"hostname": "pc1", "mac": ["12:12:12:12:12", "12:45:ff:ab:ab"], "organization.id": "1"},
        {"hostname": "pc2", "mac": ["b4:6d:83:2b:6a:a6", "aa:bb:cc:dd:ee:ff"], "organization.id": "1"},
        {"hostname": "pc3", "mac": ["11:22:33:44:55:66"], "organization.id": "2"},
        {"hostname": "pc4", "mac": ["77:88:99:aa:bb:cc", "dd:ee:ff:00:11:22", "33:44:55:66:77:88", "99:aa:bb:cc:dd:ee"], "organization.id": "3"},
    ]

    for i in range(1000):
        assets.append({"hostname": "pc4", "mac": ["77:88:99:aa:bb:cc", "dd:ee:ff:00:11:22", "33:44:55:66:77:88", "99:aa:bb:cc:dd:ee"], "organization.id": "3"},)

    dhcp_logs = [
        {"sophos.source.ip":"192.168.1.1","message":"Lease IP 192.168.1.163 renewed for MAC B4:6D:83:2B:6A:A6", "organization.id": "1", "sophos.xg.status": "Renew"},
        {"sophos.source.ip":"192.168.1.1","message":"Lease IP 192.168.1.163 renewed for MAC B4:6D:83:2B:6A:A6", "organization.id": "1", "sophos.xg.status": "Renew"},
        {"sophos.source.ip":"192.168.1.1","message":"Lease IP 192.168.1.163 renewed for MAC B4:6D:83:2B:6A:A6", "organization.id": "1", "sophos.xg.status": "Renew"},
        {"sophos.source.ip":"192.168.1.1","message":"Lease IP 192.168.1.163 renewed for MAC B4:6D:83:2B:6A:A6", "organization.id": "1", "sophos.xg.status": "Renew"},
        {"sophos.source.ip":"192.168.1.1","message":"Lease IP 192.168.1.144 renewed for MAC 33:44:55:66:77:88", "organization.id": "2", "sophos.xg.status": "Expire"},
        {"sophos.source.ip":"192.168.1.1","message":"Lease IP 192.168.1.124 renewed for MAC ff:ee:dd:cc:bb:aa", "organization.id": "3", "sophos.xg.status": "Release"},
    ]

    renew_macs = set()
    
    for log in dhcp_logs:
        log_mac = normalize_macs(log['message'].split('MAC')[1].strip())
        log_org_id = log['organization.id']
        log_status = log['sophos.xg.status']

        if log_status == "Renew":
            renew_macs.add(log_mac)

        same_org_assets = []
        for asset in assets:
            if asset['organization.id'] == log_org_id:
                same_org_assets.extend(asset['mac'])

        normalized_macs = {normalize_macs(mac) for mac in same_org_assets}

        if log_mac not in normalized_macs:
            logging.critical("Unauthorized MAC: %s", log_mac)

    print("Unique MAC addresses with Renew status:")
    for mac in sorted(renew_macs):
        print(f"  {mac}")


if __name__ == "__main__":
    main()
