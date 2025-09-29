import re
import logging
from datetime import datetime
from elasticsearch import Elasticsearch

logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")

client = Elasticsearch(
    "https://es01:9200",
    api_key="YXVPWGxKa0JQTUQxUTg5aVk5VzY6SVJqcTRPb3ptQVdTNWtzSkZBSk1pZw",
    ca_certs="./ca.crt",
    )

assets_response = client.search(
    index="assets-logs-stream",
    query={"match_all": {}}
)

dhcp_response = client.search(
    index="dhcp-logs-stream",
    query={"match_all": {}}
)

def normalize_macs(mac):
    return mac.lower().replace("-", ":")

def main():

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
