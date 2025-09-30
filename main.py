import logging
from elasticsearch import Elasticsearch
from dotenv import load_dotenv
import os
import time
import re

load_dotenv()

logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")

ELASTICSEARCH_URL = os.getenv('ELASTICSEARCH_URL')
ELASTICSEARCH_API_KEY = os.getenv('ELASTICSEARCH_API_KEY')
CA_CERT = os.getenv('CA_CERT')
ASSETS_LOGS_INDEX = os.getenv('ASSETS_LOGS_INDEX')
DHCP_LOGS_INDEX = os.getenv('DHCP_LOGS_INDEX')
SCAN_PERIOD_SECONDS = os.getenv('SCAN_PERIOD_SECONDS')

client = Elasticsearch(
    hosts=[ELASTICSEARCH_URL],
    api_key=ELASTICSEARCH_API_KEY,
    ca_certs=CA_CERT,
)

# for dhcp_log in dhcp_response["hits"]["hits"]:
#     print(dhcp_log["_source"])

# for asset_log in assets_response["hits"]["hits"]:
#     print(asset_log["_source"])

def normalize_macs(mac):
    return mac.lower().replace("-", ":")

mac_pattern = re.compile(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})")

def main():
    
    assets_response = client.search(
        index=ASSETS_LOGS_INDEX,
        query={"match_all": {}},
        size=10000
        )

    dhcp_response = client.search(
        index=DHCP_LOGS_INDEX,
        query={
            "range" : {
                "@timestamp" : {
                    "gte": f"now-{SCAN_PERIOD_SECONDS}s",
                    "lte": "now"
                    }
                }
            },
        size=10000
        )
    
    renew_macs = set()
    for dhcp_log in dhcp_response["hits"]["hits"]:
        mac_match = mac_pattern.search(dhcp_log["_source"]["message"])
        
        if mac_match is None:
            mac_match = "NO MAC FOUND"
        else:
            mac_match = normalize_macs(mac_match.group())
            
        log_mac = mac_match
        log_org_id = dhcp_log["_source"]['organization.id']
        log_status = dhcp_log["_source"]['sophos.xg.status']

        if log_status == "Renew":
            renew_macs.add(log_mac)

        same_org_assets = []
        for asset_log in assets_response["hits"]["hits"]:
            if asset_log["_source"]['organization.id'] == log_org_id:
                same_org_assets.extend(asset_log["_source"]['mac'])

        normalized_macs = {normalize_macs(mac) for mac in same_org_assets}

        if log_mac not in normalized_macs:
            logging.critical("Unauthorized MAC: %s", log_mac)

    # print("Unique MAC addresses with Renew status:")
    # for mac in sorted(renew_macs):
    #     print(f"  {mac}")


if __name__ == "__main__":
    while True:
        main()
        time.sleep(int(SCAN_PERIOD_SECONDS))
