from elasticsearch import Elasticsearch
import random
import string
import time

client = Elasticsearch(
    "https://es01:9200",
    api_key="YXVPWGxKa0JQTUQxUTg5aVk5VzY6SVJqcTRPb3ptQVdTNWtzSkZBSk1pZw",
    ca_certs="./ca.crt",
    )

def generate_random_hostname():
    prefix = random.choice(["DESKTOP", "LAPTOP", "PC", "WORKSTATION"])
    suffix = ''.join(random.choices(string.ascii_uppercase + string.digits, k=7))
    return f"{prefix}-{suffix}"

def generate_random_mac():
    return ':'.join(f"{random.randint(0, 255):02x}" for _ in range(6))

def generate_multiple_macs():
    return [generate_random_mac() for _ in range(random.randint(1, 10))]

def generate_random_organization_id():
    return random.randint(1, 20)

def generate_random_ip():
    # Simulate private IP range, e.g., 192.168.x.x or 10.x.x.x
    private_range = random.choice(["192.168", "10"])
    if private_range == "192.168":
        return f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}"
    else:
        return f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def generate_random_message():
    ip = generate_random_ip()
    mac = generate_random_mac()
    return f"Lease IP {ip} renewed for MAC {mac}"

def generate_random_sophos_xg_status():
    return random.choice(["Release", "Renew", "Expire"])


for i in range(10):
    random_hostname = generate_random_hostname()
    random_mac = generate_multiple_macs()
    random_organization_id = generate_random_organization_id()

    asset = {
        "hostname": random_hostname,
        "mac": random_mac,
        "organization.id": random_organization_id
    }

    response = client.index(
        index="assets-logs-stream",
        document=asset
    )

for i in range(1000):
    random_ip = generate_random_ip()
    random_message = generate_random_message()
    random_organization_id = generate_random_organization_id()
    random_sophos_xg_status = generate_random_sophos_xg_status()

    dhcp_log = {
        "sophos.source.ip": random_ip,
        "message": random_message,
        "organization.id": random_organization_id,
        "sophos.xg.status": random_sophos_xg_status
    }

    response = client.index(
        index="dhcp-logs-stream",
        document=dhcp_log
    )
    
    print("created log" + str(dhcp_log))
    
    #time.sleep(random.randint(0,30))
