#ping
import requests
def get_home():
    response = requests.get('https://api64.ipify.org?format=json').json()
    ip_address = response["ip"]
    response = requests.get(f'https://ipapi.co/{ip_address}/json/').json()
    location_data = {
        "ip": ip_address,
        "city": response.get("city")  ,
        "country": response.get("country_name"),
        "ISP": response.get("org")
    }
    return location_data
#address list generator
import re
def generate_ip_list(input_data, list):
    ip_list = re.findall(r'\d+\.\d+\.\d+\.\d+', input_data)
    comment_list = []

    for match in re.finditer(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,3})\s+(.*)", input_data):
        comment_list.append(match.group(2))

    output = []

    for i in range(0, len(ip_list)):
        answer = f"/ip firewall address-list add address={ip_list[i]} list={list} comment={comment_list[i]}"
        output.append(answer)

    return output
#dns look up
import dns.resolver
def find_dns(host, record):
    if record == "a":
        result = dns.resolver.query(host, 'A')
    elif record =="ns":
        result= dns.resolver.query(host,"NS")
    elif record =="txt":
        result = dns.resolver.query(host,"TXT")
    elif record =="mx":
        result = dns.resolver.query(host,"MX")
    return list(result)
import librouteros
#ping
def ping(host):
    ping_results = []
    #try:
    api = librouteros.connect(
            host='163.53.29.34',  # Replace with your RouterOS IP address
            username='kolusr',  # Replace with your RouterOS username
            password='4Cn723yVEl',  # Replace with your RouterOS password
        )
    for i in range(1):
            response = list(api(cmd='/ping', address=host, count='1'))
            time = response[0]['time']
            IP = response[0]["host"]
            packet = response[0]["packet-loss"]
            ping_results.append({'time': time, 'status': "UP", "address": host, "IP": IP, "packet": packet})
    api.close()
    return ping_results
#traceroute
import pandas as pd
def traceroute(destination_ip):
    api = librouteros.connect(host = '163.53.29.34',username = 'kolusr',password = '4Cn723yVEl')
    response = api('/tool/traceroute',count="1", address=destination_ip)
    data = [[item.get("address"), item.get("best"), item.get("worst"), item.get("avg"), item.get("last")] for item in response]
    del data [0:9]
    df =pd.DataFrame(data, columns=["Host: 163.53.29.34", "Best", "Worst", "Avg", "Last"])
    return df
#ptr generator
def generate_dns_zone(ip_address, prefix):
    num_of_prefix = pow(2, 32 - prefix)
    dns_config = f"@ 300 IN SOA ns1.maxbit.com.kh. noc.maxbit.com.kh. (\n"
    dns_config += "    2014102400 ; Serial\n"
    dns_config += "    300 ; Refresh\n"
    dns_config += "    1800 ; Retry\n"
    dns_config += "    3600 ; Expiry\n"
    dns_config += "    300 ; Minimum TTL\n"
    dns_config += "  )\n"
    dns_config += "IN NS ns1.maxbit.com.kh.\n"
    dns_config += "IN NS ns2.maxbit.com.kh.\n"
    ip_parts = ip_address.split('.')
    j = int(ip_parts[0])
    q = int(ip_parts[1])
    w = int(ip_parts[2])
    for i in range(0, num_of_prefix+1):
        k = i % 257
        ptr_record = f"{i} 300 IN PTR {j}.{q}.{w}.{k}.ip.maxbit.com.kh.\n"
        dns_config += ptr_record

        # Check if k reaches 256
        if k == 256:
            w += 1
            k = 0
            # Check if w reaches 256
            if w == 256:
                q += 1
                w = 0
                # Check if q reaches 256
                if q == 256:
                    j += 1
                    q = 0
    return dns_config


import http.client
import urllib.parse
import requests
import json
import socket
from ipwhois import IPWhois
import ssl


def get_domain_profile(domain_name):
    # Get the IP address for the domain
    ip_address = socket.gethostbyname(domain_name)

    # Retrieve domain WHOIS data using IPWhois
    ip_whois = IPWhois(ip_address)
    result = ip_whois.lookup_rdap()
    asn = result['asn']
    asn_description = result['asn_description']

    # Retrieve IP information using IP2WHOIS API
    p = {
        'key': 'E90274806E5603285FFCFF55EED0D570',
        'domain': domain_name,
        'format': 'json'
    }

    # Disable certificate verification
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    # Establish HTTPS connection
    conn = http.client.HTTPSConnection("api.ip2whois.com", context=context)
    conn.request("GET", "/v2?" + urllib.parse.urlencode(p))
    res = conn.getresponse()
    data = res.read()
    response_json = json.loads(data)

    # Extract desired information from the responses
    domain_profile = {
        'registrar': response_json.get("registrar"),
        'registrar_status': response_json.get('status'),
        'dates': [
            f"Created on {response_json.get('create_date')}",
            f"Updated on {response_json.get('update_date')}",
            f"Expires on {response_json.get('expire_date')}"
        ],
        "name_servers": response_json.get("nameservers"),
        "ip_address": ip_address,
        "ip_location": None,
        "ASN": f"{asn}, {asn_description}"
    }

    # Retrieve IP location information using IP2Location API
    if 'country_name' in response_json and 'city_name' in response_json:
        payload = {
            'key': 'E90274806E5603285FFCFF55EED0D570',
            'ip': ip_address,
            'format': 'json'
        }
        response = requests.get('https://api.ip2location.io/', params=payload, verify=False)
        location_json = response.json()
        domain_profile['ip_location'] = f"{location_json.get('country_name', '')}, {location_json.get('city_name', '')}"

    return domain_profile
