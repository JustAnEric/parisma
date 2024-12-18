import requests
import json

# cloudflare doh endpoint
url = "https://1.1.1.1/dns-query"

# dns query parameters
query = {
    "name": "example.com",  # domain you want to resolve
    "type": "A"             # record type
}

# headers for doh request
headers = {
    "accept": "application/dns-json"
}

# send get request
response = requests.get(url, params=query, headers=headers)

# parse and print the response
if response.status_code == 200:
    dns_response = response.json()
    print(json.dumps(dns_response, indent=2))
else:
    print(f"error: {response.status_code}, {response.text}")