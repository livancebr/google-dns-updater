from flask import Flask
from flask import request
import os
import google.cloud.logging
from google.cloud.logging.handlers import CloudLoggingHandler

import time

import google.auth
from google.cloud import dns
from google.oauth2 import service_account
from ipaddress import ip_address, IPv4Address, IPv6Address

import config

# Grab our configuration
cfg = config.cfg

# Configure the client & zone
if len(cfg.gcpAuthKeyJsonFile) == 0:
    credentials, project = google.auth.default()
else:
    credentials = service_account.Credentials.from_service_account_file(cfg.gcpAuthKeyJsonFile)

client = dns.Client(project=cfg.gcpProject, credentials=credentials)
zone = client.zone(cfg.gcpDnsZoneName, cfg.gcpDnsDomain)

records = ""
changes = zone.changes()
app = Flask(__name__)

# Initialize the Google Cloud client
client = google.cloud.logging.Client()
cloud_handler = CloudLoggingHandler(client)
app.logger.addHandler(cloud_handler)
app.logger.setLevel("INFO")

def page_not_found(e):
    app.logger.error("The resource could not be found. %s", e)
    return "<h1>404</h1><p>The resource could not be found.</p>", 404


def page_unauthorized(e):
    app.logger.error("You are not authorized to access this resource. %s", e)
    return "<h1>401</h1><p>You are not authorized to access this resource.</p>", 401

@app.route("/", methods=["POST"])
def root():
    a_record_found = False
    aaaa_record_found = False
    a_record_changed = False
    aaaa_record_changed = False
    ret_val = ""
    
    app.logger.info("Update request started.")

    request_args = request.form.to_dict()

    # Assign our parameters
    if request_args:
        host = request_args.get('host')
        ipv4 = request_args.get('ipv4')
        ipv6 = request_args.get('ipv6')
        key = request_args.get('key')

    if ipv4 and not (validIPv4Address(ipv4)):
        app.logger.info("Given IPv4 {} is not valid".format(ipv4))
        ipv4 = ""

    if ipv6 and not (validIPv6Address(ipv6)):
        app.logger.info("Given IPv6 {} is not valid".format(ipv6))
        ipv6 = ""

    # Check we have the required parameters
    if not (host and key and (ipv4 or ipv6)):
        return page_not_found(404)

    # Check the key
    if not (check_key(host,key)):
        return page_unauthorized(401)

    # Get a list of the current records
    records = get_records()

    host_with_dot = host + '.'

    # Check for matching records
    for record in records:
        if record.name == host_with_dot and record.record_type == 'A' and ipv4:
            a_record_found = True
            for data in record.rrdatas:
                if test_for_record_change(data, ipv4):
                    add_to_change_set(record, 'delete')
                    add_to_change_set(create_record_set(host_with_dot, record.record_type, ipv4), 'create')
                    a_record_changed = True
                    ret_val += "IPv4 changed successful.\n"
                else:
                    ret_val += "IPv4 record up to date.\n"
        if record.name == host_with_dot and record.record_type == 'AAAA' and ipv6:
            aaaa_record_found = True
            for data in record.rrdatas:
                if test_for_record_change(data, ipv6):
                    add_to_change_set(record, 'delete')
                    add_to_change_set(create_record_set(host_with_dot, record.record_type, ipv6), 'create')
                    aaaa_record_changed = True
                    ret_val += "IPv6 changed successful.\n"
                else:
                    ret_val += "IPv6 Record up to date.\n"

    if not (a_record_found or aaaa_record_found):
        ret_val = "No matching records.\n"

    if a_record_changed or aaaa_record_changed:
        execute_change_set(changes)

    return ret_val


def check_key(host,key):

    host_key = next((x for x in cfg.app if x['hostname'] == host), None)

    print(host_key['key'])

    if host_key and host_key['key'] == key:
        app.logger.info("Key received from client is correct.")
        return True
    else:
        app.logger.error("Key received from client is incorrect.")
        return False


def validIPv4Address(ip):
    try:
        return True if type(ip_address(ip)) is IPv4Address else False
    except ValueError:
        return False

def validIPv6Address(ip):
    try:
        return True if type(ip_address(ip)) is IPv6Address else False
    except ValueError:
        return False


def get_records(client=client, zone=zone):
    # Get the records in batches
    return zone.list_resource_record_sets(max_results=100, page_token=None, client=client)


def test_for_record_change(old_ip, new_ip):
    app.logger.info("Existing IP is {}".format(old_ip))
    app.logger.info("New IP is {}".format(new_ip))
    if old_ip != new_ip:
        app.logger.info("IP addresses do no match. Update required.")
        return True
    else:
        app.logger.info("IP addresses match. No update required.")
        return False


def create_record_set(host, record_type, ip):
    record_set = zone.resource_record_set(
        host, record_type, cfg.ttl, [ip])
    return record_set


def add_to_change_set(record_set, atype):
    if atype == 'delete':
        return changes.delete_record_set(record_set)
    else:
        return changes.add_record_set(record_set)


def execute_change_set(changes):
    app.logger.info("Change set executed")
    changes.create()
    while changes.status != 'done':
        app.logger.info("Waiting for changes to complete. Change status is {}".format(changes.status))
        time.sleep(1)
        changes.reload()

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))

