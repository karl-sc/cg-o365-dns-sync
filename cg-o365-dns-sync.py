#!/usr/bin/python3
PROGRAM_NAME = "cg-o365-dns-sync.py"
PROGRAM_DESCRIPTION = """
Prisma SDWAN DNS Sync
---------------------------------------
Synchronizes a DNS Profile to split-DNS to local public DNS resolvers against FQDN's in an EDL.
Generally used to point Office365 FQDN's (retrieved from an EDL) to point to local 8.8.8.8 resolvers
while leaving the remainder of the profile untouched.

"""

####Library Imports
from cloudgenix import API, jd
import os
import re
import sys
import argparse
import requests
from csv import reader

def parse_arguments():
    CLIARGS = {}
    parser = argparse.ArgumentParser(
        prog=PROGRAM_NAME,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=PROGRAM_DESCRIPTION
            )
    parser.add_argument('--token', '-t', metavar='"MYTOKEN"', type=str, 
                    help='specify an authtoken to use for CloudGenix authentication')
    parser.add_argument('--authtokenfile', '-f', metavar='"MYTOKENFILE.TXT"', type=str, 
                    help='a file containing the authtoken')
    parser.add_argument('--url', '-u', metavar='url', type=str, 
                    help='the EDL URL to Retrieve from (Defaults to Worldwide MS365 URL list from Palo Alto EDL Hosting Service)', 
                    default="https://saasedl.paloaltonetworks.com/feeds/m365/worldwide/any/all/url", 
                    required=False)
    parser.add_argument('--service_role', '-s', metavar='service_role', type=str, 
                    help='the DNS interface Service Role to use', required=True)
    parser.add_argument('--profile', '-p', metavar='profile', type=str, 
                    help='the DNS Profile to write to', required=True)
    parser.add_argument('--dns', '-d', metavar='dns_server', type=str, 
                    help='the DNS Server to use for the EDL entries in the Profile with the Service Roles', required=True)
    args = parser.parse_args()
    CLIARGS.update(vars(args))
    return CLIARGS

def authenticate(CLIARGS):
    print("AUTHENTICATING...")
    user_email = None
    user_password = None
    
    sdk = API()    
    ##First attempt to use an AuthTOKEN if defined
    if CLIARGS['token']:                    #Check if AuthToken is in the CLI ARG
        CLOUDGENIX_AUTH_TOKEN = CLIARGS['token']
        print("    ","Authenticating using Auth-Token in from CLI ARGS")
    elif CLIARGS['authtokenfile']:          #Next: Check if an AuthToken file is used
        tokenfile = open(CLIARGS['authtokenfile'])
        CLOUDGENIX_AUTH_TOKEN = tokenfile.read().strip()
        print("    ","Authenticating using Auth-token from file",CLIARGS['authtokenfile'])
    elif "X_AUTH_TOKEN" in os.environ:              #Next: Check if an AuthToken is defined in the OS as X_AUTH_TOKEN
        CLOUDGENIX_AUTH_TOKEN = os.environ.get('X_AUTH_TOKEN')
        print("    ","Authenticating using environment variable X_AUTH_TOKEN")
    elif "AUTH_TOKEN" in os.environ:                #Next: Check if an AuthToken is defined in the OS as AUTH_TOKEN
        CLOUDGENIX_AUTH_TOKEN = os.environ.get('AUTH_TOKEN')
        print("    ","Authenticating using environment variable AUTH_TOKEN")
    else:                                           #Next: If we are not using an AUTH TOKEN, set it to NULL        
        CLOUDGENIX_AUTH_TOKEN = None
        print("    ","Authenticating using interactive login")
    ##ATTEMPT AUTHENTICATION
    if CLOUDGENIX_AUTH_TOKEN:
        sdk.interactive.use_token(CLOUDGENIX_AUTH_TOKEN)
        if sdk.tenant_id is None:
            print("    ","ERROR: AUTH_TOKEN login failure, please check token.")
            sys.exit()
    else:
        while sdk.tenant_id is None:
            sdk.interactive.login(user_email, user_password)
            # clear after one failed login, force relogin.
            if not sdk.tenant_id:
                user_email = None
                user_password = None            
    print("    ","SUCCESS: Authentication Complete")
    return sdk

def logout(sdk):
    print("Logging out")
    sdk.get.logout()


##########MAIN FUNCTION#############
def go(sdk, CLIARGS):
    ####CODE GOES BELOW HERE#########
    dns_profile_name = CLIARGS['profile']
    service_role = CLIARGS['service_role']
    dns_server = CLIARGS['dns']
    edl_url = CLIARGS['url']
    #CLIARGS['profile'] = "pglabdns"
    #CLIARGS['service_role'] = "br_lan_role"
    resp = sdk.get.tenants()
    if resp.cgx_status:
        tenant_name = resp.cgx_content.get("name", None)
        print("======== TENANT NAME",tenant_name,"========")
    else:
        logout()
        print("ERROR: API Call failure when enumerating TENANT Name! Exiting!")
        print(resp.cgx_status)
        sys.exit((vars(resp)))

    ### Retrieve the EDL list of domains and store in a LIST object
    list_of_domains = retrieve_edl_to_list(edl_url)
    if not list_of_domains:
        sys.exit("Error, Unable to retrieve EDL list")

    ### Retrieve the desired DNS Service Profile as a GET (with eTag and all)
    dns_profile = get_dns_service_profile(dns_profile_name, sdk)
    if not dns_profile:
        sys.exit("Error, Unable to retrieve DNS Service Profile")

    ### Retrieve the Service Role ID number for interface binding
    service_role_id = get_dns_serviceroles(service_role, sdk)
    if not service_role_id:
        sys.exit("Error, Unable to retrieve Service Role ID for DNS service")
    
    put_dns_profile = populate_dns_profile_breakout(dns_profile=dns_profile, fqdn_list=list_of_domains, dns_primary=dns_server, service_role_id=service_role_id)
    result = sdk.put.dnsserviceprofiles(dns_profile['id'], put_dns_profile)
    print("Put Complete. STATUS:",result.cgx_status)
    ####CODE GOES ABOVE HERE#########

def validate_dns_profile(edl_url=None):
    pass

def retrieve_edl_to_list(edl_url):
    response = requests.get(edl_url)
    listofdomains= re.sub('\*\.|\/',"",response.text).split()
    return listofdomains

def get_dns_service_profile(profile_name, sdk):
    result = sdk.get.dnsserviceprofiles()
    answer = None
    for dns_profile in result.cgx_content['items']:
        if dns_profile['name'] == profile_name :
            answer = sdk.get.dnsserviceprofiles(dnsserviceprofile_id=dns_profile['id']).cgx_content
            return answer
    return answer
    
def edl_fqdn_filter(edl_list=None):
    pass

def populate_dns_profile_breakout(dns_profile=None, fqdn_list=None, dns_primary=None, service_role_id=None):
    dns_svr_fwd_config = dns_profile['dns_forward_config']['dns_servers']
    for domain in fqdn_list:
        domain_missing = True
        for dns_fwd_entry in dns_svr_fwd_config:
            if dns_fwd_entry.get("domain_names") != None:
                if dns_fwd_entry["domain_names"][0] == domain:
                    domain_missing = False
        if (domain_missing): 
            dns_profile['dns_forward_config']['dns_servers'].append(
            {
                "ip_prefix": "",
                "domain_names": [domain],
                "dnsserver_ip": dns_primary,
                "dnsserver_port": None,
                "forward_dnsservicerole_id": service_role_id,
                "source_port": None,
                "address_family": "ipv4"
            })
    return dns_profile

def get_dns_serviceroles(service_role_name, sdk):
    result = sdk.get.dnsserviceroles()
    for serviceroles in result.cgx_content.get('items', None):
        if serviceroles['name'] == service_role_name:
            return serviceroles['id']
    return None


if __name__ == "__main__":
    ###Get the CLI Arguments
    CLIARGS = parse_arguments()

    ###Authenticate
    SDK = authenticate(CLIARGS)
    
    ###Run Code
    go(SDK, CLIARGS)

    ###Exit Program
    logout(SDK)
