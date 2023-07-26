# cg-o365-dns-sync
Synchronized PrismaSDWAN DNS Profile with O365 domains from EDL


```Prisma SDWAN DNS Sync
---------------------------------------
Synchronizes a DNS Profile to split-DNS to local public DNS resolvers against FQDN's in an EDL.
Generally used to point Office365 FQDN's (retrieved from an EDL) to point to local 8.8.8.8 resolvers
while leaving the remainder of the profile untouched.

optional arguments:
  -h, --help            show this help message and exit
  --token "MYTOKEN", -t "MYTOKEN"
                        specify an authtoken to use for CloudGenix authentication
  --authtokenfile "MYTOKENFILE.TXT", -f "MYTOKENFILE.TXT"
                        a file containing the authtoken
  --url url, -u url     the EDL URL to Retrieve from (Defaults to Worldwide MS365 URL list from Palo Alto EDL Hosting Service)
  --service_role service_role, -s service_role
                        the DNS interface Service Role to use
  --profile profile, -p profile
                        the DNS Profile to write to
  --dns dns_server, -d dns_server
                        the DNS Server to use for the EDL entries in the Profile with the Service Roles```
