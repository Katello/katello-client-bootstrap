#!/usr/bin/python
#
import json
import getpass
import urllib2
import base64
import sys
import commands
import subprocess
import platform
import socket
import os.path
from datetime import datetime
from optparse import OptionParser
from uuid import getnode
from urllib import urlencode


HOSTNAME  = socket.getfqdn()
HEXMAC    = hex(getnode())
NOHEXMAC  = HEXMAC[2:]
MAC       = NOHEXMAC.zfill(13)[0:12]
RELEASE   = platform.linux_distribution()[1]

parser = OptionParser()
parser.add_option("-s", "--server", dest="sat6_fqdn", help="FQDN of Satellite - omit https://", metavar="SAT6_FQDN")
parser.add_option("-l", "--login", dest="login", default='admin', help="Login user for API Calls", metavar="LOGIN")
parser.add_option("-p", "--password", dest="password", help="Password for specified user. Will prompt if omitted", metavar="PASSWORD")
parser.add_option("-a", "--activationkey", dest="activationkey", help="Activation Key to register the system", metavar="ACTIVATIONKEY")
parser.add_option("-P", "--skip-puppet", dest="no_puppet", action="store_true", default=False, help="Do not install Puppet")
parser.add_option("-g", "--hostgroup", dest="hostgroup", help="Label of the Hostgroup in Satellite that the host is to be associated with", metavar="HOSTGROUP")
parser.add_option("-L", "--location", dest="location", default='Default_Location', help="Label of the Location in Satellite that the host is to be associated with", metavar="HOSTGROUP")
parser.add_option("-o", "--organization", dest="org", default='Default_Organization', help="Label of the Organization in Satellite that the host is to be associated with", metavar="ORG")
parser.add_option("-S", "--subscription-manager-args", dest="smargs", default="", help="Which additional arguments shall be passed to subscription-manager", metavar="ARGS")
parser.add_option("-u", "--update", dest="update", action="store_true", help="Fully Updates the System")
parser.add_option("-v", "--verbose", dest="verbose", action="store_true", help="Verbose output")
parser.add_option("-f", "--force", dest="force", action="store_true", help="Force registration (will erase old katello and puppet certs)")
parser.add_option("-r", "--release", dest="release", default=RELEASE, help="Specify release version")
(options, args) = parser.parse_args()

if not (options.sat6_fqdn and options.login and options.hostgroup and options.location and options.org and options.activationkey):
    print "Must specify server, login, hostgroup, location, and organization options.  See usage:"
    parser.print_help()
    print "\nExample usage: ./bootstrap.py -l admin -s satellite.example.com -o Default_Organization -L Default_Location -g My_Hostgroup -a My_Activation_Key"
    sys.exit(1)
else:
    SAT6_FQDN = options.sat6_fqdn
    LOGIN     = options.login
    PASSWORD  = options.password
    HOSTGROUP = options.hostgroup
    LOCATION  = options.location
    ORG       = options.org
    ACTIVATIONKEY = options.activationkey

if options.verbose:
    VERBOSE=True
else:
    VERBOSE=False

if options.update:
    UPDATE=True
else:
    UPDATE=False

if not PASSWORD:
    PASSWORD = getpass.getpass("%s's password:" % LOGIN)

if VERBOSE:
    print "HOSTNAME - %s" % HOSTNAME
    print "RELEASE - %s" % RELEASE
    print "MAC - %s" % MAC
    print "SAT6_FQDN - %s" % SAT6_FQDN
    print "LOGIN - %s" % LOGIN
    print "PASSWORD - %s" % PASSWORD
    print "HOSTGROUP - %s" % HOSTGROUP
    print "LOCATION - %s" % LOCATION
    print "ORG - %s" % ORG
    print "ACTIVATIONKEY - %s" % ACTIVATIONKEY
    print "UPDATE - %s" % UPDATE

class error_colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

def print_error(msg):
    print "[%sERROR%s], [%s], EXITING: [%s] failed to execute properly." % (error_colors.FAIL, error_colors.ENDC, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), msg)

def print_warning(msg):
    print "[%sWARNING%s], [%s], NON-FATAL: [%s] failed to execute properly." % (error_colors.WARNING, error_colors.ENDC, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), msg)

def print_success(msg):
    print "[%sSUCCESS%s], [%s], [%s], completed successfully." % (error_colors.OKGREEN, error_colors.ENDC, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), msg)

def print_running(msg):
    print "[%sRUNNING%s], [%s], [%s] " % (error_colors.OKBLUE, error_colors.ENDC, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), msg)

def print_generic(msg):
    print "[NOTIFICATION], [%s], [%s] " % (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), msg)

def get_output(command):
    output = commands.getstatusoutput(command)[1]
    return output

def exec_failok(command):
    print_running(command)
    output = commands.getstatusoutput(command)
    retcode = output[0]
    if retcode != 0:
        print_warning(command)
    print output[1]
    print ""

def exec_failexit(command):
    print_running(command)
    output = commands.getstatusoutput(command)
    retcode = output[0]
    if retcode != 0:
        print_error(command)
        print output[1]
        exit(retcode)
    print output[1]
    print_success(command)
    print ""

def install_prereqs():
    print_generic("Installing subscription manager prerequisites")
    exec_failexit("/usr/bin/yum -y remove subscription-manager-gnome")
    exec_failexit("/usr/bin/yum -y install subscription-manager subscription-manager-migration-*")
    exec_failexit("/usr/bin/yum -y update yum openssl")

def get_bootstrap_rpm():
    if options.force:
        clean_katello_certs()
    print_generic("Retrieving Candlepin Consumer RPMs")
    exec_failexit("/usr/bin/yum -y localinstall http://%s/pub/katello-ca-consumer-latest.noarch.rpm --nogpgcheck" % SAT6_FQDN)

def migrate_systems(org_name, ak):
    org_label=return_matching_org_label(org_name)
    print_generic("Calling rhn-migrate-classic-to-rhsm")
    #print_generic("First Prompt is for RHN Classic / Satellite 5 credentials")
    #print_generic("Second Prompt is for Satellite 6 credentials")
    #subprocess.call("/usr/sbin/rhn-migrate-classic-to-rhsm")
    exec_failexit("/usr/sbin/rhn-migrate-classic-to-rhsm --org %s --activationkey %s --keep" % (org_label, ak))

def register_systems(org_name, ak, release):
    org_label=return_matching_org_label(org_name)
    print_generic("Calling subscription-manager")
    if options.force:
        options.smargs += " --force"
    # exec_failexit("/usr/sbin/subscription-manager register --org %s --activationkey %s --release %s" % (org_label,ak,release))
    exec_failexit("/usr/sbin/subscription-manager register --org '%s' --name '%s' --activationkey '%s' %s" % (org_label, HOSTNAME, ak, options.smargs))

def enable_sat_tools():
    print_generic("Enabling the Satellite tools repositories for Puppet & Katello Agents")
    exec_failexit("subscription-manager repos --enable=rhel-*-satellite-tools-*-rpms")

def clean_katello_certs():
  print_generic("Cleaning old Katello certs")
  exec_failexit("/usr/bin/yum -y erase katello-ca-consumer-*")

def install_katello_agent():
    print_generic("Installing the Katello agent")
    exec_failexit("/usr/bin/yum -y install katello-agent")
    exec_failexit("/sbin/chkconfig goferd on")
    exec_failexit("/sbin/service goferd restart")

def clean_puppet():
    print_generic("Cleaning old Puppet Agent")
    exec_failexit("/usr/bin/yum -y erase puppet")
    exec_failexit("rm -rf /var/lib/puppet/")

def install_puppet_agent():
    puppet_env = return_puppetenv_for_hg(return_matching_hg_id(HOSTGROUP))
    print_generic("Installing the Puppet Agent")
    exec_failexit("/usr/bin/yum -y install puppet")
    exec_failexit("/sbin/chkconfig puppet on")
    exec_failexit("/usr/bin/puppet config set server %s --section agent" % SAT6_FQDN)
    exec_failexit("/usr/bin/puppet config set ca_server %s --section agent" % SAT6_FQDN)
    exec_failexit("/usr/bin/puppet config set environment %s --section agent" % puppet_env)
    ### Might need this for RHEL5
    #f = open("/etc/puppet/puppet.conf","a")
    #f.write("server=%s \n" % SAT6_FQDN)
    #f.close()
    print_generic("Running Puppet in noop mode to generate SSL certs")
    exec_failexit("/usr/bin/puppet agent --test --noop --tags no_such_tag --waitforcert 10")
    exec_failexit("/sbin/service puppet restart")

def fully_update_the_box():
    print_generic("Fully Updating The Box")
    exec_failexit("/usr/bin/yum -y update")

def get_json(url):
    # Generic function to HTTP GET JSON from Satellite's API
    try:
        request = urllib2.Request(url)
        base64string = base64.encodestring('%s:%s' % (LOGIN, PASSWORD)).strip()
        request.add_header("Authorization", "Basic %s" % base64string)
        result = urllib2.urlopen(request)
        return json.load(result)
    except urllib2.URLError, e:
        print "Error: cannot connect to the API: %s" % (e)
        print "Check your URL & try to login using the same user/pass via the WebUI and check the error!"
        sys.exit(1)
    except:
        print "FATAL Error - %s" % (e)
        sys.exit(2)

def post_json(url, jdata):
    # Generic function to HTTP PUT JSON to Satellite's API.
    # Had to use a couple of hacks to urllib2 to make it
    # support an HTTP PUT, which it doesn't by default.
    try:
        opener = urllib2.build_opener(urllib2.HTTPHandler)
        request = urllib2.Request(url)
        base64string = base64.encodestring('%s:%s' % (LOGIN, PASSWORD)).strip()
        request.add_data(json.dumps(jdata))
        request.add_header("Authorization", "Basic %s" % base64string)
        request.add_header("Content-Type", "application/json")
        request.add_header("Accept", "application/json")
        #request.get_method = lambda: 'PUT'
        request.get_method = lambda: 'POST'
        url = opener.open(request)
    except urllib2.URLError, e:
        print "Error: cannot connect to the API: %s" % (e)
        print "Check your URL & try to login using the same user/pass via the WebUI and check the error!"
        sys.exit(1)
    except:
        print "FATAL Error - %s" % (e)
        sys.exit(2)

def delete_json(url):
	# Generic function to HTTP DELETE JSON from Satellite's API
    try:
        request = urllib2.Request(url)
        base64string = base64.encodestring('%s:%s' % (LOGIN, PASSWORD)).strip()
        request.add_header("Authorization", "Basic %s" % base64string)
        request.get_method = lambda: 'DELETE'
        result = urllib2.urlopen(request)
	return json.load(result)
    except urllib2.HTTPError, e:
        if e.code != 404:
            raise e
    except urllib2.URLError, e:
        print "Error: cannot connect to the API: %s" % (e)
        print "Check your URL & try to login using the same user/pass via the WebUI and check the error!"
        sys.exit(1)
    except:
        print "FATAL Error - %s" % (e)
        sys.exit(2)

def return_matching_hg_id(hg_name):
    # Given a hostgroup name, find its id
    myurl = "https://" + SAT6_FQDN+ "/api/v2/hostgroups/?" + urlencode([('search', 'title=%s' % hg_name)])
    hostgroup = get_json(myurl)
    hg_id = hostgroup['results'][0]['id']
    return hg_id

def return_puppetenv_for_hg(hg_id):
    myurl = "https://" + SAT6_FQDN+ "/api/v2/hostgroups/" + str(hg_id)
    hostgroup = get_json(myurl)
    return hostgroup['environment_name']

def return_matching_host_id(hostname):
    # Given a hostname (more precisely a puppet certname) find its id
    myurl = "https://" + SAT6_FQDN+ "/api/v2/hosts/" + hostname
    host = get_json(myurl)
    host_id = host['id']
    return host_id

def return_matching_location(location):
    # Given a location, find its id
    myurl = "https://" + SAT6_FQDN+ "/api/v2/locations/?" + urlencode([('search', 'title=%s' % location)])
    location = get_json(myurl)
    loc_id = location['results'][0]['id']
    return loc_id

def return_matching_org(organization):
    # Given an org, find its id.
    myurl = "https://" + SAT6_FQDN+ "/api/v2/organizations/"
    # myurl = "https://" + SAT6_FQDN+ "/katello/api/organizations/" + organization
    organizations = get_json(myurl)
    for org in organizations['results']:
        if org['name'] == organization:
            org_id = org['id']
            return org_id

def return_matching_org_label(organization):
    # Given an org name, find its label - required by subscription-manager
    myurl = "https://" + SAT6_FQDN+ "/katello/api/organizations/" + organization
    print "myurl: " + myurl
    organization = get_json(myurl)
    org_label = organization['label']
    return org_label

#def update_host_with_org():
# myhgid = return_matching_hg_id(HOSTGROUP)
# myhostid = return_matching_host_id(HOSTNAME)
# mylocid = return_matching_location(LOCATION)
# myorgid = return_matching_org(ORG)
# jsondata = json.loads('{"id": %s,"host": {"hostgroup_id": %s,"organization_id": %s,"location_id": %s}}' % (myhostid,myhgid,myorgid,mylocid))
# myurl = "https://" + SAT6_FQDN + "/api/v2/hosts/" + str(myhostid) + "/"
# print_running("Calling Satellite API to associate host with hostgroup, org & location")
# post_json(myurl,jsondata)
# print_success("Successfully associated host with hostgroup, org & location")

def create_host():
    myhgid = return_matching_hg_id(HOSTGROUP)
    mylocid = return_matching_location(LOCATION)
    myorgid = return_matching_org(ORG)
    if VERBOSE:
        print "------\nmyhgid: " + str(myhgid)  + "\nmylocid: " + str(mylocid) + "\nmyorgid: " + str(myorgid) + "\nMAC: " + str(MAC) + "\n------"
    jsondata = json.loads('{"host": {"name": "%s","hostgroup_id": %s,"organization_id": %s,"location_id": %s,"mac":"%s"}}' % (HOSTNAME, myhgid, myorgid, mylocid, MAC))
    myurl = "https://" + SAT6_FQDN + "/api/v2/hosts/"
    if options.force:
        print_running("Deleting old host if any")
        delete_json("%s/%s" % (myurl, HOSTNAME))
    print_running("Calling Satellite API to create a host entry associated with the group, org & location")
    post_json(myurl, jsondata)
    print_success("Successfully created host %s" % HOSTNAME)

def check_rhn_registration():
    return os.path.exists('/etc/sysconfig/rhn/systemid')

print "Satellite 6 Bootstrap Script"
print "This script is designed to register new systems or to migrate an existing system to Red Hat Satellite 6"

if check_rhn_registration():
    print_generic('This system is registered to RHN. Attempting to migrate via rhn-classic-migrate-to-rhsm')
    create_host()
    install_prereqs()
    get_bootstrap_rpm()
    migrate_systems(ORG, ACTIVATIONKEY)
else:
    print_generic('This system is not registered to RHN. Attempting to register via subscription-manager')
    create_host()
    get_bootstrap_rpm()
    register_systems(ORG, ACTIVATIONKEY, options.release)

enable_sat_tools()
install_katello_agent()
if UPDATE:
	fully_update_the_box()

if not options.no_puppet:
  if options.force:
    clean_puppet()
  install_puppet_agent()

fully_update_the_box()
