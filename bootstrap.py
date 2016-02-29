#!/usr/bin/python
#
import json
import getpass
import urllib2
import base64
import sys
import commands
import platform
import socket
import os.path
from datetime import datetime
from optparse import OptionParser
from uuid import getnode
from urllib import urlencode
from ConfigParser import SafeConfigParser


def get_architecture():
    # May not be safe for anything apart from 32/64 bit OS
    is_64bit = sys.maxsize > 2 ** 32
    if is_64bit:
        return "x86_64"
    else:
        return "x86"

FQDN = socket.getfqdn()
HOSTNAME = FQDN.split('.')[0]
DOMAIN = FQDN[FQDN.index('.')+1:]
HEXMAC = hex(getnode())
NOHEXMAC = HEXMAC[2:]
MAC = NOHEXMAC.zfill(13)[0:12]
RELEASE = platform.linux_distribution()[1]
API_PORT = 443
ARCHITECTURE = get_architecture()

parser = OptionParser()
parser.add_option("-s", "--server", dest="sat6_fqdn", help="FQDN of Satellite OR Satellite Capsule - omit https://", metavar="SAT6_FQDN")
parser.add_option("-l", "--login", dest="login", default='admin', help="Login user for API Calls", metavar="LOGIN")
parser.add_option("-p", "--password", dest="password", help="Password for specified user. Will prompt if omitted", metavar="PASSWORD")
parser.add_option("--legacy-login", dest="legacy_login", default='admin', help="Login user for Satellite 5 API Calls", metavar="LOGIN")
parser.add_option("--legacy-password", dest="legacy_password", help="Password for specified Satellite 5 user. Will prompt if omitted", metavar="PASSWORD")
parser.add_option("--legacy-purge", dest="legacy_purge", action="store_true", help="Purge system from the Legacy environment (e.g. Sat5)")
parser.add_option("-a", "--activationkey", dest="activationkey", help="Activation Key to register the system", metavar="ACTIVATIONKEY")
parser.add_option("-P", "--skip-puppet", dest="no_puppet", action="store_true", default=False, help="Do not install Puppet")
parser.add_option("-g", "--hostgroup", dest="hostgroup", help="Label of the Hostgroup in Satellite that the host is to be associated with", metavar="HOSTGROUP")
parser.add_option("-L", "--location", dest="location", default='Default_Location', help="Label of the Location in Satellite that the host is to be associated with", metavar="LOCATION")
parser.add_option("-O", "--operatingsystem", dest="operatingsystem", default=None, help="Label of the Operating System in Satellite that the host is to be associated with", metavar="OPERATINGSYSTEM")
parser.add_option("-o", "--organization", dest="org", default='Default_Organization', help="Label of the Organization in Satellite that the host is to be associated with", metavar="ORG")
parser.add_option("-S", "--subscription-manager-args", dest="smargs", default="", help="Which additional arguments shall be passed to subscription-manager", metavar="ARGS")
parser.add_option("--rhn-migrate-args", dest="rhsmargs", default="", help="Which additional arguments shall be passed to rhn-migrate-classic-to-rhsm", metavar="ARGS")
parser.add_option("-u", "--update", dest="update", action="store_true", help="Fully Updates the System")
parser.add_option("-v", "--verbose", dest="verbose", action="store_true", help="Verbose output")
parser.add_option("-f", "--force", dest="force", action="store_true", help="Force registration (will erase old katello and puppet certs)")
parser.add_option("--remove", dest="remove", action="store_true", help="Instead of registring the machine to Satellite remove it")
parser.add_option("-r", "--release", dest="release", default=RELEASE, help="Specify release version")
parser.add_option("-R", "--remove-rhn-packages", dest="removepkgs", action="store_true", help="Remove old Red Hat Network Packages")
parser.add_option("--unmanaged", dest="unmanaged", action="store_true", help="Add the server as unmanaged. Useful to skip provisioning dependencies.")
(options, args) = parser.parse_args()

if not (options.sat6_fqdn and options.login and (options.remove or (options.org and options.hostgroup and options.location and options.activationkey))):
    print "Must specify server, login, hostgroup, location, and organization options.  See usage:"
    parser.print_help()
    print "\nExample usage: ./bootstrap.py -l admin -s satellite.example.com -o Default_Organization -L Default_Location -g My_Hostgroup -a My_Activation_Key"
    sys.exit(1)

if not options.password:
    options.password = getpass.getpass("%s's password:" % options.login)

if options.verbose:
    print "HOSTNAME - %s" % HOSTNAME
    print "DOMAIN - %s" % DOMAIN
    print "RELEASE - %s" % RELEASE
    print "MAC - %s" % MAC
    print "SAT6_FQDN - %s" % options.sat6_fqdn
    print "LOGIN - %s" % options.login
    print "PASSWORD - %s" % options.password
    print "HOSTGROUP - %s" % options.hostgroup
    print "LOCATION - %s" % options.location
    print "OPERATINGSYSTEM - %s" % options.operatingsystem
    print "ORG - %s" % options.org
    print "ACTIVATIONKEY - %s" % options.activationkey
    print "UPDATE - %s" % options.update

error_colors = {
    'HEADER': '\033[95m',
    'OKBLUE': '\033[94m',
    'OKGREEN': '\033[92m',
    'WARNING': '\033[93m',
    'FAIL': '\033[91m',
    'ENDC': '\033[0m',
}


def print_error(msg):
    print "[%sERROR%s], [%s], EXITING: [%s] failed to execute properly." % (error_colors['FAIL'], error_colors['ENDC'], datetime.now().strftime('%Y-%m-%d %H:%M:%S'), msg)


def print_warning(msg):
    print "[%sWARNING%s], [%s], NON-FATAL: [%s] failed to execute properly." % (error_colors['WARNING'], error_colors['ENDC'], datetime.now().strftime('%Y-%m-%d %H:%M:%S'), msg)


def print_success(msg):
    print "[%sSUCCESS%s], [%s], [%s], completed successfully." % (error_colors['OKGREEN'], error_colors['ENDC'], datetime.now().strftime('%Y-%m-%d %H:%M:%S'), msg)


def print_running(msg):
    print "[%sRUNNING%s], [%s], [%s] " % (error_colors['OKBLUE'], error_colors['ENDC'], datetime.now().strftime('%Y-%m-%d %H:%M:%S'), msg)


def print_generic(msg):
    print "[NOTIFICATION], [%s], [%s] " % (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), msg)


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
        sys.exit(retcode)
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
        clean_katello_agent()
    print_generic("Retrieving Candlepin Consumer RPMs")
    exec_failexit("/usr/bin/yum -y localinstall http://%s/pub/katello-ca-consumer-latest.noarch.rpm --nogpgcheck" % options.sat6_fqdn)


def migrate_systems(org_name, activationkey):
    org_label = return_matching_org_label(org_name)
    print_generic("Calling rhn-migrate-classic-to-rhsm")
    options.rhsmargs += " --destination-url=https://%s:%s" % (options.sat6_fqdn, API_PORT)
    if options.legacy_purge:
        options.rhsmargs += " --legacy-user '%s' --legacy-password '%s'" % (options.legacy_login, options.legacy_password)
    else:
        options.rhsmargs += " --keep"
    if options.force:
        options.rhsmargs += " --force"
    exec_failexit("/usr/sbin/rhn-migrate-classic-to-rhsm --org %s --activation-key %s %s" % (org_label, activationkey, options.rhsmargs))
    exec_failexit("subscription-manager config --rhsm.baseurl=https://%s/pulp/repos" % options.sat6_fqdn)


def register_systems(org_name, activationkey, release):
    org_label = return_matching_org_label(org_name)
    print_generic("Calling subscription-manager")
    options.smargs += " --serverurl=https://%s:%s/rhsm --baseurl=https://%s/pulp/repos" % (options.sat6_fqdn, API_PORT, options.sat6_fqdn)
    if options.force:
        options.smargs += " --force"
    # exec_failexit("/usr/sbin/subscription-manager register --org %s --activationkey %s --release %s" % (org_label,activationkey,release))
    exec_failexit("/usr/sbin/subscription-manager register --org '%s' --name '%s' --activationkey '%s' %s" % (org_label, FQDN, activationkey, options.smargs))


def unregister_system():
    print_generic("Unregistering")
    exec_failexit("/usr/sbin/subscription-manager unregister")


def enable_sat_tools():
    print_generic("Enabling the Satellite tools repositories for Puppet & Katello Agents")
    exec_failexit("subscription-manager repos --enable=rhel-*-satellite-tools-*-rpms")


def clean_katello_agent():
    print_generic("Removing old Katello agent and certs")
    exec_failexit("/usr/bin/yum -y erase katello-ca-consumer-* katello-agent gofer")


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
    puppet_env = return_puppetenv_for_hg(return_matching_hg_id(options.hostgroup))
    print_generic("Installing the Puppet Agent")
    exec_failexit("/usr/bin/yum -y install puppet")
    exec_failexit("/sbin/chkconfig puppet on")
    exec_failexit("/usr/bin/puppet config set server %s --section agent" % options.sat6_fqdn)
    exec_failexit("/usr/bin/puppet config set ca_server %s --section agent" % options.sat6_fqdn)
    exec_failexit("/usr/bin/puppet config set environment %s --section agent" % puppet_env)
    # Might need this for RHEL5
    # f = open("/etc/puppet/puppet.conf","a")
    # f.write("server=%s \n" % options.sat6_fqdn)
    # f.close()
    print_generic("Running Puppet in noop mode to generate SSL certs")
    print_generic("Visit the UI and approve this certificate via Infrastructure->Capsules")
    print_generic("if auto-signing is disabled")
    exec_failexit("/usr/bin/puppet agent --test --noop --tags no_such_tag --waitforcert 10")
    exec_failexit("/sbin/service puppet restart")


def remove_old_rhn_packages():
    pkg_list = "rhn-setup rhn-client-tools yum-rhn-plugin rhnsd rhn-check rhnlib spacewalk-abrt spacewalk-oscap osad"
    print_generic("Removing old RHN packages")
    exec_failexit("/usr/bin/yum -y remove %s" % pkg_list)


def fully_update_the_box():
    print_generic("Fully Updating The Box")
    exec_failexit("/usr/bin/yum -y update")


def get_json(url):
    # Generic function to HTTP GET JSON from Satellite's API
    try:
        request = urllib2.Request(url)
        if options.verbose:
            print "request: " + url
        base64string = base64.encodestring('%s:%s' % (options.login, options.password)).strip()
        request.add_header("Authorization", "Basic %s" % base64string)
        result = urllib2.urlopen(request)
        return json.load(result)
    except urllib2.URLError, e:
        print "Error: cannot connect to the API: %s" % (e)
        print "Check your URL & try to login using the same user/pass via the WebUI and check the error!"
        print "error: " + e.read()
        print "url: " + url
        sys.exit(1)
    except Exception, e:
        print "FATAL Error - %s" % (e)
        sys.exit(2)


def post_json(url, jdata):
    # Generic function to HTTP PUT JSON to Satellite's API.
    # Had to use a couple of hacks to urllib2 to make it
    # support an HTTP PUT, which it doesn't by default.
    try:
        opener = urllib2.build_opener(urllib2.HTTPHandler)
        request = urllib2.Request(url)
        base64string = base64.encodestring('%s:%s' % (options.login, options.password)).strip()
        request.add_data(json.dumps(jdata))
        request.add_header("Authorization", "Basic %s" % base64string)
        request.add_header("Content-Type", "application/json")
        request.add_header("Accept", "application/json")
        request.get_method = lambda: 'POST'
        reply = opener.open(request)
    except urllib2.URLError, e:
        print "Error: cannot connect to the API: %s" % (e)
        print "Check your URL & try to login using the same user/pass via the WebUI and check the error!"
        print "error: " + e.read()
        print "url: " + url
        print "jdata: " + str(jdata)
        sys.exit(1)
    except Exception, e:
        print "FATAL Error - %s" % (e)
        sys.exit(2)


def delete_json(url):
    # Generic function to HTTP DELETE JSON from Satellite's API
    try:
        request = urllib2.Request(url)
        base64string = base64.encodestring('%s:%s' % (options.login, options.password)).strip()
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
        print "error: " + e.read()
        print "url: " + url
        sys.exit(1)
    except Exception, e:
        print "FATAL Error - %s" % (e)
        sys.exit(2)


def return_matching_domain_id(domain_name):
    # Given a domain, find its id
    myurl = "https://" + options.sat6_fqdn + ":" + API_PORT + "/api/v2/domains/?" + urlencode([('search', 'name=%s' % domain_name)])
    if options.verbose:
        print myurl
    domain = get_json(myurl)
    if len(domain['results']) == 1:
        domain_id = domain['results'][0]['id']
        return domain_id
    else:
        print_error("Could not find domain %s" % domain_name)
        sys.exit(2)



def return_matching_hg_id(hg_name):
    # Given a hostgroup name, find its id
    myurl = "https://" + options.sat6_fqdn + ":" + API_PORT + "/api/v2/hostgroups/?" + urlencode([('search', 'title=%s' % hg_name)])
    if options.verbose:
        print myurl
    hostgroup = get_json(myurl)
    if len(hostgroup['results']) == 1:
        hg_id = hostgroup['results'][0]['id']
        return hg_id
    else:
        print_error("Could not find hostgroup %s" % hg_name)
        sys.exit(2)


def return_matching_architecture_id(architecture_name):
    # Given an architecture name, find its id
    myurl = "https://" + options.sat6_fqdn + ":" + API_PORT + "/api/v2/architectures/?" + urlencode([('search', 'name=%s' % architecture_name)])
    if options.verbose:
        print myurl
    architecture = get_json(myurl)
    if len(architecture['results']) == 1:
        architecture_id = architecture['results'][0]['id']
        return architecture_id
    else:
        print_error("Could not find architecture %s" % architecture)
        sys.exit(2)


def return_matching_operatingsystem_id(operatingsystem_name):
    # Given an operatingsystem name, find its id
    myurl = "https://" + options.sat6_fqdn + ":" + API_PORT + "/api/v2/operatingsystems/?" + urlencode([('search', 'name=%s' % operatingsystem_name)])
    if options.verbose:
        print myurl
    operatingsystem = get_json(myurl)
    if len(operatingsystem['results']) == 1:
        operatingsystem_id = operatingsystem['results'][0]['id']
        return operatingsystem_id
    else:
        print_error("Could not find operatingsystem %s" % operatingsystem)
        sys.exit(2)


def return_puppetenv_for_hg(hg_id):
    myurl = "https://" + options.sat6_fqdn + ":" + API_PORT + "/api/v2/hostgroups/" + str(hg_id)
    hostgroup = get_json(myurl)
    if hostgroup['environment_name']:
        return hostgroup['environment_name']
    elif hostgroup['ancestry']:
        return return_puppetenv_for_hg(hostgroup['ancestry'])
    else:
        return 'production'


def return_matching_host_id(hostname):
    # Given a hostname (more precisely a puppet certname) find its id
    myurl = "https://" + options.sat6_fqdn + ":" + API_PORT + "/api/v2/hosts/" + hostname
    if options.verbose:
        print myurl
    host = get_json(myurl)
    host_id = host['id']
    return host_id


def return_matching_location(location):
    # Given a location, find its id
    myurl = "https://" + options.sat6_fqdn + ":" + API_PORT + "/api/v2/locations/?" + urlencode([('search', 'title=%s' % location)])
    if options.verbose:
        print myurl
    loc = get_json(myurl)
    if len(loc['results']) == 1:
        loc_id = loc['results'][0]['id']
        return loc_id
    else:
        print_error("Could not find location %s" % location)
        sys.exit(2)


def return_matching_org(organization):
    # Given an org, find its id.
    myurl = "https://" + options.sat6_fqdn + ":" + API_PORT + "/api/v2/organizations/"
    if options.verbose:
        print myurl
    organizations = get_json(myurl)
    for org in organizations['results']:
        if org['name'] == organization:
            org_id = org['id']
            return org_id
    print_error("Could not find organization %s" % organization)
    sys.exit(2)


def return_matching_org_label(organization):
    # Given an org name, find its label - required by subscription-manager
    myurl = "https://" + options.sat6_fqdn + ":" + API_PORT + "/katello/api/organizations/" + organization
    if options.verbose:
        print "myurl: " + myurl
    organization = get_json(myurl)
    org_label = organization['label']
    return org_label


def return_matching_host(fqdn):
    # Given an org, find its id.
    myurl = "https://" + options.sat6_fqdn + ":" + API_PORT + "/api/v2/hosts/?" + urlencode([('search', 'name=%s' % fqdn)])
    if options.verbose:
        print myurl
    hosts = get_json(myurl)
    if options.verbose:
        print json.dumps(hosts, sort_keys = False, indent = 2)
    if len(hosts['results']) == 1:
        host_id = hosts['results'][0]['id']
        return host_id
    elif len(hosts['results']) == 0:
        return None
    else:
        print_error("Found too many hosts with same name %s" % fqdn)
        sys.exit(2)


def create_host():
    myhgid = return_matching_hg_id(options.hostgroup)
    mylocid = return_matching_location(options.location)
    myorgid = return_matching_org(options.org)
    mydomainid = return_matching_domain_id(DOMAIN)
    architecture_id = return_matching_architecture_id(ARCHITECTURE)
    host_id = return_matching_host(FQDN)
    # create the starting json, to be filled below
    jsondata = json.loads('{"host": {"name": "%s","hostgroup_id": %s,"organization_id": %s,"location_id": %s,"mac":"%s", "domain_id":%s,"architecture_id":%s}}' % (HOSTNAME, myhgid, myorgid, mylocid, MAC, mydomainid, architecture_id))
    # optional parameters
    if options.operatingsystem is not None:
      operatingsystem_id = return_matching_operatingsystem_id(options.operatingsystem)
      jsondata['host']['operatingsystem_id'] = operatingsystem_id
    if not options.unmanaged:
        jsondata['host']['managed'] = 'true'
    else:
        jsondata['host']['managed'] = 'false'
    if options.verbose:
        print json.dumps(jsondata, sort_keys = False, indent = 2)
    myurl = "https://" + options.sat6_fqdn + ":" + API_PORT + "/api/v2/hosts/"
    if options.force and host_id is not None:
        delete_host(host_id)
    print_running("Calling Satellite API to create a host entry associated with the group, org & location")
    post_json(myurl, jsondata)
    print_success("Successfully created host %s" % FQDN)


def delete_host(host_id):
    myurl = "https://" + options.sat6_fqdn + ":" + API_PORT + "/api/v2/hosts/"
    print_running("Deleting host id %s for host %s" % (host_id, FQDN))
    delete_json("%s/%s" % (myurl, host_id))


def check_rhn_registration():
    return os.path.exists('/etc/sysconfig/rhn/systemid')


def get_api_port():
    configparser = SafeConfigParser()
    configparser.read('/etc/rhsm/rhsm.conf')
    return configparser.get('server', 'port')

print "Satellite 6 Bootstrap Script"
print "This script is designed to register new systems or to migrate an existing system to Red Hat Satellite 6"

if options.remove:
    API_PORT = get_api_port()
    host_id = return_matching_host(FQDN)
    if host_id is not None:
        delete_host(host_id)
    unregister_system()
    clean_katello_agent()
    if not options.no_puppet:
        clean_puppet()
elif check_rhn_registration():
    print_generic('This system is registered to RHN. Attempting to migrate via rhn-classic-migrate-to-rhsm')
    install_prereqs()
    get_bootstrap_rpm()
    API_PORT = get_api_port()
    create_host()
    migrate_systems(options.org, options.activationkey)
else:
    print_generic('This system is not registered to RHN. Attempting to register via subscription-manager')
    get_bootstrap_rpm()
    API_PORT = get_api_port()
    create_host()
    register_systems(options.org, options.activationkey, options.release)

if not options.remove:
    enable_sat_tools()
    install_katello_agent()
    if options.update:
        fully_update_the_box()

    if not options.no_puppet:
        if options.force:
            clean_puppet()
        install_puppet_agent()

    if options.removepkgs:
        remove_old_rhn_packages()
