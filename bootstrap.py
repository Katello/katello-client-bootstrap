#!/usr/bin/python
#
try:
    import json
except ImportError:
    import simplejson as json
import getpass
import urllib2
import base64
import sys
import commands
import platform
import socket
import os.path
import glob
from datetime import datetime
from optparse import OptionParser
from urllib import urlencode
from ConfigParser import SafeConfigParser


def get_architecture():
    # May not be safe for anything apart from 32/64 bit OS
    try:
        is_64bit = sys.maxsize > 2 ** 32
    except:
        is_64bit = platform.architecture()[0] == '64bit'
    if is_64bit:
        return "x86_64"
    else:
        return "x86"

FQDN = socket.getfqdn()
HOSTNAME = FQDN.split('.')[0]
DOMAIN = FQDN[FQDN.index('.')+1:]

MAC = None
try:
    import uuid
    mac1 = uuid.getnode()
    mac2 = uuid.getnode()
    if mac1 == mac2:
        MAC = ':'.join(("%012X" % mac1)[i:i+2] for i in range(0, 12, 2))
except ImportError:
    if os.path.exists('/sys/class/net/eth0/address'):
        address_files = ['/sys/class/net/eth0/address']
    else:
        address_files = glob.glob('/sys/class/net/*/address')
    for f in address_files:
        MAC = open(f).readline().strip().upper()
        if MAC != "00:00:00:00:00:00":
            break
if not MAC:
    MAC = "00:00:00:00:00:00"

API_PORT = "443"
ARCHITECTURE = get_architecture()
try:
    RELEASE = platform.linux_distribution()[1]
except AttributeError:
    RELEASE = platform.dist()[1]

parser = OptionParser()
parser.add_option("-s", "--server", dest="foreman_fqdn", help="FQDN of Foreman OR Capsule - omit https://", metavar="foreman_fqdn")
parser.add_option("-l", "--login", dest="login", default='admin', help="Login user for API Calls", metavar="LOGIN")
parser.add_option("-p", "--password", dest="password", help="Password for specified user. Will prompt if omitted", metavar="PASSWORD")
parser.add_option("--legacy-login", dest="legacy_login", default='admin', help="Login user for Satellite 5 API Calls", metavar="LOGIN")
parser.add_option("--legacy-password", dest="legacy_password", help="Password for specified Satellite 5 user. Will prompt if omitted", metavar="PASSWORD")
parser.add_option("--legacy-purge", dest="legacy_purge", action="store_true", help="Purge system from the Legacy environment (e.g. Sat5)")
parser.add_option("-a", "--activationkey", dest="activationkey", help="Activation Key to register the system", metavar="ACTIVATIONKEY")
parser.add_option("-P", "--skip-puppet", dest="no_puppet", action="store_true", default=False, help="Do not install Puppet")
parser.add_option("--skip-foreman", dest="no_foreman", action="store_true", default=False, help="Do not create a Foreman host. Implies --skip-puppet.")
parser.add_option("-g", "--hostgroup", dest="hostgroup", help="Label of the Hostgroup in Foreman that the host is to be associated with", metavar="HOSTGROUP")
parser.add_option("-L", "--location", dest="location", default='Default_Location', help="Label of the Location in Foreman that the host is to be associated with", metavar="LOCATION")
parser.add_option("-O", "--operatingsystem", dest="operatingsystem", default=None, help="Label of the Operating System in Foreman that the host is to be associated with", metavar="OPERATINGSYSTEM")
parser.add_option("--partitiontable", dest="partitiontable", default=None, help="Label of the Operating System in Foreman that the host is to be associated with", metavar="PARTITIONTABLE")
parser.add_option("-o", "--organization", dest="org", default='Default_Organization', help="Label of the Organization in Foreman that the host is to be associated with", metavar="ORG")
parser.add_option("-S", "--subscription-manager-args", dest="smargs", default="", help="Which additional arguments shall be passed to subscription-manager", metavar="ARGS")
parser.add_option("--rhn-migrate-args", dest="rhsmargs", default="", help="Which additional arguments shall be passed to rhn-migrate-classic-to-rhsm", metavar="ARGS")
parser.add_option("-u", "--update", dest="update", action="store_true", help="Fully Updates the System")
parser.add_option("-v", "--verbose", dest="verbose", action="store_true", help="Verbose output")
parser.add_option("-f", "--force", dest="force", action="store_true", help="Force registration (will erase old katello and puppet certs)")
parser.add_option("--remove", dest="remove", action="store_true", help="Instead of registring the machine to Foreman remove it")
parser.add_option("-r", "--release", dest="release", default=RELEASE, help="Specify release version")
parser.add_option("-R", "--remove-rhn-packages", dest="removepkgs", action="store_true", help="Remove old Red Hat Network Packages")
parser.add_option("--unmanaged", dest="unmanaged", action="store_true", help="Add the server as unmanaged. Useful to skip provisioning dependencies.")
(options, args) = parser.parse_args()

if not (options.foreman_fqdn and options.login and (options.remove or (options.org and options.activationkey and (options.no_foreman or (options.hostgroup and options.location))))):
    print "Must specify server, login, hostgroup, location, and organization options.  See usage:"
    parser.print_help()
    print "\nExample usage: ./bootstrap.py -l admin -s foreman.example.com -o Default_Organization -L Default_Location -g My_Hostgroup -a My_Activation_Key"
    sys.exit(1)

if not options.password:
    options.password = getpass.getpass("%s's password:" % options.login)

if options.no_foreman:
    options.no_puppet = True

if options.verbose:
    print "HOSTNAME - %s" % HOSTNAME
    print "DOMAIN - %s" % DOMAIN
    print "RELEASE - %s" % RELEASE
    print "MAC - %s" % MAC
    print "foreman_fqdn - %s" % options.foreman_fqdn
    print "LOGIN - %s" % options.login
    print "PASSWORD - %s" % options.password
    print "HOSTGROUP - %s" % options.hostgroup
    print "LOCATION - %s" % options.location
    print "OPERATINGSYSTEM - %s" % options.operatingsystem
    print "PARTITIONTABLE - %s" % options.partitiontable
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
    print_generic("Retrieving Client CA Certificate RPMs")
    exec_failexit("rpm -Uvh http://%s/pub/katello-ca-consumer-latest.noarch.rpm" % options.foreman_fqdn)


def migrate_systems(org_name, activationkey):
    org_label = return_matching_katello_key('organizations', 'name="%s"' % org_name, 'label', False)
    print_generic("Calling rhn-migrate-classic-to-rhsm")
    options.rhsmargs += " --destination-url=https://%s:%s/rhsm" % (options.foreman_fqdn, API_PORT)
    if options.legacy_purge:
        options.rhsmargs += " --legacy-user '%s' --legacy-password '%s'" % (options.legacy_login, options.legacy_password)
    else:
        options.rhsmargs += " --keep"
    if options.force:
        options.rhsmargs += " --force"
    exec_failexit("/usr/sbin/rhn-migrate-classic-to-rhsm --org %s --activation-key %s %s" % (org_label, activationkey, options.rhsmargs))
    exec_failexit("subscription-manager config --rhsm.baseurl=https://%s/pulp/repos" % options.foreman_fqdn)


def register_systems(org_name, activationkey, release):
    org_label = return_matching_katello_key('organizations', 'name="%s"' % org_name, 'label', False)
    print_generic("Calling subscription-manager")
    options.smargs += " --serverurl=https://%s:%s/rhsm --baseurl=https://%s/pulp/repos" % (options.foreman_fqdn, API_PORT, options.foreman_fqdn)
    if options.force:
        options.smargs += " --force"
    exec_failexit("/usr/sbin/subscription-manager register --org '%s' --name '%s' --activationkey '%s' %s" % (org_label, FQDN, activationkey, options.smargs))


def unregister_system():
    print_generic("Unregistering")
    exec_failexit("/usr/sbin/subscription-manager unregister")


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


def clean_environment():
    for key in ['LD_LIBRARY_PATH', 'LD_PRELOAD']:
        os.environ.pop(key, None)


def install_puppet_agent():
    puppet_env = return_puppetenv_for_hg(return_matching_foreman_key('hostgroups', 'title="%s"' % options.hostgroup, 'id', False))
    print_generic("Installing the Puppet Agent")
    exec_failexit("/usr/bin/yum -y install puppet")
    exec_failexit("/sbin/chkconfig puppet on")
    exec_failexit("/usr/bin/puppet config set server %s --section agent" % options.foreman_fqdn)
    exec_failexit("/usr/bin/puppet config set ca_server %s --section agent" % options.foreman_fqdn)
    exec_failexit("/usr/bin/puppet config set environment %s --section agent" % puppet_env)
    # Might need this for RHEL5
    # f = open("/etc/puppet/puppet.conf","a")
    # f.write("server=%s \n" % options.foreman_fqdn)
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
    # Generic function to HTTP GET JSON from Foreman's API
    try:
        request = urllib2.Request(url)
        if options.verbose:
            print "request: " + url
        base64string = base64.encodestring('%s:%s' % (options.login, options.password)).strip()
        request.add_header("Authorization", "Basic %s" % base64string)
        result = urllib2.urlopen(request)
        return json.load(result)
    except urllib2.HTTPError, e:
        if e.code == 401:
            print 'Error: user not authorized to perform this action. Check user/pass or permission assigned.'
            print "url: " + url
            sys.exit(1)
        if e.code == 422:
            print 'Error: Unprocessable entity to API. Check API syntax.'
            print "error: " + e.read()
            print "url: " + url
            sys.exit(1)
        raise e
    except urllib2.URLError, e:
        print "Error in API call: %s" % (e)
        print "Check your URL & try to login using the same user/pass via the WebUI and check the error!"
        print "error: " + e.read()
        print "url: " + url
        sys.exit(1)
    except Exception, e:
        print "FATAL Error - %s" % (e)
        sys.exit(2)


def post_json(url, jdata):
    # Generic function to HTTP PUT JSON to Foreman's API.
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
    except urllib2.HTTPError, e:
        if e.code == 401:
            print 'Error: user not authorized to perform this action. Check user/pass or permission assigned.'
            print "url: " + url
            sys.exit(1)
        if e.code == 422:
            print 'Error: Unprocessable entity to API. Check API syntax.'
            print "error: " + e.read()
            print "url: " + url
            sys.exit(1)
        raise e
    except urllib2.URLError, e:
        print "Error in API call: %s" % (e)
        print "Check your URL & try to login using the same user/pass via the WebUI and check the error!"
        print "error: " + e.read()
        print "url: " + url
        print "jdata: " + str(jdata)
        sys.exit(1)
    except Exception, e:
        print "FATAL Error - %s" % (e)
        sys.exit(2)


def delete_json(url):
    # Generic function to HTTP DELETE JSON from Foreman's API
    try:
        request = urllib2.Request(url)
        base64string = base64.encodestring('%s:%s' % (options.login, options.password)).strip()
        request.add_header("Authorization", "Basic %s" % base64string)
        request.get_method = lambda: 'DELETE'
        result = urllib2.urlopen(request)
        return json.load(result)
    except urllib2.HTTPError, e:
        if e.code == 401:
            print 'Error: user not authorized to perform this action. Check user/pass or permission assigned.'
            print "url: " + url
            sys.exit(1)
        if e.code == 422:
            print 'Error: Unprocessable entity to API. Check API syntax.'
            print "error: " + e.read()
            print "url: " + url
            sys.exit(1)
        if e.code != 404:
            raise e
    except urllib2.URLError, e:
        print "Error in API call: %s" % (e)
        print "Check your URL & try to login using the same user/pass via the WebUI and check the error!"
        print "error: " + e.read()
        print "url: " + url
        sys.exit(1)
    except Exception, e:
        print "FATAL Error - %s" % (e)
        sys.exit(2)


def return_matching_foreman_key(api_name, search_key, return_key, null_result_ok=False):
    return return_matching_key("/api/v2/" + api_name, search_key, return_key, null_result_ok)


def return_matching_katello_key(api_name, search_key, return_key, null_result_ok=False):
    return return_matching_key("/katello/api/" + api_name, search_key, return_key, null_result_ok)


# Search in API
# given a search key, return the ID
# api_path is the path in url for API name, search_key must contain also the key for search (name=, title=, ...)
# the search_key must be quoted in advance
def return_matching_key(api_path, search_key, return_key, null_result_ok=False):
    myurl = "https://" + options.foreman_fqdn + ":" + API_PORT + api_path + "/?" + urlencode([('search', '' + str(search_key))])
    if options.verbose:
        print myurl
    return_values = get_json(myurl)
    if options.verbose:
        print json.dumps(return_values, sort_keys=False, indent=2)
    result_len = len(return_values['results'])
    if result_len == 1:
        return_values_return_key = return_values['results'][0][return_key]
        return return_values_return_key
    elif result_len == 0 and null_result_ok is True:
        return None
    else:
        print_error("%d element in array for search key '%s' in API '%s'. Fatal error." % (result_len, search_key, api_path))
        sys.exit(2)


def return_puppetenv_for_hg(hg_id):
    myurl = "https://" + options.foreman_fqdn + ":" + API_PORT + "/api/v2/hostgroups/" + str(hg_id)
    hostgroup = get_json(myurl)
    if hostgroup['environment_name']:
        return hostgroup['environment_name']
    elif hostgroup['ancestry']:
        parent = hostgroup['ancestry'].split('/')[-1]
        return return_puppetenv_for_hg(parent)
    else:
        return 'production'


def create_host():
    myhgid = return_matching_foreman_key('hostgroups', 'title="%s"' % options.hostgroup, 'id', False)
    mylocid = return_matching_foreman_key('locations', 'title="%s"' % options.location, 'id', False)
    myorgid = return_matching_foreman_key('organizations', 'name="%s"' % options.org, 'id', False)
    mydomainid = return_matching_foreman_key('domains', 'name="%s"' % DOMAIN, 'id', False)
    architecture_id = return_matching_foreman_key('architectures', 'name="%s"' % ARCHITECTURE, 'id', False)
    host_id = return_matching_foreman_key('hosts', 'name="%s"' % FQDN, 'id', True)
    # create the starting json, to be filled below
    jsondata = json.loads('{"host": {"name": "%s","hostgroup_id": %s,"organization_id": %s,"location_id": %s,"mac":"%s", "domain_id":%s,"architecture_id":%s}}' % (HOSTNAME, myhgid, myorgid, mylocid, MAC, mydomainid, architecture_id))
    # optional parameters
    if options.operatingsystem is not None:
        operatingsystem_id = return_matching_foreman_key('operatingsystems', 'title="%s"' % options.operatingsystem, 'id', False)
        jsondata['host']['operatingsystem_id'] = operatingsystem_id
    if options.partitiontable is not None:
        partitiontable_id = return_matching_foreman_key('ptables', 'name="%s"' % options.partitiontable, 'id', False)
        jsondata['host']['ptable_id'] = partitiontable_id
    if not options.unmanaged:
        jsondata['host']['managed'] = 'true'
    else:
        jsondata['host']['managed'] = 'false'
    if options.verbose:
        print json.dumps(jsondata, sort_keys=False, indent=2)
    myurl = "https://" + options.foreman_fqdn + ":" + API_PORT + "/api/v2/hosts/"
    if options.force and host_id is not None:
        delete_host(host_id)
    print_running("Calling Foreman API to create a host entry associated with the group, org & location")
    post_json(myurl, jsondata)
    print_success("Successfully created host %s" % FQDN)


def delete_host(host_id):
    myurl = "https://" + options.foreman_fqdn + ":" + API_PORT + "/api/v2/hosts/"
    print_running("Deleting host id %s for host %s" % (host_id, FQDN))
    delete_json("%s/%s" % (myurl, host_id))


def disassociate_host(host_id):
    myurl = "https://" + options.foreman_fqdn + ":" + API_PORT + "/api/v2/hosts/" + str(host_id) + "/disassociate"
    print_running("Disassociating host id %s for host %s" % (host_id, FQDN))
    put_json(myurl)


def check_rhn_registration():
    if os.path.exists('/etc/sysconfig/rhn/systemid'):
        retcode = commands.getstatusoutput('rhn-channel -l')[0]
        return retcode == 0
    else:
        return False


def get_api_port():
    configparser = SafeConfigParser()
    configparser.read('/etc/rhsm/rhsm.conf')
    return configparser.get('server', 'port')

print "Foreman Bootstrap Script"
print "This script is designed to register new systems or to migrate an existing system to a Foreman server with Katello"

clean_environment()
if options.remove:
    API_PORT = get_api_port()
    host_id = return_matching_foreman_key('hosts', 'name="%s"' % FQDN, 'id', True)
    if host_id is not None:
        disassociate_host(host_id)
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
    if not options.no_foreman:
        create_host()
    migrate_systems(options.org, options.activationkey)
else:
    print_generic('This system is not registered to RHN. Attempting to register via subscription-manager')
    get_bootstrap_rpm()
    API_PORT = get_api_port()
    if not options.no_foreman:
        create_host()
    register_systems(options.org, options.activationkey, options.release)

if not options.remove:
    install_katello_agent()
    if options.update:
        fully_update_the_box()

    if not options.no_puppet:
        if options.force:
            clean_puppet()
        install_puppet_agent()

    if options.removepkgs:
        remove_old_rhn_packages()
