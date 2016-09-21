#!/usr/bin/python

import getpass
import urllib2
import base64
import sys
import commands
import platform
import socket
import os.path
import pwd
import glob
import shutil
import rpm
import rpmUtils.miscutils
import os.path
from datetime import datetime
from optparse import OptionParser
from urllib import urlencode
from ConfigParser import SafeConfigParser

def get_architecture():
    return os.uname()[4]

FQDN = socket.getfqdn()
if FQDN.find(".") != -1:
    HOSTNAME = FQDN.split('.')[0]
    DOMAIN = FQDN[FQDN.index('.')+1:]
else:
    HOSTNAME = FQDN
    DOMAIN = None

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
parser.add_option("-g", "--hostgroup", dest="hostgroup", help="Title of the Hostgroup in Foreman that the host is to be associated with", metavar="HOSTGROUP")
parser.add_option("-L", "--location", dest="location", default='Default Location', help="Title of the Location in Foreman that the host is to be associated with", metavar="LOCATION")
parser.add_option("-O", "--operatingsystem", dest="operatingsystem", default=None, help="Title of the Operating System in Foreman that the host is to be associated with", metavar="OPERATINGSYSTEM")
parser.add_option("--partitiontable", dest="partitiontable", default=None, help="Name of the Operating System in Foreman that the host is to be associated with", metavar="PARTITIONTABLE")
parser.add_option("-o", "--organization", dest="org", default='Default_Organization', help="Name of the Organization in Foreman that the host is to be associated with", metavar="ORG")
parser.add_option("-S", "--subscription-manager-args", dest="smargs", default="", help="Which additional arguments shall be passed to subscription-manager", metavar="ARGS")
parser.add_option("--rhn-migrate-args", dest="rhsmargs", default="", help="Which additional arguments shall be passed to rhn-migrate-classic-to-rhsm", metavar="ARGS")
parser.add_option("-u", "--update", dest="update", action="store_true", help="Fully Updates the System")
parser.add_option("-v", "--verbose", dest="verbose", action="store_true", help="Verbose output")
parser.add_option("-f", "--force", dest="force", action="store_true", help="Force registration (will erase old katello and puppet certs)")
parser.add_option("--add-domain", dest="add_domain", action="store_true", help="Automatically add the clients domain to Foreman")
parser.add_option("--remove", dest="remove", action="store_true", help="Instead of registring the machine to Foreman remove it")
parser.add_option("-r", "--release", dest="release", default=RELEASE, help="Specify release version")
parser.add_option("-R", "--remove-obsolete-packages", dest="removepkgs", action="store_true", help="Remove old Red Hat Network and RHUI Packages (default)", default=True)
parser.add_option("--no-remove-obsolete-packages", dest="removepkgs", action="store_false", help="Don't remove old Red Hat Network and RHUI Packages")
parser.add_option("--unmanaged", dest="unmanaged", action="store_true", help="Add the server as unmanaged. Useful to skip provisioning dependencies.")
parser.add_option("--rex", dest="remote_exec", action="store_true", help="Install Foreman's SSH key for remote execution.", default=False)
parser.add_option("--rex-user", dest="remote_exec_user", default="root", help="Local user used by Foreman's remote execution feature.")
parser.add_option("--pe-server", dest="pe_server_fqdn", help="FQDN of PE Server", metavar="pe_server_fqdn")
parser.add_option("--is-hypervisor", dest="hypervisor", action="store_true", help="Used if system is a RHEV/RHV hypervisor")
(options, args) = parser.parse_args()

if not (options.foreman_fqdn and options.login and (options.remove or (options.org and options.activationkey and (options.no_foreman or (options.hostgroup and options.location))))):
    print "Must specify server, login, organization, location, hostgroup, and activation key.  See usage:"
    parser.print_help()
    print "\nExample usage: ./bootstrap.py -l admin -s foreman.example.com -o 'Default Organization' -L 'Default Location' -g My_Hostgroup -a My_Activation_Key"
    sys.exit(1)

if not DOMAIN and not (options.force or options.no_puppet):
    print "We could not determine the domain of this machine, most probably `hostname -f` does not return the FQDN."
    print "This can lead to Puppet missbehaviour and thus the script will terminate now."
    print "You can override this by passing --force or --skip-puppet"
    sys.exit(1)

if not options.password and not options.no_foreman:
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
    print "PE Server - %s" % options.pe_server_fqdn

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
    return retcode


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

def yum(command, pkgs = ""):
    exec_failexit("/usr/bin/yum -y %s %s" % (command, pkgs))

def check_migration_version():
    required_version = rpmUtils.miscutils.stringToVersion('1.14.2')
    err = "subscription-manager-migration not found"

    ts = rpm.TransactionSet()
    mi = ts.dbMatch('name', 'subscription-manager-migration')
    for h in mi:
        if rpmUtils.miscutils.compareEVR(rpmUtils.miscutils.stringToVersion(h['evr']), required_version) < 0:
            err = "%s-%s is too old" % (h['name'], h['evr'])
        else:
            err = None

    if err:
       print_error(err)
       sys.exit(1)


def install_prereqs():
    print_generic("Installing subscription manager prerequisites")
    yum("remove", "subscription-manager-gnome")
    yum("install", "subscription-manager subscription-manager-migration-*")
    yum("update", "yum openssl")


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
    
    
def enable_satellite_tools():
    print_generic("Enabling satellite-tools repository for Puppet and Katello agents")
    exec_failexit("subscription-manager repos --enable=rhel-*-satellite-tools-*-rpms")    


def clean_katello_agent():
    print_generic("Removing old Katello agent and certs")
    yum("erase", "katello-ca-consumer-* katello-agent gofer")


def install_katello_agent():
    print_generic("Installing the Katello agent")
    yum("install", "katello-agent")
    exec_failexit("/sbin/chkconfig goferd on")
    exec_failexit("/sbin/service goferd restart")


def clean_puppet():
    print_generic("Cleaning old Puppet Agent")
    yum("erase", "puppet")
    exec_failexit("rm -rf /var/lib/puppet/")
    if os.path.isfile('/etc/yum.repos.d/pe_repo.repo.bak'):
        print_generic("Restoring local PE repo")
        exec_failexit("mv /etc/yum.repos.d/pe_repo.repo{.bak,}")



def clean_environment():
    for key in ['LD_LIBRARY_PATH', 'LD_PRELOAD']:
        os.environ.pop(key, None)


def install_puppet_agent():
    puppet_env = return_puppetenv_for_hg(return_matching_foreman_key('hostgroups', 'title="%s"' % options.hostgroup, 'id', False))
    print_generic("Installing the Puppet Agent")
    yum("install", "puppet")
    exec_failexit("/sbin/chkconfig puppet on")
    puppet_conf = open('/etc/puppet/puppet.conf', 'wb')
    puppet_conf.write("""
[main]
vardir = /var/lib/puppet
logdir = /var/log/puppet
rundir = /var/run/puppet
ssldir = $vardir/ssl

[agent]
pluginsync      = true
report          = true
ignoreschedules = true
daemon          = false
ca_server       = %s
certname        = %s
environment     = %s
server          = %s
""" % (options.foreman_fqdn, FQDN, puppet_env, options.foreman_fqdn))
    puppet_conf.close()
    print_generic("Running Puppet in noop mode to generate SSL certs")
    print_generic("Visit the UI and approve this certificate via Infrastructure->Capsules")
    print_generic("if auto-signing is disabled")
    exec_failexit("/usr/bin/puppet agent --test --noop --tags no_such_tag --waitforcert 10")
    exec_failexit("/sbin/service puppet restart")


def install_pe_agent(org_name):
    org_label = return_matching_katello_key('organizations', 'name="%s"' % org_name, 'label', False)
    if os.path.isfile('/etc/yum.repos.d/pe_repo.repo'):
        exec_failexit("mv /etc/yum.repos.d/pe_repo.repo{,.bak}")
    exec_failexit("subscription-manager attach --pool=$(subscription-manager list --available --matches='Puppet Enterprise' --pool-only)" )
    exec_failexit("subscription-manager repos --disable=*-pe-*")
    exec_failexit("subscription-manager repos --enable=%s_Puppet_Enterprise_$(uname -r | cut -d. -f6)-pe-$(uname -r | cut -d. -f7)" % ( org_label ))
    print_generic("Installing the PE Agent")
    yum("install", "pe-agent")
    exec_failexit("/sbin/chkconfig pe-puppet on")
    exec_failexit("/usr/local/bin/puppet agent -t --server %s || true" % (options.pe_server_fqdn))
    exec_failexit("/sbin/service pe-puppet restart")


def remove_obsolete_packages():
    print_generic("Removing old RHN packages")
    yum("remove", "rhn-setup rhn-client-tools yum-rhn-plugin rhnsd rhn-check rhnlib spacewalk-abrt spacewalk-oscap osad rh-*-rhui-client")

def fully_update_the_box():
    print_generic("Fully Updating The Box")
    yum("update")


# curl https://satellite.example.com:9090/ssh/pubkey >> ~/.ssh/authorized_keys
# sort -u ~/.ssh/authorized_keys
def install_foreman_ssh_key():
    userpw = pwd.getpwnam(options.remote_exec_user)
    foreman_ssh_dir = os.sep.join([userpw.pw_dir,'.ssh'])
    foreman_ssh_authfile = os.sep.join([foreman_ssh_dir,'authorized_keys'])
    if not os.path.isdir(foreman_ssh_dir):
        os.mkdir(foreman_ssh_dir, 0700)
        os.chown(foreman_ssh_dir, userpw.pw_uid, userpw.pw_gid)
    try:
        foreman_ssh_key = urllib2.urlopen("https://%s:9090/ssh/pubkey" % options.foreman_fqdn).read()
    except HTTPError as e:
        print_generic("The server was unable to fulfill the request. Error: %s" % e.code)
    except URLError as e:
        print_generic("Could not reach the server. Error: %s" % e.reason)
        return 
    if os.path.isfile(foreman_ssh_authfile):
        if foreman_ssh_key in open(foreman_ssh_authfile, 'r').read():
            print_generic("Foreman's SSH key is already present in %s" % foreman_ssh_authfile)
            return 
    with os.fdopen(os.open(foreman_ssh_authfile, os.O_WRONLY | os.O_CREAT, 0600), 'a') as output:
        output.write(foreman_ssh_key)
        os.chown(foreman_ssh_authfile, userpw.pw_uid, userpw.pw_gid)
        print_generic("Foreman's SSH key was added to %s" % foreman_ssh_authfile)

def install_virt_who():
    print_generic("Installing virt-who")
    yum("install", "virt-who")
    exec_failexit("/sbin/chkconfig virt-who on")
    exec_failexit("/bin/mv /etc/sysconfig/virt-who{,.bak}")
    virt_who_conf = open('/etc/sysconfig/virt-who', 'wb')
    virt_who_conf.write("""
VIRTWHO_DEBUG=0
VIRTWHO_SATELLITE6=1
VIRTWHO_LIBVIRT=1
""")
    virt_who_conf.close()
    exec_failexit("/bin/virt-who --one-shot")
    exec_failexit("/sbin/service virt-who start")

# a substitute/supplement to urllib2.HTTPErrorProcessor
# that doesn't raise exceptions on status codes 201,204,206
class BetterHTTPErrorProcessor(urllib2.BaseHandler):
    def http_error_201(self, request, response, code, msg, hdrs):
        return response
    def http_error_204(self, request, response, code, msg, hdrs):
        return response
    def http_error_206(self, request, response, code, msg, hdrs):
        return response
opener = urllib2.build_opener(BetterHTTPErrorProcessor)
urllib2.install_opener(opener)

def call_api(url, data=None, method='GET'):
    try:
        request = urllib2.Request(url)
        if options.verbose:
            print 'error: %s - url: %s' % [e, url]
            print 'method: %s' % method
            print 'data: %s' % json.dumps(data, sort_keys=False, indent=2)
        base64string = base64.encodestring('%s:%s' % (options.login, options.password)).strip()
        request.add_header("Authorization", "Basic %s" % base64string)
        request.add_header("Content-Type", "application/json")
        request.add_header("Accept", "application/json")
        if data:
           request.add_data(json.dumps(data))
        request.get_method = lambda: method
        result = urllib2.urlopen(request)
        jsonresult = json.load(result)
        if options.verbose:
            print 'result: %s' % json.dumps(jsonresult, sort_keys=False, indent=2)
        return jsonresult
    except urllib2.URLError, e:
        print 'An error occured: %s' % e
        print 'url: %s' % url
        if isinstance(e, urllib2.HTTPError):
            print 'code: %s' % e.code
        if data:
            print 'data: %s' % json.dumps(data, sort_keys=False, indent=2)
        try:
            jsonerr = json.load(e)
            print 'error: %s' % json.dumps(jsonerr, sort_keys=False, indent=2)
        except:
            print 'error: %s' % e
        sys.exit(1)
    except Exception, e:
        print "FATAL Error - %s" % (e)
        sys.exit(2)


def get_json(url):
    return call_api(url)


def post_json(url, jdata):
    return call_api(url, data=jdata, method='POST')


def delete_json(url):
    return call_api(url, method='DELETE')


def put_json(url):
    return call_api(url, method='PUT')


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
    return_values = get_json(myurl)
    result_len = len(return_values['results'])
    if result_len == 1:
        return_values_return_key = return_values['results'][0][return_key]
        return return_values_return_key
    elif result_len == 0 and null_result_ok is True:
        return None
    else:
        print_error("%d element in array for search key '%s' in API '%s'. Please note that all searches are case-sensitive. Fatal error." % (result_len, search_key, api_path))
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

def create_domain(domain, orgid, locid):
    myurl = "https://" + options.foreman_fqdn + ":" + API_PORT + "/api/v2/domains"
    domid = return_matching_foreman_key('domains', 'name="%s"' % domain, 'id', True)
    if not domid:
        jsondata = json.loads('{"domain": {"name": "%s", "organization_ids": [%s], "location_ids": [%s]}}' % (domain, orgid, locid))
        print_running("Calling Foreman API to create domain %s associated with the org & location" % domain)
        post_json(myurl, jsondata)

def create_host():
    myhgid = return_matching_foreman_key('hostgroups', 'title="%s"' % options.hostgroup, 'id', False)
    mylocid = return_matching_foreman_key('locations', 'title="%s"' % options.location, 'id', False)
    myorgid = return_matching_foreman_key('organizations', 'name="%s"' % options.org, 'id', False)
    if DOMAIN:
        if options.add_domain:
            create_domain(DOMAIN, myorgid, mylocid)

        mydomainid = return_matching_foreman_key('domains', 'name="%s"' % DOMAIN, 'id', True)
        if not mydomainid: 
            print_generic("Domain %s doesn't exist in Foreman, consider using the --add-domain option." % DOMAIN)
            sys.exit(2)
    else:
        mydomainid = None
    architecture_id = return_matching_foreman_key('architectures', 'name="%s"' % ARCHITECTURE, 'id', False)
    host_id = return_matching_foreman_key('hosts', 'name="%s"' % FQDN, 'id', True)
    # create the starting json, to be filled below
    jsondata = json.loads('{"host": {"name": "%s","hostgroup_id": %s,"organization_id": %s,"location_id": %s,"mac":"%s","architecture_id":%s}}' % (HOSTNAME, myhgid, myorgid, mylocid, MAC, architecture_id))
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
    if mydomainid:
        jsondata['host']['domain_id'] = mydomainid
    myurl = "https://" + options.foreman_fqdn + ":" + API_PORT + "/api/v2/hosts/"
    if options.force and host_id is not None:
        disassociate_host(host_id)
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


def prepare_rhel5_migration():
    install_prereqs()

    # only do the certificate magic if 69.pem is not present
    # and we have active channels
    if check_rhn_registration() and not os.path.exists('/etc/pki/product/69.pem'):
        _LIBPATH = "/usr/share/rhsm"
        # add to the path if need be
        if _LIBPATH not in sys.path:
            sys.path.append(_LIBPATH)
        from subscription_manager.migrate import migrate

        class MEOptions:
            force = True

        me = migrate.MigrationEngine()
        me.options = MEOptions()
        subscribed_channels = me.get_subscribed_channels_list()
        me.print_banner(("System is currently subscribed to these RHNClassic Channels:"))
        for channel in subscribed_channels:
            print channel
        me.check_for_conflicting_channels(subscribed_channels)
        me.deploy_prod_certificates(subscribed_channels)
        me.clean_up(subscribed_channels)

    # at this point we should have at least 69.pem available, but lets
    # doublecheck and copy it manually if not
    if not os.path.exists('/etc/pki/product/'):
        os.mkdir("/etc/pki/product/")
    mapping_file = "/usr/share/rhsm/product/RHEL-5/channel-cert-mapping.txt"
    if not os.path.exists('/etc/pki/product/69.pem') and os.path.exists(mapping_file):
        for line in open(mapping_file):
            if line.startswith('rhel-%s-server-5' % ARCHITECTURE):
                cert=line.split(" ")[1]
                shutil.copy('/usr/share/rhsm/product/RHEL-5/'+cert.strip(), '/etc/pki/product/69.pem')
                break

    # cleanup
    if os.path.exists('/etc/sysconfig/rhn/systemid'):
        os.remove('/etc/sysconfig/rhn/systemid')

# Add check for root user. Done here to allow an unprivileged user to run the script
# to see its various options. 
if os.getuid() != 0:
    print_error("This script requires root-level access")
    sys.exit(1)

# try to import json or simplejson
# do it at this point in the code to have our custom print and exec functions available
try:
    import json
except ImportError:
    try:
        import simplejson as json
    except ImportError:
        print_warning("Could neither import json nor simplejson, will try to install simplejson and re-import")
        yum("install", "python-simplejson")
        try:
            import simplejson as json
        except ImportError:
            print_error("Could not install python-simplejson")
            sys.exit(1)


clean_environment()

if not options.remove and int(RELEASE[0]) == 5:
    prepare_rhel5_migration()

if options.remove:
    API_PORT = get_api_port()
    unregister_system()
    host_id = return_matching_foreman_key('hosts', 'name="%s"' % FQDN, 'id', True)
    if host_id is not None:
        disassociate_host(host_id)
        delete_host(host_id)
    clean_katello_agent()
    if not options.no_puppet:
        clean_puppet()
elif check_rhn_registration():
    print_generic('This system is registered to RHN. Attempting to migrate via rhn-classic-migrate-to-rhsm')
    install_prereqs()
    check_migration_version()
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
    enable_satellite_tools()
    install_katello_agent()
    if options.update:
        fully_update_the_box()

    if not options.no_puppet:
        if not options.pe_server_fqdn:
            if options.force:
                clean_puppet()
            install_puppet_agent()

    if not options.no_puppet:
        if options.pe_server_fqdn:
            if options.force:
                clean_puppet()
            install_pe_agent(options.org)

    if options.removepkgs:
        remove_obsolete_packages()

    if options.remote_exec:
        install_foreman_ssh_key()
        
    if options.hypervisor:
        install_virt_who()

