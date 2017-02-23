#!/usr/bin/python
"""
Script to register a new host to Foreman/Satellite
or move it from Satellite 5 to 6.

Use `pydoc ./bootstrap.py` to get the documentation.
Use `awk -F'# >' 'NF>1 {print $2}' ./bootstrap.py` to see the flow.
"""

import getpass
import urllib2
import base64
import sys
import commands
import platform
import socket
import os
import pwd
import glob
import shutil
import rpm
import rpmUtils.miscutils
import tempfile
from datetime import datetime
from optparse import OptionParser
from urllib import urlencode
from ConfigParser import SafeConfigParser


def get_architecture():
    """
    Helper function to get the architecture x86_64 vs. x86.
    """
    return os.uname()[4]


"""Colors to be used by the multiple `print_*` functions."""
error_colors = {
    'HEADER': '\033[95m',
    'OKBLUE': '\033[94m',
    'OKGREEN': '\033[92m',
    'WARNING': '\033[93m',
    'FAIL': '\033[91m',
    'ENDC': '\033[0m',
}


def print_error(msg):
    """Helper function to output an ERROR message."""
    print "[%sERROR%s], [%s], EXITING: [%s] failed to execute properly." % (error_colors['FAIL'], error_colors['ENDC'], datetime.now().strftime('%Y-%m-%d %H:%M:%S'), msg)


def print_warning(msg):
    """Helper function to output a WARNING message."""
    print "[%sWARNING%s], [%s], NON-FATAL: [%s] failed to execute properly." % (error_colors['WARNING'], error_colors['ENDC'], datetime.now().strftime('%Y-%m-%d %H:%M:%S'), msg)


def print_success(msg):
    """Helper function to output a SUCCESS message."""
    print "[%sSUCCESS%s], [%s], [%s], completed successfully." % (error_colors['OKGREEN'], error_colors['ENDC'], datetime.now().strftime('%Y-%m-%d %H:%M:%S'), msg)


def print_running(msg):
    """Helper function to output a RUNNING message."""
    print "[%sRUNNING%s], [%s], [%s] " % (error_colors['OKBLUE'], error_colors['ENDC'], datetime.now().strftime('%Y-%m-%d %H:%M:%S'), msg)


def print_generic(msg):
    """Helper function to output a NOTIFICATION message."""
    print "[NOTIFICATION], [%s], [%s] " % (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), msg)


def exec_failok(command):
    """Helper function to call a command with only warning if failing."""
    print_running(command)
    output = commands.getstatusoutput(command)
    retcode = output[0] >> 8
    if retcode != 0:
        print_warning(command)
    print output[1]
    print ""
    return retcode


def exec_failexit(command):
    """Helper function to call a command with error and exit if failing."""
    print_running(command)
    output = commands.getstatusoutput(command)
    retcode = output[0] >> 8
    if retcode != 0:
        print_error(command)
        print output[1]
        sys.exit(retcode)
    print output[1]
    print_success(command)
    print ""


def delete_file(filename):
    """Helper function to delete files."""
    if not os.path.exists(filename):
        print_generic("%s does not exist - not removing" % filename)
        return
    try:
        os.remove(filename)
        print_success("Removing %s" % filename)
    except OSError, e:
        print_generic("Error when removing %s - %s" % (filename, e.strerror))
        print_error("Removing %s" % filename)
        sys.exit(1)


def delete_directory(directoryname):
    """Helper function to delete directories."""
    if not os.path.exists(directoryname):
        print_generic("%s does not exist - not removing" % directoryname)
        return
    try:
        shutil.rmtree(directoryname)
        print_success("Removing %s" % directoryname)
    except OSError, e:
        print_generic("Error when removing %s - %s" % (directoryname, e.strerror))
        print_error("Removing %s" % directoryname)
        sys.exit(1)


def yum(command, pkgs=""):
    """Helper function to call a yum command on a list of packages."""
    exec_failexit("/usr/bin/yum -y %s %s" % (command, pkgs))


def check_migration_version():
    """
    Verify that the command 'subscription-manager-migration' isn't too old.
    """
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
    """
    Install subscription manager and its prerequisites.
    """
    print_generic("Installing subscription manager prerequisites")
    yum("remove", "subscription-manager-gnome")
    yum("install", "subscription-manager 'subscription-manager-migration-*'")
    if 'prereq-update' not in options.skip:
        yum("update", "yum openssl python")


def get_bootstrap_rpm():
    """
    Retrieve Client CA Certificate RPMs from the Satellite 6 server.
    Uses --insecure options to curl(1) if instructed to download via HTTPS
    If called with --force, calls clean_katello_agent().
    """
    if options.force:
        clean_katello_agent()
    if os.path.exists('/etc/rhsm/ca/katello-server-ca.pem'):
        print_generic("A Katello CA certificate is already installed. Assuming system is registered")
        print_generic("To override this behavior, run the script with the --force option. Exiting.")
        sys.exit(1)

    if options.download_method == "https":
        print_generic("Writing custom cURL configuration to allow download via HTTPS without certificate verification")
        curl_config_dir = tempfile.mkdtemp()
        curl_config = open(os.path.join(curl_config_dir, '.curlrc'), 'wb')
        curl_config.write("insecure")
        curl_config.close()
        os.environ["CURL_HOME"] = curl_config_dir
        print_generic("Retrieving Client CA Certificate RPMs")
        exec_failexit("rpm -Uvh https://%s/pub/katello-ca-consumer-latest.noarch.rpm" % options.foreman_fqdn)
        print_generic("Deleting cURL configuration")
        delete_directory(curl_config_dir)
        os.environ.pop("CURL_HOME", None)
    else:
        print_generic("Retrieving Client CA Certificate RPMs")
        exec_failexit("rpm -Uvh http://%s/pub/katello-ca-consumer-latest.noarch.rpm" % options.foreman_fqdn)


def disable_rhn_plugin():
    if os.path.exists('/etc/yum/pluginconf.d/rhnplugin.conf'):
        rhnpluginconfig = SafeConfigParser()
        rhnpluginconfig.read('/etc/yum/pluginconf.d/rhnplugin.conf')
        if rhnpluginconfig.get('main', 'enabled') == '1':
            print_generic("RHN yum plugin was enabled. Disabling...")
            rhnpluginconfig.set('main', 'enabled', '0')
            rhnpluginconfig.write(open('/etc/yum/pluginconf.d/rhnplugin.conf', 'w'))
    if os.path.exists('/etc/sysconfig/rhn/systemid'):
        os.rename('/etc/sysconfig/rhn/systemid', '/etc/sysconfig/rhn/systemid.bootstrap-bak')


def enable_rhsmcertd():
    """
    Enable and restart the rhsmcertd service
    """
    exec_failexit("/sbin/chkconfig rhsmcertd on")
    exec_failexit("/sbin/service rhsmcertd restart")


def migrate_systems(org_name, activationkey):
    """
    Call `rhn-migrate-classic-to-rhsm` to migrate the machine from Satellite
    5 to 6 using the organization name/label and the given activation key, and
    configure subscription manager with the baseurl of Satellite6's pulp.
    This allows the administrator to override the URL provided in the
    katello-ca-consumer-latest RPM, which is useful in scenarios where the
    Capsules/Servers are load-balanced or using subjectAltName certificates.
    If called with "--legacy-purge", uses "legacy-user" and "legacy-password"
    to remove the machine.
    Option "--force" is always passed so that `rhn-migrate-classic-to-rhsm`
    does not fail on channels which cannot be mapped either because they
    are cloned channels, custom channels, or do not exist in the destination.
    """
    if 'foreman' in options.skip:
        org_label = org_name
    else:
        org_label = return_matching_katello_key('organizations', 'name="%s"' % org_name, 'label', False)
    print_generic("Calling rhn-migrate-classic-to-rhsm")
    options.rhsmargs += " --force --destination-url=https://%s:%s/rhsm" % (options.foreman_fqdn, API_PORT)
    if options.legacy_purge:
        options.rhsmargs += " --legacy-user '%s' --legacy-password '%s'" % (options.legacy_login, options.legacy_password)
    else:
        options.rhsmargs += " --keep"
    exec_failexit("/usr/sbin/rhn-migrate-classic-to-rhsm --org %s --activation-key '%s' %s" % (org_label, activationkey, options.rhsmargs))
    exec_failexit("subscription-manager config --rhsm.baseurl=https://%s/pulp/repos" % options.foreman_fqdn)
    enable_rhsmcertd()

    # When rhn-migrate-classic-to-rhsm is called with --keep, it will leave the systemid
    # file intact, which might confuse the (not yet removed) yum-rhn-plugin.
    # Move the file to a backup name & disable the RHN plugin, so the user can still restore it if needed.
    disable_rhn_plugin()


def register_systems(org_name, activationkey, release):
    """
    Register the host to Satellite 6's organization using
    `subscription-manager` and the given activation key.
    Option "--force" is given further.
    """
    if 'foreman' in options.skip:
        org_label = org_name
    else:
        org_label = return_matching_katello_key('organizations', 'name="%s"' % org_name, 'label', False)
    print_generic("Calling subscription-manager")
    options.smargs += " --serverurl=https://%s:%s/rhsm --baseurl=https://%s/pulp/repos" % (options.foreman_fqdn, API_PORT, options.foreman_fqdn)
    if options.force:
        options.smargs += " --force"
    exec_failexit("/usr/sbin/subscription-manager register --org '%s' --name '%s' --activationkey '%s' %s" % (org_label, FQDN, activationkey, options.smargs))
    enable_rhsmcertd()


def unregister_system():
    """Unregister the host using `subscription-manager`."""
    print_generic("Unregistering")
    exec_failexit("/usr/sbin/subscription-manager unregister")


def clean_katello_agent():
    """Remove old Katello agent (aka Gofer) and certificate RPMs."""
    print_generic("Removing old Katello agent and certs")
    delete_file("/etc/rhsm/ca/katello-server-ca.pem")
    yum("erase", "'katello-ca-consumer-*' katello-agent gofer")


def install_katello_agent():
    """Install Katello agent (aka Gofer) and activate /start it."""
    print_generic("Installing the Katello agent")
    yum("install", "katello-agent")
    exec_failexit("/sbin/chkconfig goferd on")
    exec_failexit("/sbin/service goferd restart")


def clean_puppet():
    """Remove old Puppet Agent and its configuration"""
    print_generic("Cleaning old Puppet Agent")
    yum("erase", "puppet")
    delete_directory("/var/lib/puppet/")


def clean_environment():
    """
    Undefine `LD_LIBRARY_PATH` and `LD_PRELOAD` as many environments
    have it defined non-sensibly.
    """
    for key in ['LD_LIBRARY_PATH', 'LD_PRELOAD']:
        os.environ.pop(key, None)


def generate_katello_facts():
    """
    Write katello_facts file based on FQDN. Done after installation
    of katello-ca-consumer RPM in case the script is overriding the
    FQDN
    """
    print_generic("Writing FQDN katello-fact")
    katellofacts = open('/etc/rhsm/facts/katello.facts', 'w')
    katellofacts.write('{"network.hostname-override":"%s"}\n' % (FQDN))
    katellofacts.close()


def install_puppet_agent():
    """Install and configure, then enable and start the Puppet Agent"""
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


def remove_obsolete_packages():
    """Remove old RHN packages"""
    print_generic("Removing old RHN packages")
    yum("remove", "rhn-setup rhn-client-tools yum-rhn-plugin rhnsd rhn-check rhnlib spacewalk-abrt spacewalk-oscap osad 'rh-*-rhui-client'")


def fully_update_the_box():
    """Call `yum -y update` to upgrade the host."""
    print_generic("Fully Updating The Box")
    yum("update")


# curl https://satellite.example.com:9090/ssh/pubkey >> ~/.ssh/authorized_keys
# sort -u ~/.ssh/authorized_keys
def install_foreman_ssh_key():
    """
    Download and install the Satellite's SSH public key into the foreman user's
    authorized keys file, so that remote execution becomes possible.
    """
    userpw = pwd.getpwnam(options.remote_exec_user)
    foreman_ssh_dir = os.sep.join([userpw.pw_dir, '.ssh'])
    foreman_ssh_authfile = os.sep.join([foreman_ssh_dir, 'authorized_keys'])
    if not os.path.isdir(foreman_ssh_dir):
        os.mkdir(foreman_ssh_dir, 0700)
        os.chown(foreman_ssh_dir, userpw.pw_uid, userpw.pw_gid)
    try:
        foreman_ssh_key = urllib2.urlopen("https://%s:9090/ssh/pubkey" % options.foreman_fqdn).read()
    except urllib2.HTTPError, e:
        print_generic("The server was unable to fulfill the request. Error: %s - %s" % (e.code, e.reason))
        print_generic("Please ensure the Remote Execution feature is configured properly")
        print_warning("Installing Foreman SSH key")
        return
    except urllib2.URLError, e:
        print_generic("Could not reach the server. Error: %s" % e.reason)
        return
    if os.path.isfile(foreman_ssh_authfile):
        if foreman_ssh_key in open(foreman_ssh_authfile, 'r').read():
            print_generic("Foreman's SSH key is already present in %s" % foreman_ssh_authfile)
            return
    output = os.fdopen(os.open(foreman_ssh_authfile, os.O_WRONLY | os.O_CREAT, 0600), 'a')
    output.write(foreman_ssh_key)
    os.chown(foreman_ssh_authfile, userpw.pw_uid, userpw.pw_gid)
    print_generic("Foreman's SSH key was added to %s" % foreman_ssh_authfile)
    output.close()


class BetterHTTPErrorProcessor(urllib2.BaseHandler):
    """
    A substitute/supplement class to urllib2.HTTPErrorProcessor
    that doesn't raise exceptions on status codes 201,204,206
    """
    def http_error_201(self, request, response, code, msg, hdrs):
        return response

    def http_error_204(self, request, response, code, msg, hdrs):
        return response

    def http_error_206(self, request, response, code, msg, hdrs):
        return response


def call_api(url, data=None, method='GET'):
    """
    Helper function to place an API call returning JSON results and doing
    some error handling. Any error results in an exit.
    """
    try:
        request = urllib2.Request(url)
        if options.verbose:
            print 'url: %s' % url
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
    """Use `call_api` to place a "GET" REST API call."""
    return call_api(url)


def post_json(url, jdata):
    """Use `call_api` to place a "POST" REST API call."""
    return call_api(url, data=jdata, method='POST')


def delete_json(url):
    """Use `call_api` to place a "DELETE" REST API call."""
    return call_api(url, method='DELETE')


def put_json(url):
    """Use `call_api` to place a "PUT" REST API call."""
    return call_api(url, method='PUT')


def return_matching_foreman_key(api_name, search_key, return_key, null_result_ok=False):
    """
    Function uses `return_matching_key` to make an API call to Foreman.
    """
    return return_matching_key("/api/v2/" + api_name, search_key, return_key, null_result_ok)


def return_matching_katello_key(api_name, search_key, return_key, null_result_ok=False):
    """
    Function uses `return_matching_key` to make an API call to Katello.
    """
    return return_matching_key("/katello/api/" + api_name, search_key, return_key, null_result_ok)


def return_matching_key(api_path, search_key, return_key, null_result_ok=False):
    """
    Search in API given a search key, which must be unique, then returns the
    field given in "return_key" as ID.
    api_path is the path in url for API name, search_key must contain also
    the key for search (name=, title=, ...).
    The search_key must be quoted in advance.
    """
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
    """
    Return the Puppet environment of the given hostgroup ID, either directly
    or inherited through its hierarchy. If no environment is found,
    "production" is assumed.
    """
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
    """
    Call Foreman API to create a network domain associated with the given
    organization and location.
    """
    myurl = "https://" + options.foreman_fqdn + ":" + API_PORT + "/api/v2/domains"
    domid = return_matching_foreman_key('domains', 'name="%s"' % domain, 'id', True)
    if not domid:
        jsondata = json.loads('{"domain": {"name": "%s", "organization_ids": [%s], "location_ids": [%s]}}' % (domain, orgid, locid))
        print_running("Calling Foreman API to create domain %s associated with the org & location" % domain)
        post_json(myurl, jsondata)


def create_host():
    """
    Call Foreman API to create a host entry associated with the
    host group, organization & location, domain and architecture.
    """
    myhgid = return_matching_foreman_key('hostgroups', 'title="%s"' % options.hostgroup, 'id', False)
    if options.location:
        mylocid = return_matching_foreman_key('locations', 'title="%s"' % options.location, 'id', False)
    else:
        mylocid = None
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
    jsondata = json.loads('{"host": {"name": "%s","hostgroup_id": %s,"organization_id": %s, "mac":"%s","architecture_id":%s}}' % (HOSTNAME, myhgid, myorgid, MAC, architecture_id))
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
    if mylocid:
        jsondata['host']['location_id'] = mylocid
    if mydomainid:
        jsondata['host']['domain_id'] = mydomainid
    myurl = "https://" + options.foreman_fqdn + ":" + API_PORT + "/api/v2/hosts/"
    if options.force and host_id is not None:
        disassociate_host(host_id)
        delete_host(host_id)
    print_running("Calling Foreman API to create a host entry associated with the group & org")
    post_json(myurl, jsondata)
    print_success("Successfully created host %s" % FQDN)


def delete_host(host_id):
    """Call Foreman API to delete the current host."""
    myurl = "https://" + options.foreman_fqdn + ":" + API_PORT + "/api/v2/hosts/"
    print_running("Deleting host id %s for host %s" % (host_id, FQDN))
    delete_json("%s/%s" % (myurl, host_id))


def disassociate_host(host_id):
    """
    Call Foreman API to disassociate host from content host before deletion.
    """
    myurl = "https://" + options.foreman_fqdn + ":" + API_PORT + "/api/v2/hosts/" + str(host_id) + "/disassociate"
    print_running("Disassociating host id %s for host %s" % (host_id, FQDN))
    put_json(myurl)


def configure_subscription_manager():
    productidconfig = SafeConfigParser()
    productidconfig.read('/etc/yum/pluginconf.d/product-id.conf')
    if productidconfig.get('main', 'enabled') == '0':
        print_generic("Product-id yum plugin was disabled. Enabling...")
        productidconfig.set('main', 'enabled', '1')
        productidconfig.write(open('/etc/yum/pluginconf.d/product-id.conf', 'w'))

    submanconfig = SafeConfigParser()
    submanconfig.read('/etc/yum/pluginconf.d/subscription-manager.conf')
    if submanconfig.get('main', 'enabled') == '0':
        print_generic("subscription-manager yum plugin was disabled. Enabling...")
        submanconfig.set('main', 'enabled', '1')
        submanconfig.write(open('/etc/yum/pluginconf.d/subscription-manager.conf', 'w'))


def check_rhn_registration():
    """Helper function to check if host is registered to legacy RHN."""
    if os.path.exists('/etc/sysconfig/rhn/systemid'):
        retcode = commands.getstatusoutput('rhn-channel -l')[0] >> 8
        return retcode == 0
    else:
        return False


def enable_repos():
    """Enable necessary repositories using subscription-manager."""
    repostoenable = " ".join(['--enable=%s' % i for i in options.enablerepos.split(',')])
    print_running("Enabling repositories - %s" % options.enablerepos)
    exec_failok("subscription-manager repos %s" % repostoenable)


def get_api_port():
    """Helper function to get the server port from Subscription Manager."""
    configparser = SafeConfigParser()
    configparser.read('/etc/rhsm/rhsm.conf')
    return configparser.get('server', 'port')


print "Foreman Bootstrap Script"
print "This script is designed to register new systems or to migrate an existing system to a Foreman server with Katello"


def prepare_rhel5_migration():
    """
    Execute specific preparations steps for RHEL 5. Older releases of RHEL 5
    did not have a version of rhn-classic-migrate-to-rhsm which supported
    activation keys. This function allows those systems to get a proper
    product certificate.
    """
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
                cert = line.split(" ")[1]
                shutil.copy('/usr/share/rhsm/product/RHEL-5/' + cert.strip(),
                            '/etc/pki/product/69.pem')
                break

    # cleanup
    disable_rhn_plugin()


if __name__ == '__main__':

    # > Register our better HTTP processor as default opener for URLs.
    opener = urllib2.build_opener(BetterHTTPErrorProcessor)
    urllib2.install_opener(opener)

    # > Gather MAC Address.
    MAC = None
    try:
        import uuid
        mac1 = uuid.getnode()
        mac2 = uuid.getnode()
        if mac1 == mac2:
            MAC = ':'.join(("%012X" % mac1)[i:i + 2] for i in range(0, 12, 2))
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

    # > Gather API port (HTTPS), ARCHITECTURE and (OS) RELEASE
    API_PORT = "443"
    ARCHITECTURE = get_architecture()
    try:
        RELEASE = platform.linux_distribution()[1]
    except AttributeError:
        RELEASE = platform.dist()[1]

    SKIP_STEPS = ['foreman', 'puppet', 'migration', 'prereq-update', 'katello-agent', 'remove-obsolete-packages']

    # > Define and parse the options
    parser = OptionParser()
    parser.add_option("-s", "--server", dest="foreman_fqdn", help="FQDN of Foreman OR Capsule - omit https://", metavar="foreman_fqdn")
    parser.add_option("-l", "--login", dest="login", default='admin', help="Login user for API Calls", metavar="LOGIN")
    parser.add_option("-p", "--password", dest="password", help="Password for specified user. Will prompt if omitted", metavar="PASSWORD")
    parser.add_option("--fqdn", dest="fqdn", help="Set an explicit FQDN, overriding detected FQDN from socket.getfqdn(), currently detected as %default", metavar="FQDN", default=socket.getfqdn())
    parser.add_option("--legacy-login", dest="legacy_login", default='admin', help="Login user for Satellite 5 API Calls", metavar="LOGIN")
    parser.add_option("--legacy-password", dest="legacy_password", help="Password for specified Satellite 5 user. Will prompt if omitted", metavar="PASSWORD")
    parser.add_option("--legacy-purge", dest="legacy_purge", action="store_true", help="Purge system from the Legacy environment (e.g. Sat5)")
    parser.add_option("-a", "--activationkey", dest="activationkey", help="Activation Key to register the system", metavar="ACTIVATIONKEY")
    parser.add_option("-P", "--skip-puppet", dest="no_puppet", action="store_true", default=False, help="Do not install Puppet")
    parser.add_option("--skip-foreman", dest="no_foreman", action="store_true", default=False, help="Do not create a Foreman host. Implies --skip-puppet. When using --skip-foreman, you MUST pass the Organization's LABEL, not NAME")
    parser.add_option("-g", "--hostgroup", dest="hostgroup", help="Title of the Hostgroup in Foreman that the host is to be associated with", metavar="HOSTGROUP")
    parser.add_option("-L", "--location", dest="location", help="Title of the Location in Foreman that the host is to be associated with", metavar="LOCATION")
    parser.add_option("-O", "--operatingsystem", dest="operatingsystem", default=None, help="Title of the Operating System in Foreman that the host is to be associated with", metavar="OPERATINGSYSTEM")
    parser.add_option("--partitiontable", dest="partitiontable", default=None, help="Name of the Partition Table in Foreman that the host is to be associated with", metavar="PARTITIONTABLE")
    parser.add_option("-o", "--organization", dest="org", default='Default Organization', help="Name of the Organization in Foreman that the host is to be associated with", metavar="ORG")
    parser.add_option("-S", "--subscription-manager-args", dest="smargs", default="", help="Which additional arguments shall be passed to subscription-manager", metavar="ARGS")
    parser.add_option("--rhn-migrate-args", dest="rhsmargs", default="", help="Which additional arguments shall be passed to rhn-migrate-classic-to-rhsm", metavar="ARGS")
    parser.add_option("-u", "--update", dest="update", action="store_true", help="Fully Updates the System")
    parser.add_option("-v", "--verbose", dest="verbose", action="store_true", help="Verbose output")
    parser.add_option("-f", "--force", dest="force", action="store_true", help="Force registration (will erase old katello and puppet certs)")
    parser.add_option("--add-domain", dest="add_domain", action="store_true", help="Automatically add the clients domain to Foreman")
    parser.add_option("--remove", dest="remove", action="store_true", help="Instead of registring the machine to Foreman remove it")
    parser.add_option("-r", "--release", dest="release", default=RELEASE, help="Specify release version")
    parser.add_option("-R", "--remove-obsolete-packages", dest="removepkgs", action="store_true", help="Remove old Red Hat Network and RHUI Packages (default)", default=True)
    parser.add_option("--download-method", dest="download_method", default="http", help="Method to download katello-ca-consumer package (e.g. http or https)", metavar="DOWNLOADMETHOD", choices=['http', 'https'])
    parser.add_option("--no-remove-obsolete-packages", dest="removepkgs", action="store_false", help="Don't remove old Red Hat Network and RHUI Packages")
    parser.add_option("--unmanaged", dest="unmanaged", action="store_true", help="Add the server as unmanaged. Useful to skip provisioning dependencies.")
    parser.add_option("--rex", dest="remote_exec", action="store_true", help="Install Foreman's SSH key for remote execution.", default=False)
    parser.add_option("--rex-user", dest="remote_exec_user", default="root", help="Local user used by Foreman's remote execution feature.")
    parser.add_option("--enablerepos", dest="enablerepos", help="Repositories to be enabled via subscription-manager - comma separated", metavar="enablerepos")
    parser.add_option("--skip", dest="skip", action="append", help="Skip the listed steps (choices: %s)" % SKIP_STEPS, choices=SKIP_STEPS, default=[])
    (options, args) = parser.parse_args()

    if options.no_foreman:
        options.skip.append('foreman')
    if options.no_puppet:
        options.skip.append('puppet')
    if not options.removepkgs:
        options.skip.append('remove-obsolete-packages')

    # > Validate that the options make sense or exit with a message.
    # the logic is as follows:
    #   if mode = create:
    #     foreman_fqdn
    #     org
    #     activation_key
    #     if foreman:
    #       hostgroup
    #   else if mode = remove:
    #     if removing from foreman:
    #        foreman_fqdn
    if not ((options.remove and ('foreman' in options.skip or options.foreman_fqdn)) or
            (options.foreman_fqdn and options.org and options.activationkey and ('foreman' in options.skip or options.hostgroup))):
        if not options.remove:
            print "Must specify server, login, organization, hostgroup and activation key.  See usage:"
        else:
            print "Must specify server.  See usage:"
        parser.print_help()
        print "\nExample usage: ./bootstrap.py -l admin -s foreman.example.com -o 'Default Organization' -L 'Default Location' -g My_Hostgroup -a My_Activation_Key"
        sys.exit(1)

    # > Gather FQDN, HOSTNAME and DOMAIN using options.fqdn
    # > If socket.fqdn() returns an FQDN, derive HOSTNAME & DOMAIN using FQDN
    # > else, HOSTNAME isn't an FQDN
    # > if user passes --override-fqdn set FQDN, HOSTNAME and DOMAIN to the parameter that is given.
    FQDN = options.fqdn
    if FQDN.find(".") != -1:
        HOSTNAME = FQDN.split('.')[0]
        DOMAIN = FQDN[FQDN.index('.') + 1:]
    else:
        HOSTNAME = FQDN
        DOMAIN = None

    # > Exit if DOMAIN isn't set and Puppet must be installed (without force)
    if not DOMAIN and not (options.force or 'puppet' in options.skip):
        print "We could not determine the domain of this machine, most probably `hostname -f` does not return the FQDN."
        print "This can lead to Puppet missbehaviour and thus the script will terminate now."
        print "You can override this by passing one of the following"
        print "\t--force - to disable all checking"
        print "\t--skip-puppet - to omit installing the puppet agent"
        sys.exit(1)

    # > Ask for the password if not given as option
    if not options.password and 'foreman' not in options.skip:
        options.password = getpass.getpass("%s's password:" % options.login)

    # > If user wants to purge profile from RHN/Satellite 5, credentials are needed.
    if options.legacy_purge and not options.legacy_password:
        options.legacy_password = getpass.getpass("Legacy User %s's password:" % options.legacy_login)

    # > Puppet won't be installed if Foreman Host shall not be created
    if 'foreman' in options.skip:
        options.skip.append('puppet')

    options.skip = set(options.skip)

    # > Output all parameters if verbose.
    if options.verbose:
        print "HOSTNAME - %s" % HOSTNAME
        print "DOMAIN - %s" % DOMAIN
        print "FQDN - %s" % FQDN
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
        print "LEGACY LOGIN - %s" % options.legacy_login
        print "LEGACY PASSWORD - %s" % options.legacy_password
        print "DOWNLOAD METHOD - %s" % options.download_method
        print "SKIP - %s" % options.skip

    # > Exit if the user isn't root.
    # Done here to allow an unprivileged user to run the script to see
    # its various options.
    if os.getuid() != 0:
        print_error("This script requires root-level access")
        sys.exit(1)

    # > Try to import json or simplejson.
    # do it at this point in the code to have our custom print and exec
    # functions available
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

    # > Clean the environment from LD_... variables
    clean_environment()

    # > IF RHEL 5 and not removing, prepare the migration.
    if not options.remove and int(RELEASE[0]) == 5:
        prepare_rhel5_migration()

    if options.remove:
        # > IF remove, disassociate/delete host, unregister,
        # >            uninstall katello and optionally puppet agents
        API_PORT = get_api_port()
        unregister_system()
        if 'foreman' not in options.skip:
            host_id = return_matching_foreman_key('hosts', 'name="%s"' % FQDN, 'id', True)
            if host_id is not None:
                disassociate_host(host_id)
                delete_host(host_id)
        if 'katello-agent' not in options.skip:
            clean_katello_agent()
        if 'puppet' not in options.skip:
            clean_puppet()
    elif check_rhn_registration() and 'migration' not in options.skip:
        # > ELIF registered to RHN, install subscription-manager prerequs
        # >                         get CA RPM, optionally create host,
        # >                         migrate via rhn-classic-migrate-to-rhsm
        print_generic('This system is registered to RHN. Attempting to migrate via rhn-classic-migrate-to-rhsm')
        install_prereqs()
        check_migration_version()
        get_bootstrap_rpm()
        generate_katello_facts()
        API_PORT = get_api_port()
        if 'foreman' not in options.skip:
            create_host()
        configure_subscription_manager()
        migrate_systems(options.org, options.activationkey)
        if options.enablerepos:
            enable_repos()
    else:
        # > ELSE get CA RPM, optionally create host,
        # >      register via subscription-manager
        print_generic('This system is not registered to RHN. Attempting to register via subscription-manager')
        get_bootstrap_rpm()
        generate_katello_facts()
        API_PORT = get_api_port()
        if 'foreman' not in options.skip:
            create_host()
        configure_subscription_manager()
        register_systems(options.org, options.activationkey, options.release)
        if options.enablerepos:
            enable_repos()

    if not options.remove:
        # > IF not removing, install Katello agent, optionally update host,
        # >                  optionally clean and install Puppet agent
        # >                  optionally remove legacy RHN packages
        if 'katello-agent' not in options.skip:
            install_katello_agent()
        if options.update:
            fully_update_the_box()

        if 'puppet' not in options.skip:
            if options.force:
                clean_puppet()
            install_puppet_agent()

        if 'remove-obsolete-packages' not in options.skip:
            remove_obsolete_packages()

        if options.remote_exec:
            install_foreman_ssh_key()
