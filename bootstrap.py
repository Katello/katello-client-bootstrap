#!/usr/bin/python
"""
Script to register a new host to Foreman/Satellite
or move it from Satellite 5 to 6.

Use `pydoc ./bootstrap.py` to get the documentation.
Use `awk -F'# >' 'NF>1 {print $2}' ./bootstrap.py` to see the flow.
Use `/usr/libexec/platform-python bootstrap.py` on RHEL8
"""

import getpass
try:
    # pylint:disable=invalid-name
    import urllib2
    from urllib import urlencode
    urllib_urlopen = urllib2.urlopen
    urllib_urlerror = urllib2.URLError
    urllib_httperror = urllib2.HTTPError
    urllib_basehandler = urllib2.BaseHandler
    urllib_request = urllib2.Request
    urllib_build_opener = urllib2.build_opener
    urllib_install_opener = urllib2.install_opener
except ImportError:
    # pylint:disable=invalid-name,no-member
    import urllib
    import urllib.request
    import urllib.error
    from urllib.parse import urlencode
    urllib_urlopen = urllib.request.urlopen
    urllib_urlerror = urllib.error.URLError
    urllib_httperror = urllib.error.HTTPError
    urllib_basehandler = urllib.request.BaseHandler
    urllib_request = urllib.request.Request
    urllib_build_opener = urllib.request.build_opener
    urllib_install_opener = urllib.request.install_opener
import base64
import sys
try:
    from commands import getstatusoutput
    NEED_STATUS_SHIFT = True
except ImportError:
    from subprocess import getstatusoutput
    NEED_STATUS_SHIFT = False
import platform
import socket
import os
import pwd
import glob
import shutil
import tempfile
from datetime import datetime
from optparse import OptionParser
try:
    from ConfigParser import SafeConfigParser
except ImportError:
    from configparser import ConfigParser as SafeConfigParser
try:
    import yum  # pylint:disable=import-error
    USE_YUM = True
except ImportError:
    import dnf  # pylint:disable=import-error
    USE_YUM = False
import rpm  # pylint:disable=import-error


VERSION = '1.7.5'

# Python 2.4 only supports octal numbers by prefixing '0'
# Python 3 only support octal numbers by prefixing '0o'
# Therefore use the decimal notation for file permissions
OWNER_ONLY_DIR = 448  # octal: 700
OWNER_ONLY_FILE = 384  # octal: 600


def get_architecture():
    """
    Helper function to get the architecture x86_64 vs. x86.
    """
    return os.uname()[4]


ERROR_COLORS = {
    """Colors to be used by the multiple `print_*` functions."""
    'HEADER': '\033[95m',
    'OKBLUE': '\033[94m',
    'OKGREEN': '\033[92m',
    'WARNING': '\033[93m',
    'FAIL': '\033[91m',
    'ENDC': '\033[0m',
}

SUBSCRIPTION_MANAGER_SERVER_TIMEOUT_VERSION = '1.18.2'
SUBSCRIPTION_MANAGER_MIGRATION_MINIMAL_VERSION = '1.14.2'
SUBSCRIPTION_MANAGER_MIGRATION_REMOVE_PKGS_VERSION = '1.18.2'


def filter_string(string):
    """Helper function to filter out passwords from strings"""
    if options.password:
        string = string.replace(options.password, '******')
    if options.legacy_password:
        string = string.replace(options.legacy_password, '******')
    return string


def print_error(msg):
    """Helper function to output an ERROR message."""
    print_message(color_string('ERROR', 'FAIL'), 'EXITING: [%s] failed to execute properly.' % msg)


def print_warning(msg):
    """Helper function to output a WARNING message."""
    print_message(color_string('WARNING', 'WARNING'), 'NON-FATAL: [%s] failed to execute properly.' % msg)


def print_success(msg):
    """Helper function to output a SUCCESS message."""
    print_message(color_string('SUCCESS', 'OKGREEN'), '[%s], completed successfully.' % msg)


def print_running(msg):
    """Helper function to output a RUNNING message."""
    print_message(color_string('RUNNING', 'OKBLUE'), '[%s]' % msg)


def print_generic(msg):
    """Helper function to output a NOTIFICATION message."""
    print_message('NOTIFICATION', '[%s]' % msg)


def print_message(prefix, msg):
    """Helper function to output a message with a prefix"""
    print("[%s], [%s], %s" % (prefix, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), msg))


def color_string(msg, color):
    """Helper function to add ANSII colors to a message"""
    return '%s%s%s' % (ERROR_COLORS[color], msg, ERROR_COLORS['ENDC'])


def exec_failok(command):
    """Helper function to call a command with only warning if failing."""
    return exec_command(command, True)


def exec_failexit(command):
    """Helper function to call a command with error and exit if failing."""
    return exec_command(command, False)


def exec_command(command, failok=False):
    """Helper function to call a command and handle errors and output."""
    filtered_command = filter_string(command)
    print_running(filtered_command)
    retcode, output = getstatusoutput(command)
    if NEED_STATUS_SHIFT:
        retcode = os.WEXITSTATUS(retcode)
    print(output)
    if retcode != 0:
        if failok:
            print_warning(filtered_command)
        else:
            print_error(filtered_command)
            sys.exit(retcode)
    else:
        print_success(filtered_command)
    return retcode


def delete_file(filename):
    """Helper function to delete files."""
    if not os.path.exists(filename):
        print_generic("%s does not exist - not removing" % filename)
        return
    try:
        os.remove(filename)
        print_success("Removing %s" % filename)
    except OSError:
        exception = sys.exc_info()[1]
        print_generic("Error when removing %s - %s" % (filename, exception.strerror))
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
    except OSError:
        exception = sys.exc_info()[1]
        print_generic("Error when removing %s - %s" % (directoryname, exception.strerror))
        print_error("Removing %s" % directoryname)
        sys.exit(1)


def call_yum(command, params="", failonerror=True):
    """
    Helper function to call a yum command on a list of packages.
    pass failonerror = False to make yum commands non-fatal
    """
    exec_command("/usr/bin/yum -y %s %s" % (command, params), not failonerror)


def check_migration_version(required_version):
    """
    Verify that the command 'subscription-manager-migration' isn't too old.
    """
    status, err = check_package_version('subscription-manager-migration', required_version)

    return (status, err)


def check_subman_version(required_version):
    """
    Verify that the command 'subscription-manager' isn't too old.
    """
    status, _ = check_package_version('subscription-manager', required_version)

    return status


def check_package_version(package_name, package_version):
    """
    Verify that the version of a package
    """
    required_version = ('0', package_version, '1')
    err = "%s not found" % package_name

    transaction_set = rpm.TransactionSet()
    db_result = transaction_set.dbMatch('name', package_name)
    for package in db_result:
        p_name = package['name'].decode('ascii')
        p_version = package['version'].decode('ascii')
        if rpm.labelCompare(('0', p_version, '1'), required_version) < 0:
            err = "%s %s is too old" % (p_name, p_version)
        else:
            err = None

    return (err is None, err)


def setup_yum_repo(url, gpg_key):
    """
    Configures a yum repository at /etc/yum.repos.d/katello-client-bootstrap-deps.repo
    """
    submanrepoconfig = SafeConfigParser()
    submanrepoconfig.add_section('kt-bootstrap')
    submanrepoconfig.set('kt-bootstrap', 'name', 'Subscription-manager dependencies for katello-client-bootstrap')
    submanrepoconfig.set('kt-bootstrap', 'baseurl', url)
    submanrepoconfig.set('kt-bootstrap', 'enabled', '1')
    submanrepoconfig.set('kt-bootstrap', 'gpgcheck', '1')
    submanrepoconfig.set('kt-bootstrap', 'gpgkey', gpg_key)
    submanrepoconfig.write(open('/etc/yum.repos.d/katello-client-bootstrap-deps.repo', 'w'))
    print_generic('Building yum metadata cache. This may take a few minutes')
    call_yum('makecache')


def install_prereqs():
    """
    Install subscription manager and its prerequisites.
    If subscription-manager is installed already, check to see if we are migrating. If yes, install subscription-manager-migration.
    Else if subscription-manager and subscription-manager-migration are available in a configured repo, install them both.
    Otherwise, exit and inform user that we cannot proceed
    """
    print_generic("Checking subscription manager prerequisites")
    if options.deps_repository_url:
        print_generic("Enabling %s as a repository for dependency RPMs" % options.deps_repository_url)
        setup_yum_repo(options.deps_repository_url, options.deps_repository_gpg_key)
    if USE_YUM:
        yum_base = yum.YumBase()
        pkg_list = yum_base.doPackageLists(patterns=['subscription-manager'])
        subman_installed = pkg_list.installed
        subman_available = pkg_list.available
    else:
        dnf_base = dnf.Base()
        dnf_base.fill_sack()
        pkg_list = dnf_base.sack.query().filter(name='subscription-manager')
        subman_installed = pkg_list.installed().run()
        subman_available = pkg_list.available().run()
    call_yum("remove", "subscription-manager-gnome", False)
    if subman_installed:
        if check_rhn_registration() and 'migration' not in options.skip:
            print_generic("installing subscription-manager-migration")
            call_yum("install", "'subscription-manager-migration-*'", False)
        print_generic("subscription-manager is installed already. Attempting update")
        call_yum("update", "subscription-manager 'subscription-manager-migration-*'", False)
    elif subman_available:
        print_generic("subscription-manager NOT installed. Installing.")
        call_yum("install", "subscription-manager 'subscription-manager-migration-*'")
    else:
        print_error("Cannot find subscription-manager in any configured repository. Consider using the --deps-repository-url switch to specify a repository with the subscription-manager RPMs")
        sys.exit(1)
    if 'prereq-update' not in options.skip:
        call_yum("update", "yum openssl python", False)
    if options.deps_repository_url:
        delete_file('/etc/yum.repos.d/katello-client-bootstrap-deps.repo')


def is_fips():
    """
    Checks to see if the system is FIPS enabled.
    """
    try:
        fips_file = open("/proc/sys/crypto/fips_enabled", "r")
        fips_status = fips_file.read(1)
    except IOError:
        fips_status = "0"
    return fips_status == "1"


def get_rhsm_proxy():
    """
    Return the proxy server settings from /etc/rhsm/rhsm.conf as dictionary proxy_config.
    """
    rhsmconfig = SafeConfigParser()
    rhsmconfig.read('/etc/rhsm/rhsm.conf')
    proxy_options = [option for option in rhsmconfig.options('server') if option.startswith('proxy')]
    proxy_config = {}
    for option in proxy_options:
        proxy_config[option] = rhsmconfig.get('server', option)
    return proxy_config


def set_rhsm_proxy(proxy_config):
    """
    Set proxy server settings in /etc/rhsm/rhsm.conf from dictionary saved_proxy_config.
    """
    rhsmconfig = SafeConfigParser()
    rhsmconfig.read('/etc/rhsm/rhsm.conf')
    for option in proxy_config.keys():
        rhsmconfig.set('server', option, proxy_config[option])
    rhsmconfig.write(open('/etc/rhsm/rhsm.conf', 'w'))


def get_bootstrap_rpm(clean=False, unreg=True):
    """
    Retrieve Client CA Certificate RPMs from the Satellite 6 server.
    Uses --insecure options to curl(1) if instructed to download via HTTPS
    This function is usually called with clean=options.force, which ensures
    clean_katello_agent() is called if --force is specified. You can optionally
    pass unreg=False to bypass unregistering a system (e.g. when moving between
    capsules.
    """
    if clean:
        clean_katello_agent()
    if os.path.exists('/etc/rhsm/ca/katello-server-ca.pem'):
        print_generic("A Katello CA certificate is already installed. Assuming system is registered.")
        print_generic("If you want to move the system to a different Content Proxy in the same setup, please use --new-capsule.")
        print_generic("If you want to remove the old host record and all data associated with it, please use --force.")
        print_generic("Exiting.")
        sys.exit(1)
    if os.path.exists('/etc/pki/consumer/cert.pem') and unreg:
        print_generic('System appears to be registered via another entitlement server. Attempting unregister')
        unregister_system()
    if options.download_method == "https":
        print_generic("Writing custom cURL configuration to allow download via HTTPS without certificate verification")
        curl_config_dir = tempfile.mkdtemp()
        curl_config = open(os.path.join(curl_config_dir, '.curlrc'), 'w')
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
    """
    Disable the RHN plugin for Yum
    """
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
    enable_service("rhsmcertd")
    exec_service("rhsmcertd", "restart")


def is_registered():
    """
    Check if all required certificates are in place (i.e. a system is
    registered to begin with) before we start changing things
    """
    return (os.path.exists('/etc/rhsm/ca/katello-server-ca.pem') and
            os.path.exists('/etc/pki/consumer/cert.pem'))


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
        if options.removepkgs and check_migration_version(SUBSCRIPTION_MANAGER_MIGRATION_REMOVE_PKGS_VERSION)[0]:
            options.rhsmargs += " --remove-rhn-packages"
    else:
        options.rhsmargs += " --keep"
    if check_subman_version(SUBSCRIPTION_MANAGER_SERVER_TIMEOUT_VERSION):
        exec_failok("/usr/sbin/subscription-manager config --server.server_timeout=%s" % options.timeout)
    exec_command("/usr/sbin/rhn-migrate-classic-to-rhsm --org %s --activation-key '%s' %s" % (org_label, activationkey, options.rhsmargs), options.ignore_registration_failures)
    exec_command("subscription-manager config --rhsm.baseurl=https://%s/pulp/repos" % options.foreman_fqdn, options.ignore_registration_failures)
    if options.release:
        exec_failexit("subscription-manager release --set %s" % options.release)
    enable_rhsmcertd()

    # When rhn-migrate-classic-to-rhsm is called with --keep, it will leave the systemid
    # file intact, which might confuse the (not yet removed) yum-rhn-plugin.
    # Move the file to a backup name & disable the RHN plugin, so the user can still restore it if needed.
    disable_rhn_plugin()


def register_systems(org_name, activationkey):
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
    if options.release:
        options.smargs += " --release %s" % options.release
    if check_subman_version(SUBSCRIPTION_MANAGER_SERVER_TIMEOUT_VERSION):
        exec_failok("/usr/sbin/subscription-manager config --server.server_timeout=%s" % options.timeout)
    exec_command("/usr/sbin/subscription-manager register --org '%s' --name '%s' --activationkey '%s' %s" % (org_label, FQDN, activationkey, options.smargs), options.ignore_registration_failures)
    enable_rhsmcertd()


def unregister_system():
    """Unregister the host using `subscription-manager`."""
    print_generic("Cleaning old yum metadata")
    call_yum("clean", "metadata dbcache", False)
    print_generic("Unregistering")
    exec_failok("/usr/sbin/subscription-manager unregister")
    exec_failok("/usr/sbin/subscription-manager clean")


def clean_katello_agent():
    """Remove old Katello agent (aka Gofer) and certificate RPMs."""
    print_generic("Removing old Katello agent and certs")
    call_yum("remove", "'katello-ca-consumer-*' katello-agent gofer katello-host-tools katello-host-tools-fact-plugin", False)
    delete_file("/etc/rhsm/ca/katello-server-ca.pem")


def install_katello_agent():
    """Install Katello agent (aka Gofer) and activate /start it."""
    print_generic("Installing the Katello agent")
    call_yum("install", "katello-agent")
    enable_service("goferd")
    exec_service("goferd", "restart")


def install_katello_host_tools():
    """Install Katello Host Tools"""
    print_generic("Installing the Katello Host Tools")
    call_yum("install", "katello-host-tools")


def clean_puppet():
    """Remove old Puppet Agent and its configuration"""
    print_generic("Cleaning old Puppet Agent")
    call_yum("remove", "puppet-agent", False)
    delete_directory("/var/lib/puppet/")
    delete_directory("/opt/puppetlabs/puppet/cache")
    delete_directory("/etc/puppetlabs/puppet/ssl")


def clean_environment():
    """
    Undefine `GEM_PATH`, `LD_LIBRARY_PATH` and `LD_PRELOAD` as many environments
    have it defined non-sensibly.
    """
    for key in ['GEM_PATH', 'LD_LIBRARY_PATH', 'LD_PRELOAD']:
        os.environ.pop(key, None)


def generate_katello_facts():
    """
    Write katello_facts file based on FQDN. Done after installation
    of katello-ca-consumer RPM in case the script is overriding the
    FQDN. Place the location if the location option is included
    """

    print_generic("Writing FQDN katello-fact")
    katellofacts = open('/etc/rhsm/facts/katello.facts', 'w')
    katellofacts.write('{"network.hostname-override":"%s"}\n' % (FQDN))
    katellofacts.close()

    if options.location and 'foreman' in options.skip:
        print_generic("Writing LOCATION RHSM fact")
        locationfacts = open('/etc/rhsm/facts/location.facts', 'w')
        locationfacts.write('{"foreman_location":"%s"}\n' % (options.location))
        locationfacts.close()


def install_puppet_agent():
    """Install and configure, then enable and start the Puppet Agent"""
    puppet_env = return_puppetenv_for_hg(return_matching_foreman_key('hostgroups', 'title="%s"' % options.hostgroup, 'id', False))
    print_generic("Installing the Puppet Agent")
    call_yum("install", "puppet-agent")
    enable_service("puppet")

    puppet_conf_file = '/etc/puppetlabs/puppet/puppet.conf'
    main_section = """[main]
vardir = /opt/puppetlabs/puppet/cache
logdir = /var/log/puppetlabs/puppet
rundir = /var/run/puppetlabs
ssldir = /etc/puppetlabs/puppet/ssl
"""
    if is_fips():
        main_section += "digest_algorithm = sha256"
        print_generic("System is in FIPS mode. Setting digest_algorithm to SHA256 in puppet.conf")
    puppet_conf = open(puppet_conf_file, 'w')

    # set puppet.conf certname to lowercase FQDN, as capitalized characters would
    # get translated anyway generating our certificate
    # * https://puppet.com/docs/puppet/3.8/configuration.html#certname
    # * https://puppet.com/docs/puppet/4.10/configuration.html#certname
    # * https://puppet.com/docs/puppet/5.5/configuration.html#certname
    # other links mentioning capitalized characters related issues:
    # * https://grokbase.com/t/gg/puppet-users/152s27374y/forcing-a-variable-to-be-lower-case
    # * https://groups.google.com/forum/#!topic/puppet-users/vRAu092ppzs
    puppet_conf.write("""
%s
[agent]
pluginsync      = true
report          = true
ignoreschedules = true
daemon          = false
ca_server       = %s
certname        = %s
environment     = %s
server          = %s
""" % (main_section, options.puppet_ca_server, FQDN.lower(), puppet_env, options.puppet_server))
    if options.puppet_ca_port:
        puppet_conf.write("""ca_port         = %s
""" % (options.puppet_ca_port))
    if options.puppet_noop:
        puppet_conf.write("""noop            = true
""")
    puppet_conf.close()
    noop_puppet_signing_run()
    if 'puppet-enable' not in options.skip:
        enable_service("puppet")
        exec_service("puppet", "restart")


def noop_puppet_signing_run():
    """
    Execute Puppet with --noop to generate and sign certs
    """
    print_generic("Running Puppet in noop mode to generate SSL certs")
    print_generic("Visit the UI and approve this certificate via Infrastructure->Capsules")
    print_generic("if auto-signing is disabled")
    exec_failexit("/opt/puppetlabs/puppet/bin/puppet agent --test --noop --tags no_such_tag --waitforcert 10")
    if 'puppet-enable' not in options.skip:
        enable_service("puppet")
        exec_service("puppet", "restart")


def remove_obsolete_packages():
    """Remove old RHN packages"""
    print_generic("Removing old RHN packages")
    call_yum("remove", "rhn-setup rhn-client-tools yum-rhn-plugin rhnsd rhn-check rhnlib spacewalk-abrt spacewalk-oscap osad 'rh-*-rhui-client' 'candlepin-cert-consumer-*'", False)


def fully_update_the_box():
    """Call `yum -y update` to upgrade the host."""
    print_generic("Fully Updating The Box")
    call_yum("update")


# curl https://satellite.example.com:9090/ssh/pubkey >> ~/.ssh/authorized_keys
# sort -u ~/.ssh/authorized_keys
def install_ssh_key_from_url(remote_url):
    """
    Download and install Foreman's SSH public key.
    """
    print_generic("Fetching Remote Execution SSH key from %s" % remote_url)
    try:
        if sys.version_info >= (2, 6):
            foreman_ssh_key_req = urllib_urlopen(remote_url, timeout=options.timeout)
        else:
            foreman_ssh_key_req = urllib_urlopen(remote_url)
        foreman_ssh_key = foreman_ssh_key_req.read()
        if sys.version_info >= (3, 0):
            foreman_ssh_key = foreman_ssh_key.decode(foreman_ssh_key_req.headers.get_content_charset('utf-8'))
    except urllib_httperror:
        exception = sys.exc_info()[1]
        print_generic("The server was unable to fulfill the request. Error: %s - %s" % (exception.code, exception.reason))
        print_generic("Please ensure the Remote Execution feature is configured properly")
        print_warning("Installing Foreman SSH key")
        return
    except urllib_urlerror:
        exception = sys.exc_info()[1]
        print_generic("Could not reach the server. Error: %s" % exception.reason)
        return
    install_ssh_key_from_string(foreman_ssh_key)


def install_ssh_key_from_api():
    """
    Download and install all Foreman's SSH public keys.
    """
    print_generic("Fetching Remote Execution SSH keys from the Foreman API")
    url = "https://" + options.foreman_fqdn + ":" + str(API_PORT) + "/api/v2/smart_proxies/"
    smart_proxies = get_json(url)
    for smart_proxy in smart_proxies['results']:
        if 'remote_execution_pubkey' in smart_proxy:
            install_ssh_key_from_string(smart_proxy['remote_execution_pubkey'])


def install_ssh_key_from_string(foreman_ssh_key):
    """
    Install Foreman's SSH public key into the foreman user's
    authorized keys file location, so that remote execution becomes possible.
    If not set default is ~/.ssh/authorized_keys
    """
    print_generic("Installing Remote Execution SSH key for user %s" % options.remote_exec_user)
    foreman_ssh_key = foreman_ssh_key.strip()
    userpw = pwd.getpwnam(options.remote_exec_user)
    if not options.remote_exec_authpath:
        options.remote_exec_authpath = os.path.join(userpw.pw_dir, '.ssh', 'authorized_keys')
        foreman_ssh_dir = os.path.join(userpw.pw_dir, '.ssh')
        if not os.path.isdir(foreman_ssh_dir):
            os.mkdir(foreman_ssh_dir, OWNER_ONLY_DIR)
            os.chown(foreman_ssh_dir, userpw.pw_uid, userpw.pw_gid)
    elif os.path.exists(options.remote_exec_authpath) and not os.path.isfile(options.remote_exec_authpath):
        print_error("Foreman's SSH key not installed. You need to provide a full path to an authorized_keys file, you provided: '%s'" % options.remote_exec_authpath)
        return
    if os.path.isfile(options.remote_exec_authpath):
        if foreman_ssh_key in open(options.remote_exec_authpath, 'r').read():
            print_generic("Foreman's SSH key already present in %s" % options.remote_exec_authpath)
            return
    output = os.fdopen(os.open(options.remote_exec_authpath, os.O_WRONLY | os.O_CREAT, OWNER_ONLY_FILE), 'a')
    output.write("\n")
    output.write(foreman_ssh_key)
    os.chown(options.remote_exec_authpath, userpw.pw_uid, userpw.pw_gid)
    print_generic("Foreman's SSH key added to %s" % options.remote_exec_authpath)
    output.close()


class BetterHTTPErrorProcessor(urllib_basehandler):
    """
    A substitute/supplement class to HTTPErrorProcessor
    that doesn't raise exceptions on status codes 201,204,206
    """
    # pylint:disable=unused-argument,no-self-use,no-init

    def http_error_201(self, request, response, code, msg, hdrs):
        """Handle HTTP 201"""
        return response

    def http_error_204(self, request, response, code, msg, hdrs):
        """Handle HTTP 204"""
        return response

    def http_error_206(self, request, response, code, msg, hdrs):
        """Handle HTTP 206"""
        return response


def call_api(url, data=None, method='GET'):
    """
    Helper function to place an API call returning JSON results and doing
    some error handling. Any error results in an exit.
    """
    try:
        request = urllib_request(url)
        if options.verbose:
            print('url: %s' % url)
            print('method: %s' % method)
            print('data: %s' % json.dumps(data, sort_keys=False, indent=2))
        auth_string = '%s:%s' % (options.login, options.password)
        base64string = base64.b64encode(auth_string.encode('utf-8')).decode().strip()
        request.add_header("Authorization", "Basic %s" % base64string)
        request.add_header("Content-Type", "application/json")
        request.add_header("Accept", "application/json")
        if data:
            if hasattr(request, 'add_data'):
                request.add_data(json.dumps(data))
            else:
                request.data = json.dumps(data).encode()
        request.get_method = lambda: method
        if sys.version_info >= (2, 6):
            result = urllib_urlopen(request, timeout=options.timeout)
        else:
            result = urllib_urlopen(request)
        jsonresult = json.load(result)
        if options.verbose:
            print('result: %s' % json.dumps(jsonresult, sort_keys=False, indent=2))
        return jsonresult
    except urllib_urlerror:
        exception = sys.exc_info()[1]
        print('An error occurred: %s' % exception)
        print('url: %s' % url)
        if isinstance(exception, urllib_httperror):
            print('code: %s' % exception.code)  # pylint:disable=no-member
        if data:
            print('data: %s' % json.dumps(data, sort_keys=False, indent=2))
        try:
            jsonerr = json.load(exception)
            print('error: %s' % json.dumps(jsonerr, sort_keys=False, indent=2))
        except:  # noqa: E722, pylint:disable=bare-except
            print('error: %s' % exception)
        sys.exit(1)
    except Exception:  # pylint:disable=broad-except
        exception = sys.exc_info()[1]
        print("FATAL Error - %s" % (exception))
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


def put_json(url, jdata=None):
    """Use `call_api` to place a "PUT" REST API call."""
    return call_api(url, data=jdata, method='PUT')


def update_host_capsule_mapping(attribute, capsule_id, host_id):
    """
    Update the host entry to point a feature to a new proxy
    """
    url = "https://" + options.foreman_fqdn + ":" + str(API_PORT) + "/api/v2/hosts/" + str(host_id)
    if attribute == 'content_source_id':
        jdata = {"host": {"content_facet_attributes": {"content_source_id": capsule_id}, "content_source_id": capsule_id}}
    else:
        jdata = {"host": {attribute: capsule_id}}
    return put_json(url, jdata)


def get_capsule_features(capsule_id):
    """
    Fetch all features available on a proxy
    """
    url = "https://" + options.foreman_fqdn + ":" + str(API_PORT) + "/katello/api/capsules/%s" % str(capsule_id)
    return [feature['name'] for feature in get_json(url)['features']]


def update_host_config(attribute, value, host_id):
    """
    Update a host config
    """
    attribute_id = return_matching_foreman_key(attribute + 's', 'title="%s"' % value, 'id', False)
    json_key = attribute + "_id"
    jdata = {"host": {json_key: attribute_id}}
    put_json("https://" + options.foreman_fqdn + ":" + API_PORT + "/api/hosts/%s" % host_id, jdata)


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
    elif result_len == 0 and null_result_ok is True:
        return_values_return_key = None
    else:
        print_error("%d element in array for search key '%s' in API '%s'. Please note that all searches are case-sensitive." % (result_len, search_key, api_path))
        print_error("Please also ensure that the user has permissions to view the searched objects. Fatal error.")
        sys.exit(2)

    return return_values_return_key


def return_puppetenv_for_hg(hg_id):
    """
    Return the Puppet environment of the given hostgroup ID, either directly
    or inherited through its hierarchy. If no environment is found,
    "production" is assumed.
    """
    myurl = "https://" + options.foreman_fqdn + ":" + API_PORT + "/api/v2/hostgroups/" + str(hg_id)
    hostgroup = get_json(myurl)
    environment_name = 'production'
    if hostgroup['environment_name']:
        environment_name = hostgroup['environment_name']
    elif hostgroup['ancestry']:
        parent = hostgroup['ancestry'].split('/')[-1]
        environment_name = return_puppetenv_for_hg(parent)
    return environment_name


def create_domain(domain, orgid, locid):
    """
    Call Foreman API to create a network domain associated with the given
    organization and location.
    """
    myurl = "https://" + options.foreman_fqdn + ":" + API_PORT + "/api/v2/domains"
    domid = return_matching_foreman_key('domains', 'name="%s"' % domain, 'id', True)
    if not domid:
        jsondata = {"domain": {"name": domain, "organization_ids": [orgid], "location_ids": [locid]}}
        print_running("Calling Foreman API to create domain %s associated with the org & location" % domain)
        post_json(myurl, jsondata)


def create_host():

    # pylint:disable=too-many-branches
    # pylint:disable=too-many-statements

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
        domain_available_search = 'name="%s"&organization_id=%s' % (DOMAIN, myorgid)
        if mylocid:
            domain_available_search += '&location_id=%s' % (mylocid)
        mydomainid = return_matching_foreman_key('domains', domain_available_search, 'id', True)
        if not mydomainid:
            print_generic("Domain %s exists in Foreman, but is not assigned to the requested Organization or Location." % DOMAIN)
            sys.exit(2)
    else:
        mydomainid = None
    if options.force_content_source:
        my_content_src_id = return_matching_foreman_key(api_name='smart_proxies', search_key='name="%s"' % options.foreman_fqdn, return_key='id', null_result_ok=True)
        if my_content_src_id is None:
            print_warning("You requested to set the content source to %s, but we could not find such a Smart Proxy configured. The content source WILL NOT be updated!" % (options.foreman_fqdn,))
    else:
        my_content_src_id = None
    architecture_id = return_matching_foreman_key('architectures', 'name="%s"' % ARCHITECTURE, 'id', False)
    host_id = return_matching_foreman_key('hosts', 'name="%s"' % FQDN, 'id', True)
    # create the starting json, to be filled below
    jsondata = {"host": {"name": HOSTNAME, "hostgroup_id": myhgid, "organization_id": myorgid, "mac": MAC, "architecture_id": architecture_id, "build": False}}
    # optional parameters
    if my_content_src_id:
        jsondata['host']['content_facet_attributes'] = {'content_source_id': my_content_src_id}
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
    if options.ip:
        jsondata['host']['ip'] = options.ip
    if options.comment:
        jsondata['host']['comment'] = options.comment
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
    """
    Configure subscription-manager plugins in Yum
    """
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
        retcode = getstatusoutput('rhn-channel -l')[0]
        if NEED_STATUS_SHIFT:
            retcode = os.WEXITSTATUS(retcode)
        return retcode == 0
    return False


def enable_repos():
    """Enable necessary repositories using subscription-manager."""
    repostoenable = " ".join(['--enable=%s' % i for i in options.enablerepos.split(',')])
    print_running("Enabling repositories - %s" % options.enablerepos)
    exec_failok("subscription-manager repos %s" % repostoenable)


def install_packages():
    """Install user-provided packages"""
    packages = options.install_packages.replace(',', " ")
    print_running("Installing the following packages %s" % packages)
    call_yum("install", packages, False)


def get_api_port():
    """Helper function to get the server port from Subscription Manager."""
    configparser = SafeConfigParser()
    configparser.read('/etc/rhsm/rhsm.conf')
    try:
        return configparser.get('server', 'port')
    except:  # noqa: E722, pylint:disable=bare-except
        return "443"


def check_rpm_installed():
    """Check if the machine already has Katello/Spacewalk RPMs installed"""
    rpm_sat = ['katello', 'foreman-proxy-content', 'katello-capsule', 'spacewalk-proxy-common', 'spacewalk-backend']
    transaction_set = rpm.TransactionSet()
    db_results = transaction_set.dbMatch()
    for package in db_results:
        package_name = package['name'].decode('ascii')
        if package_name in rpm_sat:
            print_error("%s RPM found. bootstrap.py should not be used on a Katello/Spacewalk/Satellite host." % (package_name))
            sys.exit(1)


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
        # pylint:disable=W,C,R
        _LIBPATH = "/usr/share/rhsm"
        # add to the path if need be
        if _LIBPATH not in sys.path:
            sys.path.append(_LIBPATH)
        from subscription_manager.migrate import migrate  # pylint:disable=import-error

        class MEOptions:
            force = True

        me = migrate.MigrationEngine()
        me.options = MEOptions()
        subscribed_channels = me.get_subscribed_channels_list()
        me.print_banner(("System is currently subscribed to these RHNClassic Channels:"))
        for channel in subscribed_channels:
            print(channel)
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


def enable_service(service, failonerror=True):
    """
    Helper function to enable a service using proper init system.
    pass failonerror = False to make init system's commands non-fatal
    """
    if os.path.exists("/run/systemd"):
        exec_command("/usr/bin/systemctl enable %s" % (service), not failonerror)
    else:
        exec_command("/sbin/chkconfig %s on" % (service), not failonerror)


def exec_service(service, command, failonerror=True):
    """
    Helper function to call a service command using proper init system.
    Available command values = start, stop, restart
    pass failonerror = False to make init system's commands non-fatal
    """
    if os.path.exists("/run/systemd"):
        exec_command("/usr/bin/systemctl %s %s" % (command, service), not failonerror)
    else:
        exec_command("/sbin/service %s %s" % (service, command), not failonerror)


if __name__ == '__main__':

    # pylint:disable=invalid-name

    print("Foreman Bootstrap Script")
    print("This script is designed to register new systems or to migrate an existing system to a Foreman server with Katello")

    # > Register our better HTTP processor as default opener for URLs.
    opener = urllib_build_opener(BetterHTTPErrorProcessor)
    urllib_install_opener(opener)

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
        # pylint:disable=deprecated-method
        RELEASE = platform.linux_distribution()[1]
    except AttributeError:
        # pylint:disable=deprecated-method
        RELEASE = platform.dist()[1]
    IS_EL5 = int(RELEASE[0]) == 5
    IS_EL8 = int(RELEASE[0]) == 8
    if not IS_EL5:
        DEFAULT_DOWNLOAD_METHOD = 'https'
    else:
        DEFAULT_DOWNLOAD_METHOD = 'http'

    SKIP_STEPS = ['foreman', 'puppet', 'migration', 'prereq-update', 'katello-agent', 'remove-obsolete-packages', 'puppet-enable', 'katello-host-tools']

    # > Define and parse the options
    usage_string = "Usage: %prog -l admin -s foreman.example.com -o 'Default Organization' -L 'Default Location' -g My_Hostgroup -a My_Activation_Key"
    parser = OptionParser(usage=usage_string, version="%%prog %s" % VERSION)
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
    parser.add_option("--force-content-source", dest="force_content_source", action="store_true", default=False, help="Force the content source to be the registration capsule (it overrides the value in the host group if any is defined)")
    parser.add_option("--content-only", dest="content_only", action="store_true", default=False,
                      help="Setup host for content only. Alias to --skip foreman. Implies --skip-puppet. When using --content-only, you MUST pass the Organization's LABEL, not NAME")
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
    parser.add_option("--puppet-noop", dest="puppet_noop", action="store_true", help="Configure Puppet agent to only run in noop mode")
    parser.add_option("--puppet-server", dest="puppet_server", action="store", help="Configure Puppet agent to use this server as master (defaults to the Foreman server)")
    parser.add_option("--puppet-ca-server", dest="puppet_ca_server", action="store", help="Configure Puppet agent to use this server as CA (defaults to the Foreman server)")
    parser.add_option("--puppet-ca-port", dest="puppet_ca_port", action="store", help="Configure Puppet agent to use this port to connect to the CA")
    parser.add_option("--remove", dest="remove", action="store_true", help="Instead of registering the machine to Foreman remove it")
    parser.add_option("-r", "--release", dest="release", help="Specify release version")
    parser.add_option("-R", "--remove-obsolete-packages", dest="removepkgs", action="store_true", help="Remove old Red Hat Network and RHUI Packages (default)", default=True)
    parser.add_option("--download-method", dest="download_method", default=DEFAULT_DOWNLOAD_METHOD, help="Method to download katello-ca-consumer package (e.g. http or https)", metavar="DOWNLOADMETHOD", choices=['http', 'https'])
    parser.add_option("--no-remove-obsolete-packages", dest="removepkgs", action="store_false", help="Don't remove old Red Hat Network and RHUI Packages")
    parser.add_option("--unmanaged", dest="unmanaged", action="store_true", help="Add the server as unmanaged. Useful to skip provisioning dependencies.")
    parser.add_option("--rex", dest="remote_exec", action="store_true", help="Install Foreman's SSH key for remote execution.", default=False)
    parser.add_option("--rex-user", dest="remote_exec_user", default="root", help="Local user used by Foreman's remote execution feature.")
    parser.add_option("--rex-proxies", dest="remote_exec_proxies", help="Comma separated list of proxies to install Foreman's SSH keys for remote execution.")
    parser.add_option("--rex-urlkeyfile", dest="remote_exec_url", help="HTTP/S location of a file containing one or more Foreman's SSH keys for remote execution.")
    parser.add_option("--rex-apikeys", dest="remote_exec_apikeys", action="store_true", help="Fetch Foreman's SSH keys from the API.")
    parser.add_option("--rex-authpath", dest="remote_exec_authpath", help="Full path to local authorized_keys file in order to install Foreman's SSH keys for remote execution. Default ~/.ssh/authorized_keys")
    parser.add_option("--enablerepos", dest="enablerepos", help="Repositories to be enabled via subscription-manager - comma separated", metavar="enablerepos")
    parser.add_option("--skip", dest="skip", action="append", help="Skip the listed steps (choices: %s)" % SKIP_STEPS, choices=SKIP_STEPS, default=[])
    parser.add_option("--ip", dest="ip", help="IPv4 address of the primary interface in Foreman (defaults to the address used to make request to Foreman)")
    parser.add_option("--deps-repository-url", dest="deps_repository_url", help="URL to a repository that contains the subscription-manager RPMs")
    parser.add_option("--deps-repository-gpg-key", dest="deps_repository_gpg_key", help="GPG Key to the repository that contains the subscription-manager RPMs", default="file:///etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release")
    parser.add_option("--install-packages", dest="install_packages", help="List of packages to be additionally installed - comma separated", metavar="installpackages")
    parser.add_option("--new-capsule", dest="new_capsule", action="store_true", help="Switch the server to a new capsule for content and Puppet. Pass --server with the Capsule FQDN as well.")
    parser.add_option("-t", "--timeout", dest="timeout", type="int", help="Timeout (in seconds) for API calls and subscription-manager registration. Defaults to %default", metavar="timeout", default=900)
    parser.add_option("-c", "--comment", dest="comment", help="Add a host comment")
    parser.add_option("--ignore-registration-failures", dest="ignore_registration_failures", action="store_true", help="Continue running even if registration via subscription-manager/rhn-migrate-classic-to-rhsm returns a non-zero return code.")
    parser.add_option("--preserve-rhsm-proxy", dest="preserve_rhsm_proxy", action="store_true", help="Preserve proxy settings in /etc/rhsm/rhsm.conf when migrating RHSM -> RHSM")
    parser.add_option("--install-katello-agent", dest="install_katello_agent", action="store_true", help="Installs the Katello Agent", default=False)
    (options, args) = parser.parse_args()

    if options.no_foreman:
        print_warning("The --skip-foreman option is deprecated, please use --skip foreman.")
        options.skip.append('foreman')
    if options.no_puppet:
        print_warning("The --skip-puppet option is deprecated, please use --skip puppet.")
        options.skip.append('puppet')
    if not options.removepkgs:
        options.skip.append('remove-obsolete-packages')
    if options.content_only:
        print_generic("The --content-only option was provided. Adding --skip foreman")
        options.skip.append('foreman')
    if not options.puppet_server:
        options.puppet_server = options.foreman_fqdn
    if not options.puppet_ca_server:
        options.puppet_ca_server = options.foreman_fqdn

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
            (options.foreman_fqdn and options.org and options.activationkey and ('foreman' in options.skip or options.hostgroup)) or
            (options.foreman_fqdn and options.new_capsule)):
        if not options.remove and not options.new_capsule:
            print("Must specify server, login, organization, hostgroup and activation key.  See usage:")
        elif options.new_capsule:
            print("Must use both --new-capsule and --server. See usage:")
        else:
            print("Must specify server.  See usage:")
        parser.print_help()
        sys.exit(1)

    # > Gather FQDN, HOSTNAME and DOMAIN using options.fqdn
    # > If socket.fqdn() returns an FQDN, derive HOSTNAME & DOMAIN using FQDN
    # > else, HOSTNAME isn't an FQDN
    # > if user passes --fqdn set FQDN, HOSTNAME and DOMAIN to the parameter that is given.
    FQDN = options.fqdn
    if FQDN.find(".") != -1:
        HOSTNAME = FQDN.split('.')[0]
        DOMAIN = FQDN[FQDN.index('.') + 1:]
    else:
        HOSTNAME = FQDN
        DOMAIN = None

    # > Exit if DOMAIN isn't set and Puppet must be installed (without force)
    if not DOMAIN and not (options.force or 'puppet' in options.skip):
        print("We could not determine the domain of this machine, most probably `hostname -f` does not return the FQDN.")
        print("This can lead to Puppet misbehaviour and thus the script will terminate now.")
        print("You can override this by passing one of the following")
        print("\t--force - to disable all checking")
        print("\t--skip puppet - to omit installing the puppet agent")
        print("\t--fqdn <FQDN> - to set an explicit FQDN, overriding detected FQDN")
        sys.exit(1)

    # > Gather primary IP address if none was given
    # we do this *after* parsing options to find the IP on the interface
    # towards the Foreman instance in the case the machine has multiple
    if not options.ip:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((options.foreman_fqdn, 80))
            options.ip = s.getsockname()[0]
            s.close()
        except:  # noqa: E722, pylint:disable=bare-except
            options.ip = None

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
        print("HOSTNAME - %s" % HOSTNAME)
        print("DOMAIN - %s" % DOMAIN)
        print("FQDN - %s" % FQDN)
        print("OS RELEASE - %s" % RELEASE)
        print("MAC - %s" % MAC)
        print("IP - %s" % options.ip)
        print("foreman_fqdn - %s" % options.foreman_fqdn)
        print("LOGIN - %s" % options.login)
        print("PASSWORD - %s" % options.password)
        print("HOSTGROUP - %s" % options.hostgroup)
        print("LOCATION - %s" % options.location)
        print("OPERATINGSYSTEM - %s" % options.operatingsystem)
        print("PARTITIONTABLE - %s" % options.partitiontable)
        print("ORG - %s" % options.org)
        print("ACTIVATIONKEY - %s" % options.activationkey)
        print("CONTENT RELEASE - %s" % options.release)
        print("UPDATE - %s" % options.update)
        print("LEGACY LOGIN - %s" % options.legacy_login)
        print("LEGACY PASSWORD - %s" % options.legacy_password)
        print("DOWNLOAD METHOD - %s" % options.download_method)
        print("SKIP - %s" % options.skip)
        print("TIMEOUT - %s" % options.timeout)
        print("PUPPET SERVER - %s" % options.puppet_server)
        print("PUPPET CA SERVER - %s" % options.puppet_ca_server)
        print("PUPPET CA PORT - %s" % options.puppet_ca_port)
        print("IGNORE REGISTRATION FAILURES - %s" % options.ignore_registration_failures)
        print("PRESERVE RHSM PROXY CONFIGURATION - %s" % options.preserve_rhsm_proxy)
        print("REX - %s" % options.remote_exec)
        if options.remote_exec:
            print("REX USER - %s" % options.remote_exec_user)
            print("REX PROXIES - %s" % options.remote_exec_proxies)
            print("REX KEY URL - %s" % options.remote_exec_url)
            print("REX KEYS FROM API - %s" % options.remote_exec_apikeys)
            print("REX AUTHPATH - %s" % options.remote_exec_authpath)

    # > Exit if the user isn't root.
    # Done here to allow an unprivileged user to run the script to see
    # its various options.
    if os.getuid() != 0:
        print_error("This script requires root-level access")
        sys.exit(1)

    # > Check if Katello/Spacewalk/Satellite are installed already
    check_rpm_installed()

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
            call_yum("install", "python-simplejson")
            try:
                import simplejson as json
            except ImportError:
                print_error("Could not install python-simplejson")
                sys.exit(1)

    # > Clean the environment from LD_... variables
    clean_environment()

    # > IF RHEL 5, not removing, and not moving to new capsule prepare the migration.
    if not options.remove and IS_EL5 and not options.new_capsule:
        if options.legacy_purge:
            print_warning("Purging the system from the Legacy environment is not supported on EL5.")
        prepare_rhel5_migration()

    if options.preserve_rhsm_proxy:
        saved_proxy_config = get_rhsm_proxy()

    if options.remove:
        # > IF remove, disassociate/delete host, unregister,
        # >            uninstall katello and optionally puppet agents
        API_PORT = get_api_port()
        unregister_system()
        if 'foreman' not in options.skip:
            hostid = return_matching_foreman_key('hosts', 'name="%s"' % FQDN, 'id', True)
            if hostid is not None:
                disassociate_host(hostid)
                delete_host(hostid)
        if 'katello-agent' in options.skip:
            print_warning("Skipping the installation of the Katello Agent is now the default behavior. passing --skip katello-agent is deprecated")
        if 'katello-agent' not in options.skip or 'katello-host-tools' not in options.skip:
            clean_katello_agent()
        if 'puppet' not in options.skip:
            clean_puppet()
    elif check_rhn_registration() and 'migration' not in options.skip and not IS_EL8:
        # > ELIF registered to RHN, install subscription-manager prerequs
        # >                         get CA RPM, optionally create host,
        # >                         migrate via rhn-classic-migrate-to-rhsm
        print_generic('This system is registered to RHN. Attempting to migrate via rhn-classic-migrate-to-rhsm')
        install_prereqs()

        _, versionerr = check_migration_version(SUBSCRIPTION_MANAGER_MIGRATION_MINIMAL_VERSION)
        if versionerr:
            print_error(versionerr)
            sys.exit(1)

        get_bootstrap_rpm(clean=options.force)
        generate_katello_facts()
        API_PORT = get_api_port()
        if 'foreman' not in options.skip:
            create_host()
        configure_subscription_manager()
        migrate_systems(options.org, options.activationkey)
        if options.enablerepos:
            enable_repos()
    elif options.new_capsule:
        # > ELIF new_capsule and foreman_fqdn set, will migrate to other capsule
        #
        # > will replace CA certificate, reinstall katello-agent, gofer
        # > will optionally update hostgroup and location
        # > wil update system definition to point to new capsule for content,
        # > Puppet, OpenSCAP and update Puppet configuration (if applicable)
        # > MANUAL SIGNING OF CSR OR MANUALLY CREATING AUTO-SIGN RULE STILL REQUIRED!
        # > API doesn't have a public endpoint for creating auto-sign entries yet!
        if not is_registered():
            print_error("This system doesn't seem to be registered to a Capsule at this moment.")
            sys.exit(1)

        # Make system ready for switch, gather required data
        install_prereqs()
        get_bootstrap_rpm(clean=True, unreg=False)
        install_katello_host_tools()
        if options.install_katello_agent:
            install_katello_agent()
        if 'katello-agent' in options.skip:
            print_warning("Skipping the installation of the Katello Agent is now the default behavior. passing --skip katello-agent is deprecated")
        enable_rhsmcertd()

        API_PORT = get_api_port()
        if 'foreman' not in options.skip:
            current_host_id = return_matching_foreman_key('hosts', 'name="%s"' % FQDN, 'id', False)

            # Optionally configure new hostgroup, location
            if options.hostgroup:
                print_running("Calling Foreman API to switch hostgroup for %s to %s" % (FQDN, options.hostgroup))
                update_host_config('hostgroup', options.hostgroup, current_host_id)
            if options.location:
                print_running("Calling Foreman API to switch location for %s to %s" % (FQDN, options.location))
                update_host_config('location', options.location, current_host_id)

            # Configure new proxy_id for Puppet (if not skipped), and OpenSCAP (if available and not skipped)
            smart_proxy_id = return_matching_foreman_key('smart_proxies', 'name="%s"' % options.foreman_fqdn, 'id', True)
            if smart_proxy_id:
                capsule_features = get_capsule_features(smart_proxy_id)
                if 'puppet' not in options.skip:
                    print_running("Calling Foreman API to update Puppet master and Puppet CA for %s to %s" % (FQDN, options.foreman_fqdn))
                    update_host_capsule_mapping("puppet_proxy_id", smart_proxy_id, current_host_id)
                    update_host_capsule_mapping("puppet_ca_proxy_id", smart_proxy_id, current_host_id)
                if 'Openscap' in capsule_features:
                    print_running("Calling Foreman API to update OpenSCAP proxy for %s to %s" % (FQDN, options.foreman_fqdn))
                    update_host_capsule_mapping("openscap_proxy_id", smart_proxy_id, current_host_id)
                else:
                    print_warning("New capsule doesn't have OpenSCAP capability, not switching / configuring openscap_proxy_id")

                print_running("Calling Foreman API to update content source for %s to %s" % (FQDN, options.foreman_fqdn))
                update_host_capsule_mapping("content_source_id", smart_proxy_id, current_host_id)
            else:
                print_warning("Could not find Smart Proxy '%s'! Will not inform Foreman about the new Puppet/OpenSCAP/content source for %s." % (options.foreman_fqdn, FQDN))

        if 'puppet' not in options.skip:
            puppet_conf_path = '/etc/puppetlabs/puppet/puppet.conf'
            var_dir = '/opt/puppetlabs/puppet/cache'
            ssl_dir = '/etc/puppetlabs/puppet/ssl'

            print_running("Stopping the Puppet agent for configuration update")
            exec_service("puppet", "stop")

            # Not using clean_puppet() and install_puppet_agent() here, because
            # that would nuke custom /etc/puppet/puppet.conf files, which might
            # yield undesirable results.
            print_running("Updating Puppet configuration")
            exec_failexit("sed -i '/^[[:space:]]*server.*/ s/=.*/= %s/' %s" % (options.puppet_server, puppet_conf_path))
            exec_failok("sed -i '/^[[:space:]]*ca_server.*/ s/=.*/= %s/' %s" % (options.puppet_ca_server, puppet_conf_path))  # For RHEL5 stock puppet.conf
            delete_directory(ssl_dir)
            delete_file("%s/client_data/catalog/%s.json" % (var_dir, FQDN))

            noop_puppet_signing_run()
            print_generic("Puppet agent is not running; please start manually if required.")
            print_generic("You also need to manually revoke the certificate on the old capsule.")

    else:
        # > ELSE get CA RPM, optionally create host,
        # >      register via subscription-manager
        print_generic('This system is not registered to RHN. Attempting to register via subscription-manager')
        install_prereqs()
        get_bootstrap_rpm(clean=options.force)
        generate_katello_facts()
        API_PORT = get_api_port()
        if 'foreman' not in options.skip:
            create_host()
        configure_subscription_manager()
        if options.preserve_rhsm_proxy:
            set_rhsm_proxy(saved_proxy_config)
        register_systems(options.org, options.activationkey)
        if options.enablerepos:
            enable_repos()

    if options.location and 'foreman' in options.skip:
        delete_file('/etc/rhsm/facts/location.facts')

    if not options.remove and not options.new_capsule:
        # > IF not removing, install Katello agent, optionally update host,
        # >                  optionally clean and install Puppet agent
        # >                  optionally remove legacy RHN packages
        if options.install_katello_agent:
            install_katello_agent()
        if 'katello-agent' in options.skip:
            print_warning("Skipping the installation of the Katello Agent is now the default behavior. passing --skip katello-agent is deprecated")
        if 'katello-host-tools' not in options.skip:
            install_katello_host_tools()
        if options.update:
            fully_update_the_box()

        if 'puppet' not in options.skip:
            if options.force:
                clean_puppet()
            install_puppet_agent()

        if options.install_packages:
            install_packages()

        if 'remove-obsolete-packages' not in options.skip:
            remove_obsolete_packages()

        if options.remote_exec:
            if options.remote_exec_proxies:
                listproxies = options.remote_exec_proxies.split(",")
                for proxy_fqdn in listproxies:
                    remote_exec_url = "https://" + str(proxy_fqdn) + ":9090/ssh/pubkey"
                    install_ssh_key_from_url(remote_exec_url)
            elif options.remote_exec_url:
                install_ssh_key_from_url(options.remote_exec_url)
            elif options.remote_exec_apikeys:
                install_ssh_key_from_api()
            else:
                remote_exec_url = "https://" + str(options.foreman_fqdn) + ":9090/ssh/pubkey"
                install_ssh_key_from_url(remote_exec_url)
