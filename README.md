# Foreman Bootstrap Script
bootstrap Script for migrating existing running systems to Foreman with the Katello plugin

# Overview

* The goal is to take a RHEL client and get it registered to Foreman
This script can take a system that is registered to Spacewalk, Satellite 5, Red Hat
Network Classic and get it registered to Foreman & Katello.

Optionally, you can also move systems between Capsules (both internal and
external) of one Katello installation by using the `--new-capsule` option.

# What does the Script do?

* Identify which systems management platform is the system registered to (Classic/Sat5 or None)  then perform the following

## Red Hat Classic & Satellite 5

* Installing subscription-manager and its pre-reqs (updated yum & openssl)
* Make an API call to Katello to create the Foreman Host associated with the user specified Org/Location
* Install the Katello consumer RPM
* Running rhn-migrate-classic-to-rhsm (with the user provided activation key) to get product certs on a system
* registering the system to Foreman
* Configuring the system with a proper Puppet configuration pointing at Foreman
* Removing/disabling old RHN Classic packages/daemons (rhnsd, osad, etc)

## System already registered to a Foreman + Katello server / Capsule (--new-capsule)
* Clean the existing Katello agent installation
* Install the Katello consumer RPM for the target Foreman + Katello server / Capsule
* Install the Katello agent software again, using the configuration for the
  target Foreman + Katello / Capsule server
* Make API calls to switch the system to a different hostgroup (optional)
* Make API calls to update the Puppet master, Puppet CA, content source and
  OpenSCAP proxy IDs (optional, except for content source)
* Re-enable rhsmcertd
* Update the Puppet configuration for the system to point to the right capsule (optional)
* Restart Puppet and call for the user to go sign the CSR

## System not registered to any Red Hat Systems Management Platform:

* Make an API call to Foreman to create the Foreman Host associated with the user specified Org/Location
* Install the Katello consumer RPM
* Running subscription-manager (with the user provided activation key) to register the system.
* Configuring the system with a proper Puppet configuration pointing at Foreman
* Removing/disabling old RHN Classic packages/daemons (rhnsd, osad, etc)

# Assumptions

* The script will use only components that are present on all RHEL
  installations. We will not install additional packages, other than
  those explicitly required for Katello management, on the client
  system.  (i.e., I could have used the python-requests module to make the
  API calls a lot more pleasant, but I couldn't justify the dependencies)
* The system in question has python.
* The administrator can approve Puppet certificates if using Puppet.
  Alternatively, autosigning can be enabled for the system in question.  (And be careful, auto-signing isn't one of those things you'd leave enabled forever)
* The Foreman instance is properly prepared and is able to provision systems,
  especially the following is true:
  * The activation key provides access to a Content View
    which provides Puppet and other client side tooling.
  * The domain of the system is known to Foreman.
  * If not using the `--skip foreman` option, the hostgroup has the "Host Group" and "Operating System" tabs filled out completely. Otherwise, when boostrap runs to create the host, required information will be missing and the API call with fail.

# Dependencies

* Python2 >= 2.5 or 2.4 with python-simplejson installed
* subscription-manager (if the machine has no previous subscription)
* subscription-manager-migration >= 1.14.2 (if the machine is subscribed to Satellite 5 or Red Hat Classic)

# User required inputs

* Hostname of Foreman and/or Capsule host
* username of user with privileges to add new hosts on Foreman via the API
* password of the aforementioned user.
* Location and Organization that the system is to be associated with.
* hostgroup that the client is to be associated with.
* An Activation Key that provides a content view with access to Puppet and other tools

# Permissions

The script requires certain permissions to work properly. These heavily depend on the amount of enabled features.

By default you will need the following permissions:

* View organizations
* View locations
* View domains
* View subnets
* View hostgroups
* View hosts
* View architectures
* View partitiontables
* View operatingsystems
* Create hosts

These can be easily achieved by giving the user the 'Viewer' and 'Edit hosts' roles. Please note that the 'Edit hosts' role also allows to edit and delete hosts (see below), so it might be too permissive, depending on the environment.

When using the `--remove` or `--force` options, the following additional permissions are needed:

* Delete hosts
* Edit hosts

When using the `--add-domain` option, the following additional permission is needed:

* Create domains

When using the `--skip-foreman` option, no user account in Foreman is needed at all.

When using the `--legacy-purge` option, a user account on the legacy environment (RHN/Satellite5) is required. The user needs to be an admin of the system in the legacy environment by having any of the following roles:

* organization administrator
* system group administrator for a system group that the system is a member of
* granted permissions to the system explicitly via Users-> account-> 'Systems Administered by this User'

# Usages:

### Registering a system to Foreman + Katello

This is one of the most standard workflows with bootstrap.py. This sets up the system for content / configuration (via Puppet) & provisioning.
~~~
# ./bootstrap.py -l admin \
    -s foreman.example.com \
    -o "Red Hat" \
    -L RDU \
    -g "RHEL7/Crash" \
    -a ak-Reg_To_Crash
~~~

### Registering a system omitting Puppet setup.

There are times where you wish to not install Puppet, perhaps you have a differing or existing configuration management system.

~~~
# ./bootstrap.py -l admin \
    -s foreman.example.com \
    -o "Red Hat" \
    -L RDU \
    -g "RHEL7/Crash" \
    -a ak-Reg_To_Crash \
    --skip-puppet
~~~

### Registering a system to Foreman + Katello, for content only.

This usage leverages the `--skip-foreman` switch, which does not require username/password authentication.

**NOTES**

 - the `--skip-foreman` switch implies `--skip-puppet`
 - When using `--skip-foreman`, it is expected that the organization specified  (via `--organization|-o`) is specified via **LABEL**, not **NAME**.

~~~
# ./bootstrap.py -s foreman.example.com \
    -a ak_Reg_To_Dev_EL7 \
    -o "Red_Hat" \
    --skip-foreman
~~~


### Migrating a system from Red Hat Network (RHN) or Satellite 5 to Foreman

bootstrap.py detects the presence of `/etc/syconfig/rhn/systemid` and a valid connection to RHN/Satellite 5 as an indicator that the system is registered to a legacy platform. In these use-cases, bootstrap will call `rhn-classic-migrate-to-rhsm` to ensure the system is migrated properly from RHN or Satellite 5.

By default, bootstrap.py does not delete the system's profile from the legacy platform. This is done to keep the systems record for audit/accounting reasons. If it is desired to remove the legacy profile from RHN/Satellite 5, the `--legacy-purge` switch can be used.

**NOTES**:

- The `--legacy-purge` switch requires a user account on RHN/Satellite 5 with permissions to remove the systems in question.
- The `--legacy-login` and `--legacy-password` options allow the correct RHN/Satellite 5 username/password to be provided to bootstrap.py.
- bootstrap.py will prompt the user for the Legacy Password if not provided via CLI parameter.


~~~
# ./bootstrap.py -l admin \
    -s foreman.example.com \
    -o "Red Hat" \
    -L RDU \
    -g "RHEL7/Crash" \
    -a ak-Reg_To_Crash \
    --legacy-purge \
    --legacy-login rhn-user
~~~
### Migrating a system from one Foreman + Katello installation to another.

There are times where it is necessary to migrate clients from one Foreman + Katello installation to another. For instance, in lieu of upgrading an older Foreman + Katello installation, you choose to build a new installation in parallel. bootstrap.py can then be used to migrate clients from one Foreman + Katello installation to another. Simply provide the `--force` option, and bootstrap.py will remove the previous `katello-ca-consumer-*` package (from the old system), and will install the `katello-ca-consumer-*` package (from the new system), and continue registration as usual.

### Migrating a system from one Foreman + Katello installation 6 or Capsule / to another in the same infrastructure

In order to manually balance the load over multiple Capsule servers, you might
want to move some existing systems to newly deployed Capsules. You can easily
do this by running the bootstrap.py script like the examples below. Mind that
you still have to manually revoke any Puppet certificates on the old capsules!

~~~
# ./bootstrap.py -l admin --new-capsule --server capsule.example.com
~~~

If you want to change the hostgroup and location of the system at the same
time, run:

~~~
# ./bootstrap.py -l admin --new-capsule --server capsule.example.com \
    --hostgroup mygroup --location mylocation
~~~

### Enabling additional repositories at registration time.

It is recommended to set which repositories that you want enabled on your activation keys via the UI or via `hammer activation-key product-content`. However, older versions of `subscription-manager` (versions < 1.10) do not support product content overrides. The `--enablerepos` switch accepts a comma separated lists of repositories that are passed to `subscription-manager` that will be enabled at registration time.

~~~
# ./bootstrap.py -l admin \
    -s foreman.example.com \
    -o "Red Hat" \
    -L RDU \
    -g "RHEL7/Crash" \
    -a ak-Reg_To_Crash \
    --enablerepos=rhel-7-server-extras-rpms,rhel-7-server-optional-rpms
~~~

### Creating a domain for a host at registration time.

To create a host record, the DNS domain of a host needs to exist  (in Foreman) prior to running bootstrap.py. If the domain does not exist, it can be added via the `--add-domain` switch.

~~~
# hostname
client.linux.example.com

# ./bootstrap.py -l admin \
    -s foreman.example.com \
    -o "Red Hat" \
    -L RDU \
    -g "RHEL7/Crash" \
    -a ak-Reg_To_Crash

[NOTIFICATION], [2016-12-05 09:15:29],
[Domain linux.example.com doesn't exist in Foreman, consider using the --add-domain option.]
~~~

Run the script again including the `--add-domain` option

~~~
#./bootstrap.py -l admin \
    -s foreman.example.com \
    -o "Red Hat" \
    -L RDU \
    -g "RHEL7/Crash" \
    -a ak-Reg_To_Crash \
    --add-domain

[RUNNING], [2016-12-05 09:19:10], [Calling Foreman API to create domain
linux.example.com associated with the org & location]
[RUNNING], [2016-12-05 09:19:10], [Calling Foreman API to create a host entry
associated with the group & org]
[SUCCESS], [2016-12-05 09:19:10], [Successfully created host
client.linux.example.com], completed successfully.
~~~

### Enabling Remote Execution

bootstrap.py now includes the `--rex` & `--rex-user` features which allow the administrator to deploy the required SSH keys.

~~~

# ./bootstrap.py -l admin \
    -s foreman.example.com \
    -o "Red Hat" \
    -L RDU \
    -g "RHEL7/Crash" \
    -a ak-Reg_To_Crash \
    --rex \
    --rex-user root

[SUCCESS], [2016-12-02 06:37:09], [/usr/bin/yum -y remove rhn-setup rhn-client-tools yum-rhn-plugin rhnsd rhn-check rhnlib spacewalk-abrt spacewalk-oscap osad 'rh-*-rhui-client'], completed successfully.

[NOTIFICATION], [2016-12-02 06:37:09], [Foreman's SSH key was added to /root/.ssh/authorized_keys]
Key was added successfully.
~~~

Check the **root** users authorized key file.

~~~
cat ~/.ssh/authorized_keys
ssh-rsa AAAAB3Nz.... foreman-proxy@foreman.example.com
~~~

### Skipping particular steps:

Sometimes, you may want to skip certain steps of the bootstrapping process. the `--skip` switch provides this. It currently has the following parameters

* `foreman` - Skips any Foreman setup steps. (equivalent to the `--skip-foreman` option)
* `puppet` - Does not install puppet (equivalent to the `--skip-puppet` option)
* `migration` - Skips RHN/Spacewalk registration detection. This option prevents `rhn-classic-migrate-to-rhsm` from timing out and failing on RHN/Spacewalk systems that aren't available.
* `prereq-update` - Skips update of `yum`, `openssl` and `python`
* `katello-agent` - Does not install the `katello-agent` package
* `remove-obsolete-packages` - Does not remove the Classic/RHN/Spacewalk/RHUI packages.  (equivalent to `--no-remove-obsolete-packages`)
* `puppet-enable` - Does not enable and start the puppet daemon on the client. 

**Note:** it is strongly preferred to use the `--skip` option in lieu of the individual `--skip-foreman`, `--skip-puppet`, and `--no-remove-obsolete-packages` options.

~~~
# ./bootstrap.py -l admin \
    -s foreman.example.com \
    -o "Red Hat" \
    -L RDU \
    -g "RHEL7/Crash" \
    -a ak-Reg_To_Crash \
    --skip prereq-update --skip migration
~~~

### Providing an arbitrary Fully Qualified Domain Name.

Many users have either hostnames that are short (`hostname -f` or python's `socket.getfqdn` returns a hostname that isn't an FQDN) or non-RFC compliant (containing a character such as an underscore `-` which fails Foreman's hostname validation.

In many cases, the user cannot update his/her system to provide a FQDN. bootstrap.py provides the `--fqdn` which allows the user to specify the FQDN that will be reported to Foreman

**Prerequisites**

The user needs to set to **False** the `create_new_host_when_facts_are_uploaded` and ` create_new_host_when_report_is_uploaded` options. If these options are not set, a host entry will be created based upon the facts provided by facter.  This can be done with hammer.

~~~
hammer settings set \
  --name  create_new_host_when_facts_are_uploaded \
  --value false
hammer settings set \
  --name  create_new_host_when_report_is_uploaded \
  --value false
~~~

Example Usage
~~~
# hostname -f
node-100

# python -c 'import socket; print socket.getfqdn()'
node-100

# ./bootstrap.py -l admin \
    -s foreman.example.com \
    -o "Red Hat" \
    -L RDU \
    -g "RHEL7/Crash" \
    -a ak-Reg_To_Crash \
    --fqdn node-100.example.com
~~~

### Changing the method bootstrap uses to download the katello-ca-consumer RPM

By default, the bootstrap script uses HTTP to download the `katello-ca-consumer` RPM. In some environments, it is desired to only allow HTTPS between the client and Foreman. the `--download-method` option can be used to change the download method that bootstrap uses from HTTP to HTTPS.

~~~
./bootstrap.py -l admin \
    -s foreman.example.com \
    -o "Red Hat" \
    -L RDU \
    -g "RHEL7/Crash" \
    -a ak-Reg_To_Crash \
    --download-method https
~~~

### Providing the IP address to Foreman

Foreman requires the IP address of the machine to perform remote execution or re-deploy the machine using kickstart.

On machines with multiple interfaces or multiple addresses on one interface, it might be needed to override the auto-detection of the address and provide a specific address to Foreman.

~~~
./bootstrap.py -l admin \
    -s foreman.example.com \
    -o "Red Hat" \
    -L RDU \
    -g "RHEL7/Crash" \
    -a ak-Reg_To_Crash \
    --ip 192.0.2.23
~~~


### Configuring the client to run only in noop mode

When migrating or registering clients which may have never been managed via Puppet, it may be useful to configure the agent in `noop` mode. This allows the client to be managed via Foreman, while getting facts & reports about its configuration state, without making any changes to it. The `--puppet-noop` switch facilitates this behavior

~~~
./bootstrap.py -l admin \
    -s foreman.example.com \
    -o "Red Hat" \
    -L RDU \
    -g "RHEL7/Crash" \
    -a ak-Reg_To_Crash \
    --puppet-noop
~~~

### Providing a repository with the subscription-manager packages

For clients who do not have subscription-manager installed (which is a prerequisite of `bootstrap.py`), the `deps-repository-url` option can be used to specify a yum repository which contains the `subscription-manager` RPMs
On your Foreman instance, kickstart repositories are available via HTTP, and are ideal to be used in this scenario. However, any yum repository with the required packages would work.  

~~~
./bootstrap.py -l admin \
    -s foreman.example.com \
    -o "Red Hat" \
    -L RDU \
    -g "RHEL7/Crash" \
    -a ak-Reg_To_Crash \
    --download-method https \
    --deps-repository-url "http://server.example.com/pulp/repos/Example/Library/content/dist/rhel/server/7/7.2/x86_64/kickstart/"
~~~

Also, the `--deps-repository-gpg-key` option (defaults to `file:///etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release`) is available if the GPG key for the repository differs from `/etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release`

### Installing user specified packages

For some users who do not have a configuration management or automation solution, `bootstrap.py` provides a means to install user specified packages via the `--install-packages` switch.

~~~
./bootstrap.py -l admin \
    -s foreman.example.com \
    -o "Red Hat" \
    -L RDU \
    -g "RHEL7/Crash" \
    -a ak-Reg_To_Crash \
    --install-packages csh,dstat

~~~

### Changing the API/Subscription Manager timeouts

On busy servers, it is sometimes useful to increase the amount of time that the system waits before timing out during registration and subscription tasks. 
`bootstrap.py` defaults to an timeout of **900** seconds for APIs. Additionally, the `server_timeout` parameter for `subscription-manager` 
is configured with this value. If desired, this value can be overridden using the `--timeout` option.

~~~
./bootstrap.py -l admin \
    -s foreman.example.com \
    -o "Red Hat" \
    -L RDU \
    -g "RHEL7/Crash" \
    -a ak-Reg_To_Crash \
    --timeout 1800

~~~


# Help / Available options:

~~~
Foreman Bootstrap Script
This script is designed to register new systems or to migrate an existing system to a Foreman server with Katello
Usage: bootstrap.py -l admin -s foreman.example.com -o 'Default Organization' -L 'Default Location' -g My_Hostgroup -a My_Activation_Key

Options:
  --version             show program's version number and exit
  -h, --help            show this help message and exit
  -s foreman_fqdn, --server=foreman_fqdn
                        FQDN of Foreman OR Capsule - omit https://
  -l LOGIN, --login=LOGIN
                        Login user for API Calls
  -p PASSWORD, --password=PASSWORD
                        Password for specified user. Will prompt if omitted
  --fqdn=FQDN           Set an explicit FQDN, overriding detected FQDN from
                        socket.getfqdn(), currently detected as
                        client.example.com
  --legacy-login=LOGIN  Login user for Satellite 5 API Calls
  --legacy-password=PASSWORD
                        Password for specified Satellite 5 user. Will prompt
                        if omitted
  --legacy-purge        Purge system from the Legacy environment (e.g. Sat5)
  -a ACTIVATIONKEY, --activationkey=ACTIVATIONKEY
                        Activation Key to register the system
  -P, --skip-puppet     Do not install Puppet
  --skip-foreman        Do not create a Foreman host. Implies --skip-puppet.
                        When using --skip-foreman, you MUST pass the
                        Organization's LABEL, not NAME
  -g HOSTGROUP, --hostgroup=HOSTGROUP
                        Title of the Hostgroup in Foreman that the host is to
                        be associated with
  -L LOCATION, --location=LOCATION
                        Title of the Location in Foreman that the host is to
                        be associated with
  -O OPERATINGSYSTEM, --operatingsystem=OPERATINGSYSTEM
                        Title of the Operating System in Foreman that the host
                        is to be associated with
  --partitiontable=PARTITIONTABLE
                        Name of the Partition Table in Foreman that the host
                        is to be associated with
  -o ORG, --organization=ORG
                        Name of the Organization in Foreman that the host is
                        to be associated with
  -S ARGS, --subscription-manager-args=ARGS
                        Which additional arguments shall be passed to
                        subscription-manager
  --rhn-migrate-args=ARGS
                        Which additional arguments shall be passed to rhn-
                        migrate-classic-to-rhsm
  -u, --update          Fully Updates the System
  -v, --verbose         Verbose output
  -f, --force           Force registration (will erase old katello and puppet
                        certs)
  --add-domain          Automatically add the clients domain to Foreman
  --puppet-noop         Configure Puppet agent to only run in noop mode
  --remove              Instead of registering the machine to Foreman remove
                        it
  -r RELEASE, --release=RELEASE
                        Specify release version
  -R, --remove-obsolete-packages
                        Remove old Red Hat Network and RHUI Packages (default)
  --download-method=DOWNLOADMETHOD
                        Method to download katello-ca-consumer package (e.g.
                        http or https)
  --no-remove-obsolete-packages
                        Don't remove old Red Hat Network and RHUI Packages
  --unmanaged           Add the server as unmanaged. Useful to skip
                        provisioning dependencies.
  --rex                 Install Foreman's SSH key for remote execution.
  --rex-user=REMOTE_EXEC_USER
                        Local user used by Foreman's remote execution feature.
  --enablerepos=enablerepos
                        Repositories to be enabled via subscription-manager -
                        comma separated
  --skip=SKIP           Skip the listed steps (choices: ['foreman', 'puppet',
                        'migration', 'prereq-update', 'katello-agent',
                        'remove-obsolete-packages', 'puppet-enable'])
  --ip=IP               IPv4 address of the primary interface in Foreman
                        (defaults to the address used to make request to
                        Foreman)
  --deps-repository-url=DEPS_REPOSITORY_URL
                        URL to a repository that contains the subscription-
                        manager RPMs
  --deps-repository-gpg-key=DEPS_REPOSITORY_GPG_KEY
                        GPG Key to the repository that contains the
                        subscription-manager RPMs
  --install-packages=installpackages
                        List of packages to be additionally installed - comma
                        separated
  -t timeout, --timeout=timeout
                        Timeout (in seconds) for API calls and subscription-
                        manager registration. Defaults to 900
~~~

# Additional Notes

## FIPS support

On systems with FIPS enabled (where `/proc/sys/crypto/fips_enabled == 1`), algorithms such as MD5 are disallowed. Bootstrap will configure `digest_algorithm = sha256` in puppet.conf to allow successful puppet runs. However, the signing algorithm **must** match on the Puppet Master. It is expected that the Puppet Masters are configured with the **same** algorithm.  

# Ansible integration

The `bootstrap.yml` file contains a playbook for [Ansible](https://www.ansible.com/) which can be used to copy `bootstrap.py` to the target machine and execute it there with predefined parameters.

# For developers and contributors:

See  [CONTRIBUTING.md](https://github.com/Katello/katello-client-bootstrap/blob/master/CONTRIBUTING.md)
