# Foreman Bootstrap Script
bootstrap Script for migrating existing running systems to Foreman with the Katello plugin

# Overview

* The goal is to take a Red Hat Enterprise Linux (RHEL) client and get it registered to Foreman
This script can take a system that is registered to Spacewalk, Satellite 5, Red Hat
Network Classic and get it registered to Foreman & Katello.
* Optionally, you can also move systems between Capsules (both internal and
external) of one Katello installation by using the `--new-capsule` option.

# What does the Script do?

* Identify which systems management platform is the system registered to (Classic/Sat5 or None)  then perform the following:

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
* If `subscription-manager` is not installed or is unavailable in the host's configured repositories, a URL pointing to a repository with the `subscription-manager` RPMs is required.


# Frequently asked Questions:

We *strongly* recommend reading this document in its entirety _prior_ to running `bootstrap.py`. The script has a plethora of options for near any migration or Registration use-case.

* **Q**: Why does `bootstrap.py` require a username and password to be used?
* **A**: By default, `bootstrap.py` attempts to configure a host with a proper hostgroup, environment, organization, and location by making API calls to Foreman. The API requires authentication, and as such so does `bootstrap.py`. Alternatively, in many cases, hostgroups aren't used, and it is desired to register a host solely for content management. In this usage (when either the `--skip foreman` or `--content-only` options are provided), only an activation key.


* **Q**: Why doesn't `bootstrap.py` use python-requests?
* **A**: When designing `bootstrap.py` we wanted to make (and keep) the number of additional packages as minimal as possible, especially as `bootstrap.py` is only run once, it seems wasteful to install packages for a one-time use case. `bootstrap.py` assumes that only the standard python modules are available.


* **Q**: Why didn't you write `bootstrap.py` in Ruby (or $OTHER language)?
* **A**: Ruby is not a default package in most installations of RPM family distributions. To be as applicable to the largest number of users (and to not require a large amount of dependencies), `bootstrap.py` is written in Python.  


* **Q**: Why are the SSH keys for remote execution not deployed by default?
* **A**: The remote execution public keys, if copied locally will allow a user with appropriate permissions to run jobs against that system. We believe that changing the security profile of an existing system should be 'opt-in', not 'opt-out'. Please pass the `--rex*` options to setup Remote Execution.


* **Q**: My systems have short hostname, why does `bootstrap.py` not work properly?
* **A**: Hostnames are a unique identifier within Foreman and are used in many places such as Puppet certificate generation. They are required to be FQDNs. If you have short hostnames and cannot change them, see the [**Providing an arbitrary Fully Qualified Domain Name**](#providing-an-arbitrary-fully-qualified-domain-name) section below.

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

When using the `--skip foreman` or `--content-only` option, no user account in Foreman is needed at all.

When using the `--legacy-purge` option, a user account on the legacy environment (RHN/Satellite5) is required. The user needs to be an admin of the system in the legacy environment by having any of the following roles:

* organization administrator
* system group administrator for a system group that the system is a member of
* granted permissions to the system explicitly via Users-> account-> 'Systems Administered by this User'

# Usage:

On an EL8 (RHEL8, CentOS8, etc) host, there is no `/usr/bin/python` or `/usr/bin/python3` by default. The `bootstrap.py` script can be used with the `platform-python` as follows:
~~~
# /usr/libexec/platform-python bootstrap.py
~~~
When the `python36` module is installed, `/usr/bin/python3` can also be used.

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
    --skip puppet
~~~

### Registering a system to Foreman + Katello, for content only.

This usage leverages the `--skip foreman` switch, which does not require username/password authentication.

**NOTES**

 - the `--skip foreman` switch implies `--skip puppet`
 - When using `--skip foreman`, it is expected that the organization specified  (via `--organization|-o`) is specified via **LABEL**, not **NAME**.

Option 1: using the `--skip foreman` option.

~~~
# ./bootstrap.py -s foreman.example.com \
    -a ak_Reg_To_Dev_EL7 \
    -o "Red_Hat" \
    --skip foreman
~~~

Option 2 : using the `--content-only` option. This option exists as an alias to `--skip foreman`.

~~~
# ./bootstrap.py -s foreman.example.com \
    -a ak_Reg_To_Dev_EL7 \
    -o "Red_Hat" \
    --content-only
~~~


### Migrating a system from Red Hat Network (RHN) or Satellite 5 to Foreman

bootstrap.py detects the presence of `/etc/syconfig/rhn/systemid` and a valid connection to RHN/Satellite 5 as an indicator that the system is registered to a legacy platform. In these use-cases, bootstrap will call `rhn-classic-migrate-to-rhsm` to ensure the system is migrated properly from RHN or Satellite 5.

By default, bootstrap.py does not delete the system's profile from the legacy platform. This is done to keep the systems record for audit/accounting reasons. If it is desired to remove the legacy profile from RHN/Satellite 5, the `--legacy-purge` switch can be used.

**NOTES**:

- The `--legacy-purge` switch requires a user account on RHN/Satellite 5 with permissions to remove the systems in question.
- The `--legacy-purge` switch does not work on EL5 systems, as they lack the tooling to instruct the RHN/Satellite5 API to purge the old system entry.
- The `--legacy-login` and `--legacy-password` options allow the correct RHN/Satellite 5 username/password to be provided to bootstrap.py.
- bootstrap.py will prompt the user for the Legacy Password if not provided via CLI parameter.
- If you wish to skip the migration of the system from RHN or Satellite 5 to Foreman, pass `--skip migration` as a CLI option.


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

There are times where it is necessary to migrate clients from one Foreman + Katello installation to another. For instance, in lieu of upgrading an older Foreman + Katello installation, you choose to build a new installation in parallel. bootstrap.py can then be used to migrate clients from one Foreman + Katello installation to another. Simply provide the `--force` option, and `bootstrap.py` will remove the previous `katello-ca-consumer-*` package (from the old system), and will install the `katello-ca-consumer-*` package (from the new system), and continue registration as usual.

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

To create a host record, the DNS domain of a host needs to exist  (in Foreman) prior to running `bootstrap.py`. If the domain does not exist, it can be added via the `--add-domain` switch.

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

#### Fetching Remote Execution SSH keys from an URL

~~~
# ./bootstrap.py -l admin \
    -s foreman.example.com \
    -o "Red Hat" \
    -L RDU \
    -g "RHEL7/Crash" \
    -a ak-Reg_To_Crash \
    --rex \
    --rex-urlkeyfile https://idm.example.com/users/root/keys
~~~

#### Fetching Remote Execution SSH keys from proxies

~~~
# ./bootstrap.py -l admin \
    -s foreman.example.com \
    -o "Red Hat" \
    -L RDU \
    -g "RHEL7/Crash" \
    -a ak-Reg_To_Crash \
    --rex \
    --rex-proxies foreman.example.com,proxy01.example.com,proxy02.example.com
~~~

#### Deploying Remote Execution SSH keys to a non-default location

~~~
# ./bootstrap.py -l admin \
    -s foreman.example.com \
    -o "Red Hat" \
    -L RDU \
    -g "RHEL7/Crash" \
    -a ak-Reg_To_Crash \
    --rex \
    --rex-user root \
    --rex-authpath /etc/ssh/keys/root
~~~

### Skipping particular steps:

Sometimes, you may want to skip certain steps of the bootstrapping process. the `--skip` switch provides this. It currently has the following parameters

* `foreman` - Skips any Foreman setup steps, please note that you MUST pass the Organization's LABEL, not NAME when using this. (equivalent to the deprecated `--skip-foreman` option)
* `puppet` - Does not install puppet (equivalent to the deprecated `--skip-puppet` option)
* `migration` - Skips RHN/Spacewalk registration detection. This option prevents `rhn-classic-migrate-to-rhsm` from timing out and failing on RHN/Spacewalk systems that aren't available.
* `prereq-update` - Skips update of `yum`, `openssl` and `python`
* `katello-agent` - Does not install the `katello-agent` package (DEPRECATED)
* `katello-host-tools` - Does not install the `katello-host-tools` package
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

By default, the bootstrap script uses HTTPS to download the `katello-ca-consumer` RPM. In some environments, it is desired to connect via HTTP. the `--download-method` option can be used to change the download method that bootstrap uses from HTTPS to HTTP.

~~~
./bootstrap.py -l admin \
    -s foreman.example.com \
    -o "Red Hat" \
    -L RDU \
    -g "RHEL7/Crash" \
    -a ak-Reg_To_Crash \
    --download-method http
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


### Configuring Puppet on the client to run only in noop mode

When migrating or registering clients which may have never been managed via Puppet, it may be useful to configure the agent in `noop` mode. This allows the client to be managed via Foreman, while getting facts & reports about its configuration state, without making any changes to it. The `--puppet-noop` switch facilitates this behavior.

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

### Using an alternative Puppet master or Puppet CA

When attaching a client to a setup, where Puppet runs outside of the Foreman setup, you can configure the Puppet agent to use an alternative Puppet master using the `--puppet-server` switch.

~~~
./bootstrap.py -l admin \
    -s foreman.example.com \
    -o "Red Hat" \
    -L RDU \
    -g "RHEL7/Crash" \
    -a ak-Reg_To_Crash \
    --puppet-server=puppet.example.com
~~~

In the case the Puppet CA is running on a different server, you can use the `--puppet-ca-server` switch for the server hostname and the `--puppet-ca-port` one for the port.

~~~
./bootstrap.py -l admin \
    -s foreman.example.com \
    -o "Red Hat" \
    -L RDU \
    -g "RHEL7/Crash" \
    -a ak-Reg_To_Crash \
    --puppet-server=puppet.example.com \
    --puppet-ca-server=puppetca.example.com
~~~

~~~
./bootstrap.py -l admin \
    -s foreman.example.com \
    -o "Red Hat" \
    -L RDU \
    -g "RHEL7/Crash" \
    -a ak-Reg_To_Crash \
    --puppet-server=puppet.example.com \
    --puppet-ca-port=8141
~~~

### Adding a comment when registering a node.

When registering a client, it is sometimes desirable to add a comment, denoting internal information such as the owner of the server or other site-specific info. This can be accomplished with the `--comment` option.

~~~
./bootstrap.py -l admin \
    -s foreman.example.com \
    -o "Red Hat" \
    -L RDU \
    -g "RHEL7/Crash" \
    -a ak-Reg_To_Crash \
    --comment 'Crash Testing Server'
~~~

### Ignoring Registration Failures

When registering a client, it is sometimes desired to ignore registration failures reported via `subscription-manager` or `rhn-migrate-classic-to-rhsm`. The `--ignore-registration-failures` option allows `bootstrap.py` to continue running even when these commands return a non-zero error code. **NOTE**: it is the responsibility of the end-user to ensure, when using this option, that registration has completed successfully.

~~~
./bootstrap.py -l admin \
    -s foreman.example.com \
    -o "Red Hat" \
    -L RDU \
    -g "RHEL7/Crash" \
    -a ak-Reg_To_Crash \
    --ignore-registration-failures
~~~

### Preserving RHSM Proxy Settings

When moving clients from RHSM to Katello or a different RHSM provider, the proxy settings in `/etc/rhsm/rhsm.conf` might get lost. Using `--preserve-rhsm-proxy` you can ensure that the old settings will be restored for the new configuration.


~~~
./bootstrap.py -l admin \
    -s foreman.example.com \
    -o "Red Hat" \
    -L RDU \
    -g "RHEL7/Crash" \
    -a ak-Reg_To_Crash \
    --preserve-rhsm-proxy
~~~

### Installing the Katello agent

Bootstrap no longer defaults to installing the `katello-agent` package. The recommended default is to install the `katello-host-tools` package. If it is desired to install the `katello-agent` package, pass `--install-katello-agent` as a parameter.


~~~
./bootstrap.py -l admin \
    -s foreman.example.com \
    -o "Red Hat" \
    -L RDU \
    -g "RHEL7/Crash" \
    -a ak-Reg_To_Crash \
    --install-katello-agent
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
  --force-content-source
                        Force the content source to be the registration
                        capsule (it overrides the value in the host group if
                        any is defined)
  --content-only        Setup host for content only. Alias to --skip foreman.
                        Implies --skip-puppet. When using --content-only, you
                        MUST pass the Organization's LABEL, not NAME
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
  --puppet-server=PUPPET_SERVER
                        Configure Puppet agent to use this server as master
                        (defaults to the Foreman server)
  --puppet-ca-server=PUPPET_CA_SERVER
                        Configure Puppet agent to use this server as CA
                        (defaults to the Foreman server)
  --puppet-ca-port=PUPPET_CA_PORT
                        Configure Puppet agent to use this port to connect to
                        the CA
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
  --rex-proxies=REMOTE_EXEC_PROXIES
                        Comma separated list of proxies to install Foreman's
                        SSH keys for remote execution.
  --rex-urlkeyfile=REMOTE_EXEC_URL
                        HTTP/S location of a file containing one or
                        more Foreman's SSH keys for remote execution.
  --rex-apikeys         Fetch Foreman's SSH keys from the API.
  --rex-authpath=REMOTE_EXEC_AUTHPATH
                        Full path to local authorized_keys file in order to
                        install Foreman's SSH keys for remote execution.
                        Default ~/.ssh/authorized_keys
  --enablerepos=enablerepos
                        Repositories to be enabled via subscription-manager -
                        comma separated
  --skip=SKIP           Skip the listed steps (choices: ['foreman', 'puppet',
                        'migration', 'prereq-update', 'katello-agent',
                        'remove-obsolete-packages', 'puppet-enable', 'katello-host-tools'])
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
  --new-capsule         Switch the server to a new capsule for content and
                        Puppet. Pass --server with the Capsule FQDN as well.
  -t timeout, --timeout=timeout
                        Timeout (in seconds) for API calls and subscription-
                        manager registration. Defaults to 900
  -c COMMENT, --comment=COMMENT
                        Add a host comment
  --ignore-registration-failures
                        Continue running even if registration via
                        subscription-manager/rhn-migrate-classic-to-rhsm
                        returns a non-zero return code.
  --preserve-rhsm-proxy
                        Preserve proxy settings in /etc/rhsm/rhsm.conf when
                        migrating RHSM -> RHSM
  --install-katello-agent
                        Installs the Katello Agent
~~~

# Additional Notes

## FIPS support

On systems with FIPS enabled (where `/proc/sys/crypto/fips_enabled == 1`), algorithms such as MD5 are disallowed. Bootstrap will configure `digest_algorithm = sha256` in puppet.conf to allow successful puppet runs. However, the signing algorithm **must** match on the Puppet Master. It is expected that the Puppet Masters are configured with the **same** algorithm prior to running `bootstrap.py` on the clients.

# Ansible integration

The `bootstrap.yml` file contains a playbook for [Ansible](https://www.ansible.com/) which can be used to copy `bootstrap.py` to the target machine and execute it there with predefined parameters.

# For developers and contributors:

See  [CONTRIBUTING.md](https://github.com/Katello/katello-client-bootstrap/blob/master/CONTRIBUTING.md)
