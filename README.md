# Foreman Bootstrap Script
Bootstrap Script for migrating existing running systems to Foreman with the Katello plugin

# Overview

* The goal is to take a RHEL client and get it registered to Foreman
This script can take a system that is registered to Spacewalk, Satellite 5, Red Hat
Network Classic and get it registered to Foreman & Katello.

# What does the Script do?

* Identify which systems management platform is the system registered to (Classic/Sat5 or None)  then perform the following

## Red Hat Classic & Satellite 5

* Installing subscription-manager and its pre-reqs (updated yum & openssl)
* Make an API call to Katello to create the Foreman Host associated with the user specified Org/Location
* Install the Katello consumer RPM
* Running rhn-migrate-classic-to-rhsm (with the user provisded activation key) to get product certs on a system
* registering the system to Foreman
* Configuring the system with a proper puppet configuration pointing at Foreman
* Removing/disabling old RHN Classic packages/daemons (rhnsd, osad, etc)

## System not registered to any Red Hat Systems Management Platform:

* Make an API call to Foreman to create the Foreman Host associated with the user specified Org/Location
* Install the Katello consumer RPM
* Running subscription-manager (with the user provided activation key) to register the system.
* Configuring the system with a proper puppet configuration pointing at Foreman
* Removing/disabling old RHN Classic packages/daemons (rhnsd, osad, etc)

# Assumptions

* The script will use only components that are present on all RHEL
  installations. We will not install additional packages, other than
  those explicitly required for Katello management, on the client
  system.  (i.e., I could have used the python-requests module to make the
  API calls a lot more pleasant, but I couldn't justify the dependencies)
* The system in question has python.
* The administrator can approve puppet certificates if using Puppet.
  Alternatively, autosigning can be enabled for the system in question.  (And be careful,
  auto-signing isnt one of those things you'd leave enabled forever)
* The Foreman instance is properly prepared and is able to provision systems,
  especially the following is true:
  * The activation key provides access to a Content View
    which provides Puppet and other client side tooling.
  * The domain of the system is known to Foreman.
  * The hostgroup has the "Host Group" and "Operating System" tabs filled out completelly.
* Puppet Enterprise product has been create, with repos synchronized from PE server
  * PE repos should follow the naming convention: el7-pe-x86_64

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


# Usage:

~~~
# ./bootstrap.py -l admin \
  -s foreman.example.com \
  -o 'Default Organization' \
  -L 'Default Location' \
  -g My_Hostgroup \
  -a My_Activation_Key
~~~

# Help / Available options:

~~~
./bootstrap.py -h
Usage: bootstrap.py [options]

Options:
  -h, --help            show this help message and exit
  -s foreman_fqdn, --server=foreman_fqdn
                        FQDN of Foreman OR Capsule - omit https://
  -l LOGIN, --login=LOGIN
                        Login user for API Calls
  -p PASSWORD, --password=PASSWORD
                        Password for specified user. Will prompt if omitted
  --legacy-login=LOGIN  Login user for Satellite 5 API Calls
  --legacy-password=PASSWORD
                        Password for specified Satellite 5 user. Will prompt
                        if omitted
  --legacy-purge        Purge system from the Legacy environment (e.g. Sat5)
  -a ACTIVATIONKEY, --activationkey=ACTIVATIONKEY
                        Activation Key to register the system
  -P, --skip-puppet     Do not install Puppet
  --skip-foreman        Do not create a Foreman host. Implies --skip-puppet.
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
                        Name of the Operating System in Foreman that the host
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
  --remove              Instead of registring the machine to Foreman remove it
  -r RELEASE, --release=RELEASE
                        Specify release version
  -R, --remove-rhn-packages
                        Remove old Red Hat Network Packages
  --unmanaged           Add the server as unmanaged. Useful to skip
                        provisioning dependencies.
  --rex                 Install Foreman's SSH key for remote execution.
  --rex-user=REMOTE_EXEC_USER
                        Local user used by Foreman's remote execution feature.
~~~
