# Satellite 6 Bootstrap Script
Bootstrap Script for migrating systems to Red Hat Satellite 6

# Overview 

* The goal is to take a RHEL client and get it registered to Satellite 6. 
This script can take a system that is registered to Satellite 5, Red Hat
Network Classic and get it registered to Satellite 6.

# What does the Script do?

* Identify which systems management platform is the system registered to (Classic/Sat5 or None)  then perform the following

## Red Hat Classic & Satellite 5

* Installing subscription-manager and its pre-reqs (updated yum & openssl)
* Make an API to Satellite to create the Foreman Host associated with the user specified Org/Location
* Install the candlepin consumer RPM
* Running rhn-migrate-classic-to-rhsm (with the user provided activation key) to get product certs on a system
* registering the system to Satellite 6
* Configuring the system with a proper puppet configuration pointing
  at a Satellite
* Removing/disabling old RHN Classic packages/daemons (rhnsd, osad, etc)

## System not registered to any Red Hat Systems Management Platform:

* Make an API to Satellite to create the Foreman Host associated with the user specified Org/Location
* Install the candlepin consumer RPM
* Running subscription-manager (with the user provided activation key) to register the system. 
* Configuring the system with a proper puppet configuration pointing
  at a Satellite
* Removing/disabling old RHN Classic packages/daemons (rhnsd, osad, etc)

# Assumptions

* The script will use only components that are present on all RHEL
  installations. We will not install additional packages, other than
those explicitly required for Satellite 6 management, on the client
system.  (i.e., I could have used the python-requests module to make the
API calls a lot more pleasant, but I couldn't justify the dependencies)
* The activation key that is provide provides access to a Content View
  which provides the Satellite Tools repo.
* The system in question has python.
* The administrator can approve puppet certificates if using Puppet. 
  Alternatively, autosigning can be enabled for the system in question.  (And be careful,
  auto-signing isnt one of those things you'd leave enabled forever)

# User required inputs

* Hostname of Satellite 6 and/or Capsule
* username of user with privileges to add new hosts on Satellite via the API
* password of the aforementioned user.
* Location and Organization that the system is to be associated with.
* hostgroup that the client is to be associated with.
* An Activation Key that provides a content view with the Satellite Tools repo. 


# Usage:

~~~
# ./bootstrap.py -l admin \
  -s satellite.example.com \
  -o Default_Organization \
  -L Default_Location \
  -g My_Hostgroup \
  -a My_Activation_Key
~~~

# Help / Available options:

~~~
./bootstrap.py -h
Usage: bootstrap.py [options]

Options:
  -h, --help            show this help message and exit
  -s SAT6_FQDN, --server=SAT6_FQDN
                        FQDN of Satellite OR Satellite Capsule - omit https://
  -l LOGIN, --login=LOGIN
                        Login user for API Calls
  -p PASSWORD, --password=PASSWORD
                        Password for specified user. Will prompt if omitted
  -a ACTIVATIONKEY, --activationkey=ACTIVATIONKEY
                        Activation Key to register the system
  -P, --skip-puppet     Do not install Puppet
  -g HOSTGROUP, --hostgroup=HOSTGROUP
                        Label of the Hostgroup in Satellite that the host is
                        to be associated with
  -L HOSTGROUP, --location=HOSTGROUP
                        Label of the Location in Satellite that the host is to
                        be associated with
  -o ORG, --organization=ORG
                        Label of the Organization in Satellite that the host
                        is to be associated with
  -S ARGS, --subscription-manager-args=ARGS
                        Which additional arguments shall be passed to
                        subscription-manager
  -u, --update          Fully Updates the System
  -v, --verbose         Verbose output
  -f, --force           Force registration (will erase old katello and puppet
                        certs)
  -r RELEASE, --release=RELEASE
                        Specify release version
  -R, --remove-rhn-packages
                        Remove old Red Hat Network Packages
~~~



