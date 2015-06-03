# Satellite 6 Bootstrap Script
Bootstrap Script for migrating systems to Red Hat Satellite 6

# Overview 

* The goal is to take a RHEL client, registered to Classic or Satellite 5,
and get it registered to Satellite 6

# What does the Script do?

* Installing subscription-manager and its pre-reqs (updated yum & openssl)
* Install the candlepin consumer RPM
* Running rhn-migrate-classic-to-rhsm to get product certs on a system
* registering the system to Satellite 6
* Configuring the system with a proper puppet configuration pointing
  at a Satellite
* Removing/disabling old RHN Classic packages/daemons (rhnsd, osad, etc)
* Associating the system with the correct Organization and Location

# Assumptions

* The script will use only components that are present on all RHEL
  installations. We will not install additional packages, other than
those explicitly required for Satellite 6 management, on the client
system.  (i.e., I could have used the python-requests module to make the
API calls a lot more pleasant, but I couldn't justify the dependencies)
* During the migration, the system will be registered to a Content View
  which provides the RH Common / Satellite Tools repo.
* The system in question has python.
* Autosigning is enabled for the system in question.  (And be careful,
  auto-signing isnt one of those things you'd leave enabled forever)
* The system is registered to Classic or Satellite 5 (I have to install
packages before we attempt to migrate the systems)

# User required inputs

* Hostname of Satellite 6 and/or Capsule
* username of user with privileges to add new hosts on Satellite
* password of the aforementioned user.
* Location and Organization that the system is to be associated with.
* hostgroup that the client is to be associated with.

# Known issues

Known Issues:

* rhn-migrate-classic-to-rhsm requires a username to leave RHN classic
  bz1180273
* rhn-migrate-classic-to-rhsm doesn't support activation keys
  bz1154375
* Because of these Bugzillas, I have to prompt in the middle of the
script for credentials

Usage:

~~~
# ./bootstrap.py -l admin -s satellite.example.com -o Default_Organization -L Default_Location -g My_Hostgroup
~~~


