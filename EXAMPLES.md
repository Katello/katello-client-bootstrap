## Example usages of bootstrap.py


### Registering a system to Foreman + Katello

This is one of the most standard workflows with bootstrap.py. This sets up the system for content / configuration (via puppet) & provisioning.
~~~
# ./bootstrap.py -l admin \
    -s satellite.example.com \
    -o "Red Hat" \
    -L RDU \
    -g "RHEL7/Crash" \
    -a ak-Reg_To_Crash
~~~

### Registering a system to Foreman + Katello, omitting puppet setup.

There are times where you wish to not install puppet, perhaps you have a differing or existing configuration management system.

~~~
# ./bootstrap.py -l admin \
    -s satellite.example.com \
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
# ./bootstrap.py -s satellite.example.com \
    -a ak_Reg_To_Dev_EL7 \
    -o "Red_Hat" \
    --skip-foreman
~~~
