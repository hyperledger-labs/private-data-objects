<!---
Licensed under Creative Commons Attribution 4.0 International License
https://creativecommons.org/licenses/by/4.0/
--->

# Service Groups #

Service groups provide a means to simplify and reuse specification of
services, resources and policies for creating new contracts.

Contract creation requires specification of enclave, provisioning, and
storage services; preferred or optimized services; and storage and
replication policies. Rather than provide the information separately
for every contract created, service groups define collections of
services and policies for using those services that can be used to
simplify contract creation.  For example, a service group for testing
and developing new contracts can be created from services provided
locally. Another group can be defined to for final deployment.

Service groups can be easily defined for all of the services
associated with a given site (see the various `create_from_site`
subcommands below). They can also be created for services provided by
multiple sites (for greater resiliency and availability).

All service groups have a name and a list of services (generally
represented by the names or URLs for the services defined in the
service endpoint database). Each type of service group (`eservice`,
`pservice`, and `sservice`) has additional unique attributes that
describe policies that accompany the group. For example, enclave
services have a preferred service that identifies a place more likely
to have contract state pre-cached.

While the name space for each type of service group is independent
(that is, you can have an enclave service group with the same name as
a provisioning service group), for convenience we often use the same
name for groups of different types when we use them together. For
example, we may name enclave, provisioning and storage service groups
`develop` because we always use them together for contract
development.

While groups can be specified for any operation that creates a
contract, if no group is specified, then a group called 'default' will
be used. That group must be created.

**NOTE:** Services included in service groups must be stored in the
service endpoint database (see `pdo-service-db` command). Generally
this means that service endpoint must be added (usually by importing a
site configuration file) before groups can be created.

## Service Groups Data File ##

Service group information is stored in a database file identified by
the configuration variable `Service.GroupDatabaseFile` which defaults
to `${PDO_HOME}/data/groups_db.mdb`. Command line switches allow for
the use of alternative group files.

## Commands for Working with Service Groups ##

### Service Groups: `pdo-service-groups` ###

The `pdo-service-groups` command provides operations over the collection
of services in the service groups database.

* `clear` : remove all data from the service groups database
* `import` : import service group definitions from a file
* `export` : export service group definitions to a file
* `list` : list service groups of a service type
* `info` : provide detailed information about a group

### Enclave Service Groups

The `pdo-eservice` command provides operations to create, delete and
modify groups of enclave services. In addition to a list of services,
`eservice` groups include a preferred service that serves as a default
location for operating on the contract. If the preferred service is
`random`, then a different `eservice` will be chosen for each
operation.

* `create` : create a new service group
* `create_from_site` : add all of the services in a site file to a service group, creating it if it does not yet exist
* `delete` : remove a service group from the database
* `add` : add services to the service group
* `remove` : remove services from the service group
* `set` : replace the current list of services with a new list
* `use` : select a service for the preferred service

### Provisioning Service Groups

The `pdo-pservice` command provides operations to create, delete and
modify groups of provisioning services. Provisioning service groups do
not have any additional policies.

* `create` : create a new service group
* `create_from_site` : add all of the services in a site file to a service group, creating it if it does not yet exist
* `delete` : remove a service group from the database
* `add` : add services to the service group
* `remove` : remove services from the service group
* `set` : replace the current list of services with a new list

### Storage Service Groups

The `pdo-sservice` command provides operations to create, delete and
modify groups of storage services. Storage service groups have three
additional policy parameters that may be set: `replicas` specifies the
minimum number of replicas required for state, `duration` specifies
the minimum availability duration for each replica, and `persistent`
identifies a storage service where users can expect to find state
after the replication duration has expired.

* `create` : create a new service group
* `create_from_site` : add all of the services in a site file to a service group, creating it if it does not yet exist
* `delete` : remove a service group from the database
* `add` : add services to the service group
* `remove` : remove services from the service group
* `set` : replace the current list of services with a new list
* `use` : specify replication and availability policies

## Pattern for Adding a New Site ##

Assuming we have been given a site file, `host1.example.org.toml`,
that contains information about services available from `example.org`,
we can import the services and create groups that for all of the
services with the following commands:

```bash
$> pdo-service-db import --file host1.example.org.toml
$> pdo-eservice create_from_site --file host1.example.org.toml --group example.org/all --preferred random
$> pdo-pservice create_from_site --file host1.example.org.toml --group example.org/all
$> pdo-sservice create_from_site --file host1.example.org.toml --group example.org/all --persistent http://host1.example.org:7201
```

## Formats ##

### Import/Export Format ###

Import and export operations act on a [TOML](https://toml.io/en/)
configuration file. The file contains three top level tables labelled
'EnclaveServiceGroups', 'ProvisioningServiceGroups' and
'StorageServiceGroups'. Each top level table contains a list of
tables, identified by the group name, that contain detailed
information about the groups.

```toml
[EnclaveServiceGroups."host1/all"]
service_type = "eservice"
urls = [ "http://host1.example.org:7102", "http://host1.example.org:7105", "http://host1.example.org:7103", "http://host1.example.org:7104", "http://host1.example.org:7101",]
preferred = "random"

[ProvisioningServiceGroups."host1/all"]
service_type = "pservice"
urls = [ "http://host1.example.org:7004", "http://host1.example.org:7003", "http://host1.example.org:7002", "http://host1.example.org:7001", "http://host1.example.org:7005",]

[StorageServiceGroups."host1/all"]
service_type = "sservice"
urls = [ "http://host1.example.org:7204", "http://host1.example.org:7202", "http://host1.example.org:7205", "http://host1.example.org:7201", "http://host1.example.org:7203",]
replicas = 2
duration = 120
persistent = "http://host1.example.org:7201"
```
