<!---
Licensed under Creative Commons Attribution 4.0 International License
https://creativecommons.org/licenses/by/4.0/
--->

# Building Contract Plugins #

The plugins module provides a means to build and use operations that
is independent (as much as possible) of the actual invocation of the
operation. For example, the `mock-contract` plugin wraps the
`inc_value` method in the contract object with an interface so that it
can be invoked as part of a Python script, a pdo-shell script, or a
bash script. Similarly, the `mint_tokens` command may invoke a series
of operations across multiple contract objects in order to mint new
NFT tokens.

There are three general styles of plugins: *contract operations*,
*contract commands* and *scripts*. Loosely, a contract operation wraps
the invocation of a single method on a contract object. Contract
operations are parameterized to interact with a specific contract
object with defaults for enclave service and ledger
connections. Contract commands provide a logical operation that spans
multiple invocations (possibly across multiple contract
objects). Scripts simply provide a useful local function (such as
updating the current configuration). The PDO client library includes a
basic set of scripts that should be sufficient for most uses.

Finally, the plugins module provides a simple way to pass values
between commands and operations to enable more complex scripts. A
command may generate output or it may save a result that other
commands can leverage. The composition becomes useful when writing
complex scripts with multiple commands and operations using Python or
the pdo-shell.

## Plugin Structure ##

While there is no particular need for separating the definition of
contract operations and commands, it is often the case that plugins
are built in parts: a set of operations on a contract object, a
set of commands that implement logical operations that span multiple
invocations on multiple objects, and rarely a set of utility scripts.

The contract operations portion of the plugin defines a set of
objects, derived from the `contract_op_base` class, that each
implement one of the methods on objects of a specific contract
type. Often, these methods are shared with other contract types and
can be "inherited" simply by importing them from another operations
file. For example, the `kv-test` contract defines a `get` method. To
invoke that method, the `kv-test` plugin defines a contract operation
that sets up the invocation of the method on `kv-test` contract
objects.

The contract command portion of the plugin defines a set of commands
that span multiple operations, dervied from the
`contract_command_base` class. For example, provisioning a
`token_issuer` contract object requires two operations to be performed
(`add_endpoint` and `provision_token_issuer`). The `provision` command
executes both of these in one command to simplify interaction with the
`token_issuer` object.

Scripts provide utility functions and are derived from the
`script_command_base` class. Scripts are generally not associated with
contract objects. The PDO client library provides scripts that
simplify configuration of clients and communication with contract
objects.

All plugin classes define two important methods:
* `add_arguments` -- adds commands for processing shell arguments with
  `argparse`; the parameters can be processed through the pdo-shell or
  other command line shells.
* `invoke` -- invokes the operation on the contract object; command
  line parameters that are required should be provided as positional
  arguments and options arguments should be provided as keyword
  arguments.

All three types of plugin operations take the current interpreter
`State` as a parameter to the `invoke` method.  The important
difference between the different operations is that each type takes
unique additional parameters. The `invoke` method in the
`contract_op_base` takes an additional `Session` object with
information about the enclave service connection that should be
used. The `contract_command_base` uses a `Context` object to represent
the configuration of a contract object and its relationship to other
contract objects. Scripts, take no additional parameters beyond the
`State`.

Functionality defined in the pluging can be mapped to a `pdo-shell`
command by defining an entry point and binding it to a command
attribute in the shell class. Each type of operation (contract
operations, contract commands and scripts) has a class-specific
generator that creates a function for the shell,
`create_shell_command`. The generated commands can be mapped into the
`pdo-shell` using `bind_shell_command`.

## Base Classes ##

### State ###

Implements the client and contract configuration as a multi-tiered
dictionary with a few special twists.

State is, in a sense, the root of all other classes. The current
context and set of bindings are stored in state.

The primary methods for state allow for direct lookup using a list of
keys (`get`) and an "intelligent" lookup that examines the entries to
look for special values (`expand`). There are two forms of special
values in state: links and substitutions. A link (a state value that
begins with '@') expands to the value of the referenced state entry
including all of the structure. A substituion (begins with '$')
expands to a string value.

### Bindings ###

Implements a simple variable store for `pdo-shell` and Python
scripts. A value may be bound to a variable and a variable may be
expanded into the corresponding value. This is generally done through
the `${var}` syntax in the `pdo-shell` though it also happens during
the loading of configuration files.

When the `pdo-shell` invokes an operation through a script invocation,
a new binding is created through the `Clone` operation. All variables
*except* those that start with `_` will be copied into the new
Binding. That is, you may consider variables that begin with `_` as
variables local to a particular script.

Upon return from a script invocation, the value of all variables will
be copied into the calling environment except those variables that
begin with `_`.

Bindings are most often used to pass settings into a script, to
communicate the results of a script to the calling context, and for
saving temporary values that can be passed to other operations.

The initial set of bindings is created from the `Bindings` value in
state (which generally comes from the `Bindings` field in the
configuration file.

### SessionParameters ###

Captures the parameters for interacting with a specific contract. This
includes information about the contract (the contract save file) and
the preferred eservice for interacting with the contract.

Properties include:
* `eservice_url` -- Enclave service to use for all operations
* `save_file` -- Name of the file where contract information is
  stored, i.e. name of the contract object
* `wait` -- Default value for the `wait` parameter to contract
  invocations, may be overridden for a specific invocation
* `commit` -- Default value for the `commit` parameter to contract
  invocations, may be overridden for a specific invocation

Methods include:
* `clone` -- Create a new copy of the session, parameters may be overridden

### Context ###

Rather than having a separate file for each contract, we can specify
defaults like identity, contract source, plugin module within a
configuration file. The Context class provides an abstraction for
storing that information.

Frequently, a contract family will provide context templates that can
be instantiated (using `pdo-context`) for specific contract
objects. For example, the Exchange contract family defines the
relationships between types of assets and issuers of those assets. The
context templates simplify the configuration of a suite of contract
objects necessary to create a new asset issuer.
