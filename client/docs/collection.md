<!---
Licensed under Creative Commons Attribution 4.0 International License
https://creativecommons.org/licenses/by/4.0/
--->

# Contract Collection Files #

**THIS FILE DESCRIBES AN EXPERIMENTAL FACILITY FOR PDO**

Often a contract is meaningful only in the context of other
contracts. For example, an asset issuer contract object may depend
upon an asset type contract object. The type object is necessary to
establish trust in the scope of the asset being issued.

In order to simplify sharing, a contract collection file packages
information about a collection of contracts and their relationship to
each other into a single bundle. The file that is created includes a
context file that describes the relationships between the contracts
and a list of contract description files that can be used to operate
on the contract objects.

## What's the Problem ##

Ultimately, the contract collection file operations are designed to
simplify sharing of complex sets of inter-related contracts.

Currently, context files are the means through which relationships
between contract objects are captured. For example, the following
context file uses context relative links to describe the relationship
between an asset type, a vetting organization, and an asset issuer. In
this case, the blue marble issuer depends on specific asset type and
vetting contract object. That is, many operations on the blue marble
issuer contract object require operations on the corresponding asset
type and vetting contract objects.

```
[marbles.blue.asset_type]
identity = "blue_type"
source = "@{ContractFamily.Exchange.asset_type.source}"
name = "blue marble"
description = "blue marble asset type"
link = "http://"

[marbles.blue.vetting]
identity = "blue_vetting"
source = "@{ContractFamily.Exchange.vetting.source}"
asset_type_context = "@{..asset_type}"

[marbles.blue.issuer]
identity = "blue_issuer"
source = "${ContractFamily.Exchange.issuer.source}"
asset_type_context = "@{..asset_type}"
vetting_context = "@{..vetting}"
```

When the asset type, vetting organization and issuer contracts have
been created, common PDO tools will add a reference to the contract
description file (the `save_file` attribute).

```
[marbles.blue.asset_type]
identity = "blue_type"
source = "@{ContractFamily.Exchange.asset_type.source}"
name = "blue marble"
description = "blue marble asset type"
link = "http://"
save_file = "asset_type_5057b384b77f99cd.pdo"

[marbles.blue.vetting]
identity = "blue_vetting"
source = "@{ContractFamily.Exchange.vetting.source}"
asset_type_context = "@{..asset_type}"
save_file = "vetting_6e3338599072eecd.pdo"

[marbles.blue.issuer]
identity = "blue_issuer"
source = "${ContractFamily.Exchange.issuer.source}"
asset_type_context = "@{..asset_type}"
vetting_context = "@{..vetting}"
save_file = "issuer_contract_6926ae75188c1954.pdo"
```

Contract collection file operations are intended to provide a simple
way to share complete collections of contract object and the
relationships between them.

## Format of the Contract Collection File ##

A contract collection file is a compressed archive that includes a
collection of contract description files and a context file that
describes the relationships between the contract objects in the
description files.

The context file, `context.toml`, is a TOML formatted file that
captures the relative relationships between the contract objects. All
context relative paths (e.g. `@{..vetting}`) must be resolved within
the context defined in `context.toml`. In addition, the context
contains a list of the high level contexts to simplify enumeration of
the objects in the context file.

Each of the contract description files is stored separately in the
bundle. While the operations provided by PDO currently attach unique
identifiers to the file names, ultimately the file names should not be
assumed to be globally unique.

## Export a Contract Collection File ##

The function `export_contract_collection` creates a contract collection file:
```
    export_contract_collection(context, context_paths, contract_cache, export_file)
```

  * **context**: current context
  * **context_paths** : list of path expressions to retrieve values from a context
  * **contract_cache** : name of the directory where contract save files are stored
  * **export_file** : name of the file where the contract family will be written

```python
    export_contract_collection(
        context.get_context('marbles.blue'),
        ['asset_type', 'vetting', 'issuer'],
        '__contract_cache__',
        'blue_marble_collection.zip')
```

## Import a Contract Collection File ##

The function `import_contract_collection` creates a context and save
contract save files from a contract collection file:
```
import_contract_collection(context_file_name, contract_cache, import_file)
```

  * **context_file_name** : name of the file to save imported context
  * **contract_cache** : name of the directory where contract save files are stored
  * **import_file** : name of the contract collection file to import

```python
    import_contract_collection('blue_marble.toml', '__contract_cache__', 'blue_marble_collection.zip')
    context.LoadContextFile(state, bindings, 'blue_marble.toml', prefix='marbles.blue')
```
