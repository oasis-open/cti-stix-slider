​Conversion Issues
=====================

Single vs. Multiple
-------------------------

Some properties in STIX 2.x allowed for multiple values, but the
corresponding property in STIX 1.x does not. In these cases, the first
value is used and a warning message is output.

Related-To Relationships
-------------------------

It is assumed that all ``related-to`` relationship between the same type of object should be used to refer to
self-referencing STIX 1.x relationships.
For instance a ``related-to`` relationship between two ``threat-actor`` objects will be used to populate the STIX 1.x
``AssociatedActors`` property.

Other ``related-to`` relationships will be ignored and a warning message will be displayed.

Data Markings
--------------

The stix-slider currently supports object-level markings only. Granular markings are ignored and a warning message will be displayed.
Since that is the highest level of data marking available in STIX 2.x,
any object downgraded will contain embedded object-level markings in their STIX 1.X representation regardless of
using the same marking definition in multiple places. Therefore, it can result in a verbose output compared to its 2.X counterpart.
The marking-definition objects will be placed in the STIX_Header
section of the document.

The supported marking types are: TLP, Statement and AIS.

Kill Chains
-------------

Kill chains and their phases in STIX 2.x are referred to by their names.  There is no ``id`` associated with a kill chain phase.
Additionally, kill chains are not defined within STIX 2.x content.  The assumption is that if a kill chain is known among those
sharing content, the names will be sufficient to identify them consistently.  According to the STIX 2.x specification,
if the Lockheed Martin Cyber Kill Chain™ is used the ``kill_chain_name`` will be ``lockheed-martin-cyber-kill-chain``.

Because kill chains need to be explicitly defined within the STIX 1.x content, each kill chain phase found in the STIX 2.x content will
be used to partially construct a kill chain definition.  For this reason, the resultant kill chain will only contain the kill chain phases used.

Versioning
-------------

Both STIX 1.x and STIX 2.x support the versioning of objects, but there is no attempt
by the slider to explicitly maintain versioning information when converting to STIX 1.x.

All converted objects will be assumed to be the one and only version of an object. If more than one object is found with
the same id, it will *not* be flagged as an error.