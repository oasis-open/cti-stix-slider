Mappings from STIX 1.x to STIX 2.0
=======================================

This section outlines the disposition of each property for the top-level objects when converted.

For each STIX 2.0 object that was converted the following options are possible:

 - **STIX 2.0 property mapped directly to a STIX 1.x property.**  This property's value is used unaltered in the conversion to 2.0.
 - **STIX 2.0 property translated into STIX 1.x property.**  This property's value must undergo some minor processing to determine the
   corresponding content for 1.x.
 - **STIX 2.0 relationship mapped using STIX 1.x property.** This 2.0 relationship object is used to construct an embedded STIX 1.x relationship.
   If the STIX 2.0 ``relationship-type`` is not listed below, then that relationship will not be converted to an embedded STIX 1.x relationship.
   The "reverse" notation indicates the the STIX 1.x property is found on target object.
 - **STIX 2.0 property recorded in the STIX 1.x description property.**  This 2.0 property has no corresponding property in STIX 1.x, but its value
   can be (optionally) included in the description property of the 1.x object as text.  If the STIX 2.0 content was created using the elevator
   it might be the case that it recorded some 1.x properties in the description.  However, the slider makes no attempt to examine the content of
   the 2.0 descriptor property to determine if it can use information found within it to populate the original 1.x properties.
 - **STIX 2.0 property not mapped.**  This property will not be included in the converted 1.x object.

Top Level Object Mappings
-------------------------------

+-------------------------+---------------------------+
| **STIX 2.0 object**     | **STIX 1.x object**       |
+=========================+===========================+
| ``attack-pattern``      | ``ttp:Attack_Pattern``    |
+-------------------------+---------------------------+
| ``bundle``              | ``Package``               |
+-------------------------+---------------------------+
| ``campaign``            | ``Campaign``              |
+-------------------------+---------------------------+
| ``course-of-action``    | ``Course_Of_Action``      |
+-------------------------+---------------------------+
| ``identity``            | ``Information_Source`` or |
|                         | ``ttp:Victim_Targeting``  |
+-------------------------+---------------------------+
| ``indicator``           | ``Indicator``             |
+-------------------------+---------------------------+
| ``intrusion-set``       | *not converted*           |
+-------------------------+---------------------------+
| ``observed-data``       | ``Observable``            |
+-------------------------+---------------------------+
| ``malware``             | ``ttp:MalwareInstance``   |
+-------------------------+---------------------------+
| ``report``              | ``Report``                |
+-------------------------+---------------------------+
| ``threat-actor``        | ``Threat Actor``          |
+-------------------------+---------------------------+
| ``tool``                | ``ttp:Tool``              |
+-------------------------+---------------------------+
| ``vulnerability``       | ``et:Vulnerability``      |
+-------------------------+---------------------------+

Common Properties
------------------------

**STIX 2.0 Properties Mapped Directly to STIX 1.x Properties**

+-------------------------+------------------------------------+
| **STIX 2.0 property**   | **STIX 1.x property**              |
+=========================+====================================+
| ``created``             | *not converted* (see ``modified``) |
+-------------------------+------------------------------------+
| ``description``         | ``Description``                    |
+-------------------------+------------------------------------+
| ``id``                  | ``id``                             |
+-------------------------+------------------------------------+
| ``modified``            | ``timestamp``                      |
+-------------------------+------------------------------------+
| ``name``                | ``Title``                          |
+-------------------------+------------------------------------+

**STIX 2.0 Properties Translated to STIX 1.x Properties**

+-------------------------+--------------------------------------------------------------------------------------+
| **STIX 2.0 property**   | **STIX 1.x property**                                                                |
+=========================+======================================================================================+
| ``type``                | *implicitly defined by its element name or explicitly using xsi:type*                |
+-------------------------+--------------------------------------------------------------------------------------+
| ``created_by_ref``      | ``Information_Source``                                                               |
+-------------------------+--------------------------------------------------------------------------------------+
| ``external_references`` | ``Information_Source``,                                                              |
|                         | ``et:Vulnerability.cve_id``,                                                         |
|                         | ``ttp:Attack_Patterns.capec.id``                                                     |
+-------------------------+--------------------------------------------------------------------------------------+
| ``object_markings_refs``| ``Handling``                                                                         |
+-------------------------+--------------------------------------------------------------------------------------+
| ``granular_markings``   | ``Handling``                                                                         |
+-------------------------+--------------------------------------------------------------------------------------+

**STIX 2.0 Relationships Mapped Using STIX 1.x Relationships**

*none*

**STIX 2.0 Properties Recorded in the STIX 1.x Description Property**

*none*

**STIX 2.0 Properties Not Mapped**

- ``revoked``

Attack Pattern
------------------


**STIX 2.0 Properties Mapped Directly to STIX 1.x Properties**

*none*

**STIX 2.0 Properties Translated to STIX 1.x Properties**

+---------------------------+-------------------------------------------------------------------+
| **STIX 2.0 property**     | **STIX 1.x property**                                             |
+===========================+===================================================================+
| ``external_references``   | ``capec_id``                                                      |
+---------------------------+-------------------------------------------------------------------+
| ``kill_chain_phases``     | ``ttp:Kill_Chain_Phases``                                         |
+---------------------------+-------------------------------------------------------------------+

**STIX 2.0 Relationships Mapped Using STIX 1.x Relationships**

+------------------------------------------------+----------------------------+
| **STIX 2.0 relationship type**                 | **STIX 1.x property**      |
+================================================+============================+
| ``targets`` (identity only)                    |  ``ttp:Victim_Targeting``  |
+------------------------------------------------+----------------------------+
| ``targets`` (vulnerability only)               |  ``ttp:Exploit_Targets``   |
+------------------------------------------------+----------------------------+
|  ``uses`` (malware, tool)                      | ``ttp:Related_TTPs``       |
+------------------------------------------------+----------------------------+

**STIX 2.0 Properties Recorded in the STIX 1.x Description Property**

- ``labels``

**STIX 2.0 Properties Not Mapped**

*none*

**An Example**

STIX 2.0 in JSON

.. code-block:: json

    {
      "type": "attack-pattern",
      "id": "attack-pattern--19da6e1c-71ab-4c2f-886d-d620d09d3b5a",
      "created": "2016-08-08T15:50:10.983Z",
      "modified": "2017-01-30T21:15:04.127Z",
      "external_references": [
        {
          "external_id": "CAPEC-148",
          "source_name": "capec",
          "url": "https://capec.mitre.org/data/definitions/148.html"
        }
      ],
      "name": "Content Spoofing"
    }

STIX 1.x in XML

.. code-block:: xml

    <stix:TTP id="example:ttp-19da6e1c-71ab-4c2f-886d-d620d09d3b5a" timestamp="2017-01-30T21:15:04.127000+00:00" xsi:type='ttp:TTPType'>
        <ttp:Behavior>
            <ttp:Attack_Patterns>
                <ttp:Attack_Pattern capec_id="CAPEC-148">
                    <ttp:Title>Content Spoofing</ttp:Title>
                </ttp:Attack_Pattern>
            </ttp:Attack_Patterns>
        </ttp:Behavior>
        <ttp:Information_Source>
            <stixCommon:References>
                <stixCommon:Reference>SOURCE: capec - https://capec.mitre.org/data/definitions/148.html</stixCommon:Reference>
            </stixCommon:References>
        </ttp:Information_Source>
    </stix:TTP>

Campaigns
----------------

**STIX 2.0 Properties Mapped Directly to STIX 1.x Properties**

+-------------------------+------------------------+
| **STIX 2.0 property**   | **STIX 1.x property**  |
+=========================+========================+
| ``aliases``             | ``Names``              |
+-------------------------+------------------------+
| ``objective``           | ``Intended_Effect``    |
+-------------------------+------------------------+

**STIX 2.0 Properties Translated to STIX 1.x Properties**

*none*

**​STIX 2.0 Relationships Mapped Using STIX 1.x Relationships**

+----------------------------------------------+----------------------------------------------+
| **STIX 2.0 relationship type**               | **STIX 1.x property**                        |
+==============================================+==============================================+
| ``uses``                                     | ``Related_TTPs``                             |
+----------------------------------------------+----------------------------------------------+
| ``indicates`` (reverse)                      | ``Related_Indicators``                       |
+----------------------------------------------+----------------------------------------------+
| ``attributed-to``                            | ``Attribution``                              |
+----------------------------------------------+----------------------------------------------+
| ``related-to`` (campaign)                    | ``Associated_Campaigns``                     |
+----------------------------------------------+----------------------------------------------+

**STIX 2.0 Properties Recorded in the STIX 1.x Description Property**

-  ``first_seen``
-  ``last_seen``
-  ``label``

**STIX 2.0 Properties Not Mapped**

*none*

**An Example**

STIX 2.0 in JSON

.. code-block:: json

    {
            "created": "2014-08-08T15:50:10.983Z",
            "description": "Attacking ATM machines in the Eastern US",
            "external_references": [
                {
                    "source_name": "ACME",
                    "url": "http://foo.com/bar"
                },
                {
                    "source_name": "wikipedia",
                    "url": "https://en.wikipedia.org/wiki/Automated_teller_machine"
                },
                {
                    "source_name": "ACME Bugzilla",
                    "external_id": "1370",
                    "url": "https://www.example.com/bugs/1370"
                }
            ],
            "id": "campaign--e5268b6e-4931-42f1-b379-87f48eb41b1e",
            "modified": "2014-08-08T15:50:10.983Z",
            "name": "Compromise of ATM Machines",
            "type": "campaign"
    }

STIX 1.x in XML

.. code-block:: xml

    <stix:Campaign id="example:campaign-e5268b6e-4931-42f1-b379-87f48eb41b1e" timestamp="2014-08-08T15:50:10.983000+00:00" xsi:type='campaign:CampaignType'>
            <campaign:Title>Compromise of ATM Machines</campaign:Title>
            <campaign:Description>Attacking ATM machines in the Eastern US</campaign:Description>
            <campaign:Information_Source>
                <stixCommon:References>
                    <stixCommon:Reference>SOURCE: ACME - http://foo.com/bar</stixCommon:Reference>
                    <stixCommon:Reference>SOURCE: wikipedia - https://en.wikipedia.org/wiki/Automated_teller_machine</stixCommon:Reference>
                    <stixCommon:Reference>SOURCE: ACME Bugzilla - https://www.example.com/bugs/1370</stixCommon:Reference>
                    <stixCommon:Reference>SOURCE: ACME Bugzilla - EXTERNAL ID: 1370</stixCommon:Reference>
                </stixCommon:References>
            </campaign:Information_Source>
        </stix:Campaign>

Course of Action
----------------------

In STIX 2.0 the course-of-action object is defined as a stub. This means that in STIX
2.0 this object type is pretty "bare-bones", not containing most of the
properties that were found in STIX 1.x.


**STIX 2.0 Properties Mapped Directly to STIX 1.x Properties**

*none*

**STIX 2.0 Properties Translated to STIX 1.x Properties**

+-------------------------+------------------------+
| **STIX 2.0 property**   | **STIX 1.x property**  |
+=========================+========================+
| ``labels``              | ``Type``               |
+-------------------------+------------------------+

**STIX 2.0 Relationships Mapped Using STIX 1.x Relationships**

+----------------------------------------------+----------------------------------------------+
| **STIX 2.0 relationship type**               | **STIX 1.x property**                        |
+==============================================+==============================================+
| ``related-to`` (course-of-action)            | ``Related_COAs``                             |
+----------------------------------------------+----------------------------------------------+

**STIX 2.0 Properties Recorded in the STIX 1.x Description Property**

*none*

**STIX Properties Not Mapped**

*none*

**An Example**

STIX 2.0 in JSON

.. code-block:: json

    {
            "created": "2017-01-27T13:49:41.298Z",
            "description": "\n\nSTAGE:\n\tResponse\n\nOBJECTIVE: Block communication between the PIVY agents and the C2 Server\n\nCONFIDENCE: High\n\nIMPACT:LowThis IP address is not used for legitimate hosting so there should be no operational impact.\n\nCOST:Low\n\nEFFICACY:High",
            "id": "course-of-action--495c9b28-b5d8-11e3-b7bb-000c29789db9",
            "labels": [
                "perimeter-blocking"
            ],
            "modified": "2017-01-27T13:49:41.298Z",
            "name": "Block traffic to PIVY C2 Server (10.10.10.10)",
            "type": "course-of-action"
    }

STIX 1.x in XML

.. code-block:: xml

    <stix:Course_Of_Action id="example:course-of-action-495c9b28-b5d8-11e3-b7bb-000c29789db9" timestamp="2017-01-27T13:49:41.298000+00:00" xsi:type='coa:CourseOfActionType'>
                <coa:Title>Block traffic to PIVY C2 Server (10.10.10.10)</coa:Title>
                <coa:Type xsi:type="stixVocabs:CourseOfActionTypeVocab-1.0">Perimeter Blocking</coa:Type>
                <coa:Description>
                    STAGE:
                        Response
                    OBJECTIVE: Block communication between the PIVY agents and the C2 Server
                    CONFIDENCE: High
                    IMPACT:LowThis IP address is not used for legitimate hosting so there should be no operational impact.
                    COST:Low
                    EFFICACY:High
                </coa:Description>
    </stix:Course_Of_Action>


Indicator
------------------


**STIX 2.0 Properties Mapped Directly to STIX 1.x Properties**

+-----------------------------------+---------------------------+
| **STIX 2.0 property**             | **STIX 1.x property**     |
+===================================+===========================+
|  ``valid_from``, ``valid_until``  | ``Valid_Time_Position``   |
+-----------------------------------+---------------------------+
| ``created_by_ref``                | ``Producer``              |
+-----------------------------------+---------------------------+

**STIX 2.0  Properties Translated to STIX 1.x Properties**

+-------------------------+---------------------------------------------+
|**STIX 2.0 property**    | **STIX 1.x property**                       |
+=========================+=============================================+
| ``kill_chain_phases``   | ``Kill_Chain_Phases``                       |
+-------------------------+---------------------------------------------+
| ``pattern``             | ``IndicatorExpression``                     |
+-------------------------+---------------------------------------------+
| ``labels```             | ``Type``                                    |
+-------------------------+---------------------------------------------+

**STIX 2.0 Relationships Mapped Using STIX 1.x Relationships**

+----------------------------------------------+-----------------------+
| **STIX 2.0 relationship type**               | **STIX 1.x property** |
+==============================================+=======================+
| ``detects``                                  | ``Indicated_TTP``     |
+----------------------------------------------+-----------------------+
| ``indicates`` (campaign)                     | ``Related_Campaigns`` |
+----------------------------------------------+-----------------------+
| ``indicates`` (attack-pattern, malware, tool)| ``Indicated_TTPs``    |
+----------------------------------------------+-----------------------+
| ``related-to`` (indicator)                   | ``Related_Indicators``|
+----------------------------------------------+-----------------------+

**STIX 2.0 Properties Recorded in the STIX 1.x Description Property**

*none*

**STIX 2.0 Properties Not Mapped**

*none*

**An Example**

STIX 2.0 in JSON

.. code-block:: json

    {
            "created": "2014-05-08T09:00:00.000Z",
            "id": "indicator--53fe3b22-0201-47cf-85d0-97c02164528d",
            "labels": [
                "ip-watchlist"
            ],
            "modified": "2014-05-08T09:00:00.000Z",
            "name": "IP Address for known C2 channel",
            "pattern": "[ipv4-addr:value = '10.0.0.0']",
            "type": "indicator",
            "valid_from": "2014-05-08T09:00:00.000000Z"
    }

    {
            "created": "2014-05-08T09:00:00.000Z",
            "id": "relationship--9606dac3-965a-47d3-b270-8b17431ba0e4",
            "modified": "2014-05-08T09:00:00.000Z",
            "relationship_type": "indicates",
            "source_ref": "indicator--53fe3b22-0201-47cf-85d0-97c02164528d",
            "target_ref": "malware--73fe3b22-0201-47cf-85d0-97c02164528d",
            "type": "relationship"
        }

STIX 1.x in XML

.. code-block:: xml

    <stix:Indicator id="example:indicator-53fe3b22-0201-47cf-85d0-97c02164528d" timestamp="2014-05-08T09:00:00+00:00" xsi:type='indicator:IndicatorType'>
            <indicator:Title>IP Address for known C2 channel</indicator:Title>
            <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">IP Watchlist</indicator:Type>
            <indicator:Valid_Time_Position>
                <indicator:Start_Time precision="second">2014-05-08T09:00:00+00:00</indicator:Start_Time>
            </indicator:Valid_Time_Position>
            <indicator:Observable id="example:Observable-9f9e8592-1a3a-42f0-8e16-56c062671a5c">
                <cybox:Object id="example:Address-3923ec77-e675-4db7-b2bb-8c42717b2b3a">
                    <cybox:Properties xsi:type="AddressObj:AddressObjectType" category="ipv4-addr">
                        <AddressObj:Address_Value condition="Equals">10.0.0.0</AddressObj:Address_Value>
                    </cybox:Properties>
                </cybox:Object>
            </indicator:Observable>
            <indicator:Indicated_TTP>
                <stixCommon:TTP idref="example:ttp-73fe3b22-0201-47cf-85d0-97c02164528d" xsi:type='ttp:TTPType'/>
            </indicator:Indicated_TTP>
        </stix:Indicator>

Malware
-------------

The Malware object in STIX 2.0 is a stub.

**STIX 2.0 Properties Mapped Directly to STIX 1.x Properties**

*none*

**STIX 2.0 Properties Translated to STIX 1.x Properties**

+---------------------------+-------------------------------+
| **STIX 2.0 property**     | **STIX 1.x property**         |
+===========================+===============================+
|  ``kill_chain_phases``    | ``ttp:Kill_Chain_Phases``     |
+---------------------------+-------------------------------+
|  ``labels``               | ``Type``                      |
+---------------------------+-------------------------------+

**STIX 2.0 Relationships Mapped Using STIX 1.x Relationships**

+------------------------------------------+-----------------------------+
| **STIX 2.0 relationship type**           | **STIX 1.x property**       |
+==========================================+=============================+
| ``variant-of``                           |  ``ttp:Related_TTPs``       |
+------------------------------------------+-----------------------------+
| ``uses``                                 |  ``ttp:Related_TTPs``       |
+------------------------------------------+-----------------------------+
| ``targets`` (vulnerability only)         | ``ttp:Exploit_Targets``     |
+------------------------------------------+-----------------------------+
| ``targets`` (identity only)              | ``ttp:Victim_Targeting``    |
+------------------------------------------+-----------------------------+

**STIX 2.0 Properties Recorded in the STIX 1.x Description Property**

*none*

**STIX 2.0 Properties Not Mapped**

*none*

**An Example**

STIX 2.0 in JSON

.. code-block:: json

    {
            "created": "2017-01-27T13:49:53.997Z",
            "description": "Poison Ivy Trojan",
            "id": "malware--fdd60b30-b67c-11e3-b0b9-f01faf20d111",
            "labels": [
                "remote-access-trojan"
            ],
            "modified": "2017-01-27T13:49:53.997Z",
            "name": "Poison Ivy",
            "type": "malware"
    }

STIX 1.x in XML

.. code-block:: xml

    <stix:TTPs>
        <stix:TTP id="example:ttp-fdd60b30-b67c-11e3-b0b9-f01faf20d111" timestamp="2017-01-27T13:49:53.997000+00:00" xsi:type='ttp:TTPType'>
            <ttp:Behavior>
                <ttp:Malware>
                    <ttp:Malware_Instance>
                        <ttp:Type xsi:type="stixVocabs:MalwareTypeVocab-1.0">Remote Access Trojan</ttp:Type>
                        <ttp:Name>Poison Ivy</ttp:Name>
                        <ttp:Description>Poison Ivy Trojan</ttp:Description>
                    </ttp:Malware_Instance>
                </ttp:Malware>
            </ttp:Behavior>
        </stix:TTP>
    </stix:TTPs>

Report
--------

The Report object in 2.0 does not contain objects, but only object references
to STIX objects that are specified elsewhere (the location of the actual
objects may not be contained in the same bundle that contains the report
object).  1.x objects with the ``idref`` property only are created.

**STIX 2.0 Properties Mapped Directly to STIX 1.x Properties**

+-------------------------+------------------------+
| **STIX 2.0 property**   | **STIX 1.x property**  |
+=========================+========================+
| ``name``                | ``Header.Title``       |
+-------------------------+------------------------+
| ``description``         | ``Header.Description`` |
+-------------------------+------------------------+

**STIX 2.0 Properties Translated to STIX 1.x Properties**

+--------------------------------------------------------+-----------------------+
| **STIX 2.0 property**                                  | **STIX 1.x property** |
+========================================================+=======================+
| ``object_refs`` (observed-data)                        | ``Observables``       |
+--------------------------------------------------------+-----------------------+
| ``object_refs`` (indicator)                            | ``Indicators``        |
+--------------------------------------------------------+-----------------------+
| ``object_refs`` (attack-pattern, malware, tool)        | ``TTPs``              |
+--------------------------------------------------------+-----------------------+
| ``object_refs`` (vulnerability)                        | ``Exploit_Targets``   |
+--------------------------------------------------------+-----------------------+
| ``object_refs`` (course-of-action)                     | ``Courses_Of_Action`` |
+--------------------------------------------------------+-----------------------+
| ``object_refs`` (campaign)                             | ``Campaigns``         |
+--------------------------------------------------------+-----------------------+
| ``object_refs`` (threat-actor)                         | ``Threat_Actors``     |
+--------------------------------------------------------+-----------------------+
| ``object_refs`` (identity, intrusion-set, relationship)| *not converted*       |
+--------------------------------------------------------+-----------------------+
| ``labels``                                             | ``Header.Intent``     |
+--------------------------------------------------------+-----------------------+

​**STIX 2.0 Properties Mapped Using STIX 1.x Relationships**

*none*

**STIX 2.0 Properties Recorded in the STIX 1.x Description Property**

- ``published``

**STIX 2.0 Properties Not Mapped**

*none*

**An Example**

STIX 2.0 in JSON

.. code-block:: json

    {
            "created": "2015-05-07T14:22:14.760Z",
            "created_by_ref": "identity--c1b58a86-e037-4069-814d-dd0bc75539e3",
            "description": "Adversary Alpha has a campaign against the ICS sector!",
            "id": "report--ab11f431-4b3b-457c-835f-59920625fe65",
            "labels": [
                "campaign-characterization"
            ],
            "modified": "2015-05-07T14:22:14.760Z",
            "name": "Report on Adversary Alpha's Campaign against the Industrial Control Sector",
            "object_refs": [
                "campaign--1855cb8a-d96c-4859-a450-abb1e7c061f2"
            ],
            "published": "2015-05-31T00:00:00.000Z",
            "type": "report"
        }

STIX 1.x in XML

.. code-block:: xml

    <stix:Report timestamp="2015-05-07T14:22:14.760000+00:00" id="example:report-ab11f431-4b3b-457c-835f-59920625fe65" xsi:type='report:ReportType' version="1.0">
            <report:Header>
                <report:Title>Report on Adversary Alpha's Campaign against the Industrial Control Sector</report:Title>
                <report:Intent xsi:type="stixVocabs:ReportIntentVocab-1.0">Campaign Characterization</report:Intent>
                <report:Description ordinality="1">Adversary Alpha has a campaign against the ICS sector!
                <report:Description ordinality="2">published: 2015-05-31 00:00:00+00:00</report:Description>
            </report:Header>
            <report:Campaigns>
                <report:Campaign idref="example:campaign-1855cb8a-d96c-4859-a450-abb1e7c061f2" xsi:type='campaign:CampaignType'/>
            </report:Campaigns>
        </stix:Report>

Threat Actor
------------------

**STIX 2.0 Properties Mapped Directly to STIX 1.x Properties**

+-------------------------------------+--------------------------------------+
| **STIX 2.0 property**               | **STIX 1.x property**                |
+=====================================+======================================+
| ``goals``                           | ``Intended_Effects``                 |
+-------------------------------------+--------------------------------------+

**STIX 2.0 Properties Translated to STIX 1.x Properties**

+-------------------------------------+--------------------------------------+
| **STIX 2.0 property**               | **STIX 1.x property**                |
+=====================================+======================================+
| ``primary_motivation``              | ``Motivation``                       |
| ``secondary_motivations``           |                                      |
| ``personal_motivations``            |                                      |
+-------------------------------------+--------------------------------------+
| ``sophistication``                  | ``Sophistication``                   |
+-------------------------------------+--------------------------------------+
| ``labels``                          | ``Type``                             |
+-------------------------------------+--------------------------------------+

​**STIX 2.0 Relationships Mapped Using STIX 1.x Relationships**

+--------------------------------+---------------------------------------+
| **STIX 2.0 relationship type** | **STIX 1.x property**                 |
+================================+=======================================+
| ``uses``                       | ``Observed_TTPs``                     |
+--------------------------------+---------------------------------------+
| ``attributed-to`` (reverse)    | ``Associated_Campaigns``              |
+--------------------------------+---------------------------------------+
| ``related-to`` (threat-actor)  | ``Associated_Actors``                 |
+--------------------------------+---------------------------------------+

**STIX 2.0 Properties Recorded in the STIX 1.x Description Property**

- ``name``
- ``aliases``
- ``roles``
- ``resource_level``

**STIX 2.0 Properties Not Mapped**

*none*

**An Example**

STIX 2.0 in JSON

.. code-block:: json

    {
            "created": "2017-01-27T13:49:54.326Z",
            "id": "threat-actor--9a8a0d25-7636-429b-a99e-b2a73cd0f11f",
            "labels": [
                "nation-state"
            ],
            "modified": "2017-01-27T13:49:54.326Z",
            "name": "Adversary Bravo",
            "sophistication": "advanced",
            "type": "threat-actor"
    }

STIX 1.x in XML

.. code-block:: xml

    <stix:Threat_Actor id="example:threat-actor-9a8a0d25-7636-429b-a99e-b2a73cd0f11f"
                       timestamp="2017-01-27T13:49:54.326000+00:00"
                       xsi:type='ta:ThreatActorType'>
            <ta:Title>Adversary Bravo</ta:Title>
            <ta:Type timestamp="2018-05-06T16:57:09.692723+00:00">
                <stixCommon:Value>State Actor / Agency</stixCommon:Value>
            </ta:Type>
            <ta:Sophistication timestamp="2018-05-06T16:57:09.692815+00:00">
                <stixCommon:Value>Expert</stixCommon:Value>
            </ta:Sophistication>
    </stix:Threat_Actor>

Tool
-------

**STIX 2.0 Properties Mapped Directly to STIX 1.x Properties**

+--------------------------+--------------------------------+
| **STIX 2.0 property**    | **STIX 1.x property**          |
+==========================+================================+
| ``name``                 | ``Name`` (from CybOX)          |
+--------------------------+--------------------------------+
| ``labels``               | ``Type`` (from CybOX)          |
+--------------------------+--------------------------------+
| ``description``          | ``Description`` (from CybOX)   |
+--------------------------+--------------------------------+
| ``tool_version``         | ``Version`` (from CybOX)       |
+--------------------------+--------------------------------+


​**STIX 2.0 Properties Translated to STIX 2.0 Properties**

+-----------------------------------+-------------------------------+
| **STIX 1.x property**             | **STIX 1.x property**         |
+===================================+===============================+
| ``external_references``           | ``References`` (from CybOX)   |
+-----------------------------------+-------------------------------+
| ``kill_chain_phases``             | ``ttp:Kill_Chain_Phases``     |
+-----------------------------------+-------------------------------+

​**STIX 2.0 Relationships Mapped Using STIX 1.x Relationships**

+---------------------------------------+----------------------------+
| **STIX 2.0 relationship type**        | **STIX 1.x property**      |
+=======================================+============================+
| ``uses`` (attack-pattern) (reverse)   | ``ttp:Related_TTPs``       |
+---------------------------------------+----------------------------+
| ``targets`` (identity)                | ``ttp:Related_TTPs``       |
+---------------------------------------+----------------------------+

**STIX 2.0  Properties Recorded in the STIX 1.x Description Property**

- ``ttp:Intended_Effect``

**STIX 1.x Properties Not Mapped**

- ``labels``

**An Example**

STIX 2.0 in JSON

.. code-block:: json

    {
      "type": "tool",
      "id": "tool--ce45f721-af14-4fc0-938c-000c16186418",
      "created": "2015-05-15T09:00:00.000Z",
      "modified": "2015-05-15T09:00:00.000Z",
      "name": "cachedump",
      "labels": [
        "credential-exploitation"
      ],
      "description": "This program extracts cached password hashes from a system’s registry.",
      "kill_chain_phases": [
        {
          "kill_chain_name": "mandiant-attack-lifecycle-model",
          "phase_name": "escalate-privileges"
        }
      ]
    }

STIX 1.x in XML

.. code-block:: xml

    <stix:TTP id="example:tool-ce45f721-af14-4fc0-938c-000c16186418" timestamp="2015-05-15T09:00:00+00:00" xsi:type='ttp:TTPType'>
            <ttp:Resources>
                <ttp:Tools>
                    <ttp:Tool>
                        <cyboxCommon:Description>This program extracts cached password hashes from a system’s registry.</cyboxCommon:Description>
                        <stixCommon:Title>cachedump</stixCommon:Title>
                    </ttp:Tool>
                </ttp:Tools>
            </ttp:Resources>
            <ttp:Kill_Chain_Phases>
                <stixCommon:Kill_Chain_Phase name="escalate-privileges"
                                             phase_id="example:TTP-17715bcf-84b9-4714-a3cd-ffaf7fce9d10"
                                             kill_chain_name="mandiant-attack-lifecycle-model"
                                             kill_chain_id="example:TTP-9df538ea-f0f0-4cf0-a147-1397e51f0a63"/>
            </ttp:Kill_Chain_Phases>
        </stix:TTP>

Vulnerability
------------------

**STIX 2.0 Properties Mapped Directly to STIX 1.x Properties**

*none*

**STIX 2.0 Properties Translated to STIX 1.x Properties**

+---------------------------------------------------------+------------------------------+
| **STIX 2.0 property**                                   | **STIX 1.x  property**       |
+=========================================================+==============================+
| ``external_references`` (``source_name``: ``cve``)      |``CVE_ID``                    |
+---------------------------------------------------------+------------------------------+
| ``external_references`` (``source_name``: ``OSVDB_ID``) | ``Reference``                |
+---------------------------------------------------------+------------------------------+


**​STIX 2.0 Relationships Mapped Using STIX 1.x Relationships**

+------------------------------------------------+--------------------------------+
| **STIX 2.0 relationship type**                 | **STIX 1.x property**          |
+================================================+================================+
| ``mitigates`` (reverse)                        | ``et:Potential_COAs``          |
+------------------------------------------------+--------------------------------+
| ``related-to`` (when not used for versioning)  | ``et:Related_Exploit_Targets`` |
+------------------------------------------------+--------------------------------+

**STIX 2.0 Properties Recorded in the STIX 1.x Description Property**

- ``labels``

**STIX 2.0 Properties Not Mapped**

*none*

**An Example**

STIX 2.0 in JSON

.. code-block:: json

    {
       "created": "2014-06-20T15:16:56.986Z",
       "external_references": [
           {
               "external_id": "CVE-2013-3893",
               "source_name": "cve"
           }
       ],
       "id": "vulnerability--e77c1e36-5b43-4c5c-b8cb-7b36035f2b90",
       "modified": "2017-01-27T13:49:54.310Z",
       "name": "Heartbleed",
       "type": "vulnerability"
    }

STIX 1.x in XML

.. code-block:: xml

    <stix:Exploit_Targets>
       <stixCommon:Exploit_Target id="example:et-e77c1e36-5b43-4c5c-b8cb-7b36035f2b90"
                                  timestamp="2014-06-20T15:16:56.986650+00:00"
                                  xsi:type='et:ExploitTargetType' version="1.2">
           <et:Title>Heartbleed</et:Title>
           <et:Vulnerability>
               <et:CVE_ID>CVE-2013-3893</et:CVE_ID>
           </et:Vulnerability>
       </stixCommon:Exploit_Target>
    </stix:Exploit_Targets>


