|Build_Status| |Coverage| |Version|

cti-stix-slider
===============

NOTE: This is an `OASIS TC Open
Repository <https://www.oasis-open.org/resources/open-
repositories/>`_.
See the `Governance`_ section for more information.

The stix-slider is a software tool for 'sliding' STIX 2.0 JSON to STIX
1.x XML. Due to the differences between STIX 1.x and STIX 2.0, this
conversion is best-effort only. During the conversion, stix-slider
provides information on the assumptions it needs to make to produce
valid STIX
1.x XML, and what information was not able to be converted.

The stix-slider is a work-in-progress. It should be used to explore
how STIX 2.0 content could potentially be represented in STIX 1.x.
Using the current version of the slider will provide insight to issues
that might need to be mitigated to convert your STIX 2.0 content for
use in application that accept only STIX 1.x content.

**It should not be used in a production environment, and should not be
considered final.**

Please enter any comments on how to improve it into the issue tracker.

Requirements
------------

- Python 2.7, or 3.3+
- `python-stix <https://stix.readthedocs.io/en/stable/>`_ and its dependencies

  .. note::

      Make sure to use either the latest version of python-stix
      1.1.1.x or
      1.2.0.x, depending on whether you want to support STIX 1.1.1 or
      STIX 1.2.

-  `python-stix2 <https://pypi.org/project/python-stix2>`_ >= 1.0.0
-  `stixmarx <https://pypi.org/project/stixmarx>`_ >= 1.0.3
-  `stix-validator <https://pypi.org/project/stix-validator>`_ >= 2.5.0

Installation
------------

Install with pip::

    $ pip install stix2-slider

This will install all necessary dependencies, including the latest
version of python-stix.

If you need to support older STIX 1.1.1 content, install python-stix
1.1.1.x
first::

    $ pip install 'stix<1.2'
    $ pip install stix2-slider

You can also install the stix-slider from GitHub to get the latest
(unstable) version::

    $ pip install git+https://github.com/oasis-open/cti-stix-slider.git

Usage
-----

It is recommended that you ensure that the input STIX 2.0 file is
valid before submitting it to the slider.
Use the `stix2-validator <https://pypi.org/project//stix2-validator>`_.

As A Script
~~~~~~~~~~~

The slider comes with a bundled script which you can use to convert
STIX 2.0 content to STIX 1.x content::

        usage: stix2_slider [-h] [--no-squirrel-gaps] [-e ENABLE] [-d DISABLE] [-s]
                      [--message-log-directory MESSAGE_LOG_DIRECTORY]
                      [--log-level {DEBUG,INFO,WARN,ERROR,CRITICAL}]
                      file

        stix2-slider v1.0.0

        The stix2-slider is a work-in-progress. It should be used to explore how
        existing STIX 2.0 would potentially be represented in STIX 1.x. Using the
        current version of the stix2-slider will provide insight to issues that might need
        to be mitigated so you can use an application that supports only STIX 1.x content.

        positional arguments:   The input STIX 2.0 document to be 'slid' to STIX 1.x..

        optional arguments:
          -h, --help            show this help message and exit

          --no-squirrel-gaps    Do not include STIX 2.0 content that cannot be
                                represented directly in STIX 1.x using the description
                                property.

          -e ENABLE, --enable ENABLE
                                A comma-separated list of the stix2-slider messages to
                                enable. If the --disable option is not used, no other
                                messages will be shown. Example: stix2_slider.py
                                <file> --enable 250

          -d DISABLE, --disable DISABLE
                                A comma-separated list of the stix2-slider messages to
                                disable. Example: stix2_slider.py <file> --disable
                                212,220

          -s, --silent          If this flag is set. All stix2-slider messages will be
                                disabled.

          --message-log-directory MESSAGE_LOG_DIRECTORY
                                If this flag is set. All stix2-slider messages will be
                                saved to file. The name of the file will be the input
                                file with extension .log in the specified directory.
                                Note, make surethe directory already exists. Example:
                                stix2_slider.py <file> --message-log-directory
                                "..\logs"

          --log-level {DEBUG,INFO,WARN,ERROR,CRITICAL}
                                The logging output level.

        Refer to slider_log_messages.rst for all stix2-slider messages. Use the associated code number
        to --enable or --disable a message. By default, the stix2-slider displays all
        messages. Note: disabling the message does not disable the functionality.

As A Library
~~~~~~~~~~~~

You can also use this library to integrate STIX 'sliding' into your
own
tools. You can slide a STIX 2.0 file::

      from stix2slider import slide_file
      from stix2slider.options import initialize_options

      intialize_options()
      results = slide_file("stix_file.json")
      print(results)

Additionally, a similar method exists to accept a string as an
argument::

      from stix2slider import slide_string
      from stix2slider.options import initialize_options

      intialize_options()
      results = slide_string("...")
      print(results)

To set options, use set_option_value, found in options.py.

Governance
----------

This GitHub public repository (
**https://github.com/oasis-open/cti-stix-slider** ) was
was created at the request of the
the
`OASIS Cyber Threat Intelligence (CTI)
TC <https://www.oasis-open.org/committees/cti/>`__ as an `OASIS TC
Open
Repository <https://www.oasis-open.org/resources/open-
repositories/>`__
to support development of open source resources related to Technical
Committee work.

While this TC Open Repository remains associated with the sponsor TC,
its
development priorities, leadership, intellectual property terms,
participation rules, and other matters of governance are `separate and
distinct <https://github.com/oasis-open/cti-stix-
slider/blob/master/CONTRIBUTING.md#governance-distinct-from-oasis-tc-
process>`__
from the OASIS TC Process and related policies.

All contributions made to this TC Open Repository are subject to open
source license terms expressed in the `BSD-3-Clause
License <https://www.oasis-open.org/sites/www.oasis-
open.org/files/BSD-3-Clause.txt>`__.
That license was selected as the declared `"Applicable
License" <https://www.oasis-open.org/resources/open-
repositories/licenses>`__
when the TC Open Repository was created.

As documented in `"Public Participation
Invited <https://github.com/oasis-open/cti-stix-
elevator/blob/master/CONTRIBUTING.md#public-participation-
invited>`__",
contributions to this OASIS TC Open Repository are invited from all
parties, whether affiliated with OASIS or not. Participants must have
a
GitHub account, but no fees or OASIS membership obligations are
required. Participation is expected to be consistent with the `OASIS
TC Open Repository Guidelines and
Procedures <https://www.oasis-open.org/policies-guidelines/open-
repositories>`__,
the open source
`LICENSE <https://github.com/oasis-open/cti-stix-
elevator/blob/master/LICENSE>`__
designated for this particular repository, and the requirement for an
`Individual Contributor License
Agreement <https://www.oasis-open.org/resources/open-
repositories/cla/individual-cla>`__
that governs intellectual property.

Statement of Purpose
~~~~~~~~~~~~~~~~~~~~

Statement of Purpose for this OASIS TC Open Repository (cti-stix-
slider) as `proposed <https://lists.oasis-
open.org/archives/cti/201711/msg00000.html>`_ and `approved
<https://lists.oasis-open.org/archives/cti/201711/msg00002.html>`_
`[bis] <https://issues.oasis-open.org/browse/TCADMIN-2807>`_ by the
TC:

This GitHub public repository is provided to support version-
controlled development of a Python "slider" application which will
convert `STIX 2.0 <http://docs.oasis-open.org/cti/stix/v2.0/>`_
content to `STIX 1.x <http://docs.oasis-open.org/cti/stix/v1.2.1/>`_
content.

Maintainers
~~~~~~~~~~~

TC Open Repository
`Maintainers <https://www.oasis-open.org/resources/open-
repositories/maintainers-guide>`__
are responsible for oversight of this project's community development
activities, including evaluation of GitHub `pull
requests <https://github.com/oasis-open/cti-stix-
elevator/blob/master/CONTRIBUTING.md#fork-and-pull-collaboration-
model>`__
and
`preserving <https://www.oasis-open.org/policies-guidelines/open-
repositories#repositoryManagement>`__
open source principles of openness and fairness. Maintainers are
recognized and trusted experts who serve to implement community goals
and consensus design preferences.

Initially, the associated TC members have designated one or more
persons
to serve as Maintainer(s); subsequently, participating community
members
may select additional or substitute Maintainers, per `consensus
agreements <https://www.oasis-open.org/resources/open-
repositories/maintainers-guide#additionalMaintainers>`__.

**Current Maintainers of this TC Open Repository**

-  `Greg Back <mailto:gback@mitre.org>`__; GitHub ID:
   https://github.com/gtback/; WWW: `MITRE <https://www.mitre.org/>`__
-  `Rich Piazza <mailto:rpiazza@mitre.org>`__; GitHub ID:
   https://github.com/rpiazza/; WWW: `MITRE
   <https://www.mitre.org/>`__

About OASIS TC Open Repositories
--------------------------------

-  `TC Open Repositories: Overview and
   Resources <https://www.oasis-open.org/resources/open-
   repositories/>`__
-  `Frequently Asked
   Questions <https://www.oasis-open.org/resources/open-
   repositories/faq>`__
-  `Open Source
   Licenses <https://www.oasis-open.org/resources/open-
   repositories/licenses>`__
-  `Contributor License Agreements
   (CLAs) <https://www.oasis-open.org/resources/open-
   repositories/cla>`__
-  `Maintainers' Guidelines and
   Agreement <https://www.oasis-open.org/resources/open-
   repositories/maintainers-guide>`__

Feedback
--------

Questions or comments about this TC Open Repository's activities
should be
composed as GitHub issues or comments. If use of an issue/comment is
not
possible or appropriate, questions may be directed by email to the
Maintainer(s) `listed above <#currentMaintainers>`__. Please send
general questions about TC Open Repository participation to OASIS
Staff at
repository-admin@oasis-open.org and any specific CLA-related questions
to repository-cla@oasis-open.org.

.. |Build_Status| image:: https://travis-ci.org/oasis-open/cti-stix-slider.svg?branch=master
   :target: https://travis-ci.org/oasis-open/cti-stix-slider
.. |Coverage| image:: https://codecov.io/gh/oasis-open/cti-stix-slider/branch/master/graph/badge.svg
   :target: https://codecov.io/gh/oasis-open/cti-stix-slider
.. |Version| image:: https://img.shields.io/pypi/v/stix2-slider.svg?maxAge=3600
   :target: https://pypi.python.org/pypi/stix2-slider/

