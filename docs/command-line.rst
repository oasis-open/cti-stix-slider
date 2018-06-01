​Command Line Interface
===========================

The slider comes with a bundled script which you can use to convert
STIX 2.0 content to STIX 1.x content:

.. code-block:: text

        usage: stix2_slider [-h] [--no-squirrel-gaps]
                    [-e ENABLE] [-d DISABLE] [-s]
                    [--message-log-directory MESSAGE_LOG_DIRECTORY]
                    [--log-level {DEBUG,INFO,WARN,ERROR,CRITICAL}]
                    file

        stix2-slider v1.0.0

The stix2-slider is a work-in-progress. It should be used to explore how
existing STIX 2.0 would potentially be represented in STIX 1.x. Using the
current version of the stix2-slider will provide insight to issues that might need
to be mitigated so you can use an application that supports only STIX 1.x content.

positional arguments:

.. code-block:: text

        file    The input STIX 2.0 document to be 'slid' to STIX 1.x.

optional arguments:

.. code-block:: text

          -h, --help
                show this help message and exit

          --no-squirrel-gaps
                Do not include STIX 2.0 content that cannot be
                represented directly in STIX 1.x using the description
                property.

          -e ENABLE, --enable ENABLE
                A comma-separated list of the stix2-slider messages to
                enable. If the --disable option is not used, no other
                messages will be shown.

                Example: --enable 250

          -d DISABLE, --disable DISABLE
                A comma-separated list of the stix2-slider messages to
                disable.

                Example: --disable 212,220

          -s, --silent
                If this flag is set. All stix2-slider messages will be
                disabled.

          --message-log-directory MESSAGE_LOG_DIRECTORY
                If this flag is set all stix2-slider messages will be
                saved to file. The name of the file will be the input
                file with extension .log in the specified directory.

                Note, make sure the directory already exists.

                Example: --message-log-directory "..\logs"

          --log-level {DEBUG,INFO,WARN,ERROR,CRITICAL}
                The logging output level.


Refer to the :ref:`warning_messages` section for all stix2-slider messages. Use the associated code number
to ``--enable`` or ``--disable`` a message. By default, the stix2-slider displays all
messages.

Note: disabling the message does not disable any functionality.
