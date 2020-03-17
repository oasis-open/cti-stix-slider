​Command Line Interface
===========================

The slider comes with a bundled script which you can use to convert
STIX 2.x content to STIX 1.x content:

.. code-block:: text

        usage: stix2_slider [-h] [--no-squirrel-gaps] [--validator-args VALIDATOR_ARGS]
                            [-e ENABLE] [-d DISABLE] [-s]
                            [--message-log-directory MESSAGE_LOG_DIRECTORY]
                            [--log-level {DEBUG,INFO,WARN,ERROR,CRITICAL}]
                            [--use-namespace USE_NAMESPACE]
                            file

        stix2-slider v2.1.0

The stix2-slider is a work-in-progress. It should be used to explore how
existing STIX 2.x would potentially be represented in STIX 1.x. Using the
current version of the stix2-slider will provide insight to issues that might need
to be mitigated so you can use an application that supports only STIX 1.x content.

positional arguments:

.. code-block:: text

        file    The input STIX 2.x document to be 'slid' to STIX 1.x.

optional arguments:

.. code-block:: text

          -h, --help
                show this help message and exit

          --no-squirrel-gaps
                Do not include STIX 2.x content that cannot be
                represented directly in STIX 1.x using the description
                property.

          --validator-args VALIDATOR_ARGS
                Arguments to pass to stix-validator. Example:
                stix2_slider <file> --validator-args="--best-
                practices"

          -e ENABLE, --enable ENABLE
                A comma-separated list of the stix2-slider messages to
                enable. If the --disable option is not used, no other
                messages will be shown. Example: stix2_slider <file>
                --enable 250

          -d DISABLE, --disable DISABLE
                A comma-separated list of the stix2-slider messages to
                disable. Example: stix2_slider <file> --disable
                212,220

          -s, --silent
                If this flag is set. All stix2-slider messages will be
                disabled.

          --message-log-directory MESSAGE_LOG_DIRECTORY
                If this flag is set, all stix2-slider messages will be
                saved to file. The name of the file will be the input
                file with extension .log in the specified directory.
                Note, make sure the directory already exists. Example:
                stix2_slider <file> --message-log-directory "../logs"

          --log-level {DEBUG,INFO,WARN,ERROR,CRITICAL}
                The logging output level.

          --use-namespace USE_NAMESPACE
                Override the 'example' namespace with provided one.
                The format is the prefix, namespace uri and optionally
                the schema location separated by a space. Example:
                stix2_slider <file> --use-namespace="example
                http://example.com"


Refer to the :ref:`warning_messages` section for all stix2-slider messages. Use the associated code number
to ``--enable`` or ``--disable`` a message. By default, the stix2-slider displays all
messages.

Note: disabling the message does not disable any functionality.

It is recommended that you ensure that the input STIX 2.x file is
valid before submitting it to the slider.
Use the `stix2-validator <https://pypi.org/project//stix2-validator>`_.

