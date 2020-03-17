"""The stix2-slider is a work-in-progress. It should be used to explore how
existing STIX 2.0 would potentially be represented in STIX 1.x. Using the
current version of the stix2-slider will provide insight to issues that might need
to be mitigated so you can use an application that supports only STIX 1.x content.
"""

# Standard Library
import argparse
import sys
import textwrap

# internal
from stix2slider import slide_file
from stix2slider.options import initialize_options
from stix2slider.version import __version__

CODE_TABLE = """
Refer to slider_log_messages.rst for all stix2-slider messages. Use the associate code number
to --enable or --disable a message. By default, the stix2-slider displays all
messages. Note: disabling the message does not disable the functionality.
"""


class NewlinesHelpFormatter(argparse.RawDescriptionHelpFormatter):
    """Custom help formatter to insert newlines between argument help texts.
    """
    def _split_lines(self, text, width):
        text = self._whitespace_matcher.sub(' ', text).strip()
        txt = textwrap.wrap(text, width)
        txt[-1] += '\n'
        return txt


def _get_arg_parser(is_script=True):
    """Create and return an ArgumentParser for this application."""
    desc = "stix2-slider v{0}\n\n".format(__version__)

    parser = argparse.ArgumentParser(
        description=desc + __doc__,
        formatter_class=NewlinesHelpFormatter,
        epilog=CODE_TABLE
    )

    if is_script:
        parser.add_argument(
            "file_",
            help="The input STIX 2.0 document to be 'slid' to STIX 1.x.",
            metavar="file"
        )

    parser.add_argument(
        "--no-squirrel-gaps",
        help="Do not include STIX 2.0 content that cannot be represented "
             "directly in STIX 1.x using the description property.",
        dest="no_squirrel_gaps",
        action="store_true",
        default=False
    )

    parser.add_argument(
        "--validator-args",
        help="Arguments to pass to stix-validator.\n\n"
             "Example: stix2_slider <file> --validator-args=\"--best-practices\"",
        dest="validator_args",
        action="store",
        default=""
    )

    parser.add_argument(
        "-e",
        "--enable",
        help="A comma-separated list of the stix2-slider messages to enable. "
             "If the --disable option is not used, no other messages will be "
             "shown. \n\nExample: stix2_slider <file> --enable 250",
        dest="enabled",
        default=None
    )

    parser.add_argument(
        "-d",
        "--disable",
        help="A comma-separated list of the stix2-slider messages to disable. \n\n"
             "Example: stix2_slider <file> --disable 212,220",
        dest="disabled",
        default=None
    )

    parser.add_argument(
        "-s",
        "--silent",
        help="If this flag is set. All stix2-slider messages will be disabled.",
        dest="silent",
        action="store_true",
        default=False
    )

    parser.add_argument(
        "--message-log-directory",
        help="If this flag is set, all stix2-slider messages will be saved to "
             "file. The name of the file will be the input file with "
             "extension .log in the specified directory. Note, make sure "
             "the directory already exists.\n\n"
             "Example: stix2_slider <file> --message-log-directory \"../logs\"",
        dest="message_log_directory",
        action="store",
        default=None
    )

    parser.add_argument(
        "--log-level",
        default="INFO",
        help="The logging output level.",
        choices=["DEBUG", "INFO", "WARN", "ERROR", "CRITICAL"]
    )

    parser.add_argument(
        "--use-namespace",
        dest="use_namespace",
        help="Override the 'example' namespace with provided one. The format is"
             " the prefix, namespace uri and optionally the schema location"
             " separated by a space. \n\nExample: "
             " stix2_slider <file> --use-namespace=\"example http://example.com\""
    )

    return parser


def main():
    # Parse stix-slider command-line args
    slider_arg_parser = _get_arg_parser()
    slider_args = slider_arg_parser.parse_args()

    initialize_options(slider_args)
    result = slide_file(slider_args.file_)
    if result:
        print(result + "\n")
    else:
        sys.exit(1)


if __name__ == '__main__':
    main()
