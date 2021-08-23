# Standard Library
import argparse
import copy
import logging
import os
import shlex

# external
import sdv
from sdv import scripts, validators

ALL_OPTIONS = None

formatter = logging.Formatter("[%(name)s] [%(ecode)d] [%(levelname)-7s] [%(asctime)s] %(message)s")

# Console Handler for Elevator messages
ch = logging.StreamHandler()
ch.setFormatter(formatter)

# File Handler for Elevator logs, set individually for each file.
fh = None

# Module-level logger
log = logging.getLogger(__name__)
log.addHandler(ch)

MESSAGES_GENERATED = False


def debug(fmt, ecode, *args):
    if msg_id_enabled(ecode):
        global MESSAGES_GENERATED
        log.debug(fmt, *args, extra={'ecode': ecode})
        MESSAGES_GENERATED = True


def info(fmt, ecode, *args):
    if msg_id_enabled(ecode):
        global MESSAGES_GENERATED
        log.info(fmt, *args, extra={'ecode': ecode})
        MESSAGES_GENERATED = True


def warn(fmt, ecode, *args):
    if msg_id_enabled(ecode):
        global MESSAGES_GENERATED
        log.warning(fmt, *args, extra={'ecode': ecode})
        MESSAGES_GENERATED = True


def error(fmt, ecode, *args):
    if msg_id_enabled(ecode):
        global MESSAGES_GENERATED
        log.error(fmt, *args, extra={'ecode': ecode})
        MESSAGES_GENERATED = True


def setup_logger(package_id):
    global log
    global fh

    if ALL_OPTIONS:
        log.setLevel(get_option_value("log_level"))

        if not get_option_value("message_log_directory"):
            return

        output_directory = get_option_value("message_log_directory")
        file_directory = get_option_value("file_")

        if file_directory:
            project_path, filename = os.path.split(file_directory)
            filename = filename.split(".")[0]
            filename += ".log"
        else:
            filename = package_id.split(":")[1]
            filename += ".log"

        if not os.path.exists(output_directory):
            os.makedirs(output_directory)

        destination = os.path.join(output_directory, filename)
        destination = os.path.abspath(destination)

        # Remove File Handler from root logger if present.
        if fh in log.handlers:
            fh.close()
            log.removeHandler(fh)

        # The delay=True should prevent the file from being opened until a
        # message is emitted by the logger.
        fh = logging.FileHandler(destination, mode='w', delay=True)
        fh.setFormatter(formatter)
        log.addHandler(fh)


def _convert_to_int_list(check_codes):
    """Takes a comma-separated string or list of strings and converts to list of ints.

    Args:
        check_codes: comma-separated string or list of strings

    Returns:
        list: the check codes as a list of integers

    Raises:
        ValueError: if conversion fails
        RuntimeError: if cannot determine how to convert input
    """
    if isinstance(check_codes, list):
        if all(isinstance(x, int) for x in check_codes):
            return check_codes  # good input
        else:
            return [int(x) for x in check_codes]  # list of str
    elif isinstance(check_codes, str):
        return [int(x) for x in check_codes.split(",")]  # str, comma-separated expected
    raise RuntimeError("Could not convert values: {} of type {}".format(check_codes, type(check_codes)))


class SliderOptions(object):
    """Collection of stix2-slider options which can be set via command line or
    programmatically in a script.

    It can be initialized either by passing in the result of parse_args() from
    ``argparse.Namespace`` to the cmd_args parameter, or by specifying
    individual options with the other parameters.

    Attributes:
        cmd_args: An instance of ``argparse.Namespace`` containing options
            supplied on the command line.
        file_: Input file to be elevated.
        validator_args: If set, these values will be used to create a
            ValidationOptions instance if requested.
        enabled: Messages to enable. Expects a list of ints.
        disabled: Messages to disable. Expects a list of ints.
        silent: If set, no stix2-slider log messages will be emitted.
        message_log_directory: If set, it will write all emitted messages to
            file. It will use the filename or package id to name the log file.

    Note:
        All messages are turned on by default.
    """
    def __init__(self, cmd_args=None, file_=None,
                 no_squirrel_gaps=False, validator_args="",
                 enabled=None, disabled=None,
                 silent=False, message_log_directory=None,
                 output_directory=None, log_level="INFO", use_namespace=""):

        if cmd_args is not None:
            if hasattr(cmd_args, "file_"):
                self.file_ = cmd_args.file_
            self.no_squirrel_gaps = cmd_args.no_squirrel_gaps
            self.validator_args = cmd_args.validator_args

            self.enabled = cmd_args.enabled
            self.disabled = cmd_args.disabled
            self.silent = cmd_args.silent
            self.message_log_directory = cmd_args.message_log_directory
            self.log_level = cmd_args.log_level
            if hasattr(cmd_args, "output_directory"):
                self.output_directory = cmd_args.output_directory
            self.use_namespace = cmd_args.use_namespace

        else:
            self.file_ = file_
            self.no_squirrel_gaps = no_squirrel_gaps
            self.validator_args = validator_args
            self.enabled = enabled
            self.disabled = disabled
            self.silent = silent
            self.message_log_directory = message_log_directory
            self.log_level = log_level
            self.output_directory = output_directory
            self.use_namespace = use_namespace

        self.marking_container = None
        self.version_of_stix2x = None

    @property
    def disabled(self):
        return self._disabled

    @disabled.setter
    def disabled(self, disabled):
        def remove_silent(item, elements):
            try:
                elements.remove(item)
            except ValueError:
                pass  # suppress exception if value is not present
        # Convert string of comma-separated checks to a list,
        # and convert check code numbers to names. By default no messages are
        # disabled.
        if disabled:
            self._disabled = _convert_to_int_list(disabled)
            self._disabled = [x for x in self._disabled if x in CHECK_CODES]
            for x in self._disabled:
                remove_silent(x, self._enabled)
        else:
            self._disabled = []

    @property
    def enabled(self):
        return self._enabled

    @enabled.setter
    def enabled(self, enabled):
        def remove_silent(item, elements):
            try:
                elements.remove(item)
            except ValueError:
                pass  # suppress exception if value is not present
        # Convert string of comma-separated checks to a list,
        # and convert check code numbers to names. By default all messages are
        # enabled.
        if enabled:
            self._enabled = _convert_to_int_list(enabled)
            self._enabled = [x for x in self._enabled if x in CHECK_CODES]
            for x in self._enabled:
                remove_silent(x, self._disabled)
        else:
            self._enabled = copy.deepcopy(CHECK_CODES)


def initialize_options(options=None):
    global ALL_OPTIONS
    if not ALL_OPTIONS:
        if isinstance(options, SliderOptions):
            ALL_OPTIONS = options
        elif isinstance(options, dict):
            ALL_OPTIONS = SliderOptions(**options)
        else:
            ALL_OPTIONS = SliderOptions(options)

        if ALL_OPTIONS.silent and ALL_OPTIONS.message_log_directory:
            warn("Both console and output log have disabled messages.", 202)


def get_validator_options():
    if ALL_OPTIONS:
        validator_parser = _get_validator_arg_parser()
        validator_args = validator_parser.parse_args(
            shlex.split(get_option_value("validator_args"))
        )

        _validate_validator_args(validator_args)
        options = _set_validation_options(validator_args)

        return options


def get_option_value(option_name):
    if ALL_OPTIONS and hasattr(ALL_OPTIONS, option_name):
        return getattr(ALL_OPTIONS, option_name)
    else:
        return None


def set_option_value(option_name, option_value):
    if ALL_OPTIONS:
        setattr(ALL_OPTIONS, option_name, option_value)
    else:
        error("options not initialized", 204)


def msg_id_enabled(msg_id):
    if get_option_value("silent"):
        return False

    if not get_option_value("disabled"):
        return msg_id in get_option_value("enabled")
    else:
        return not (msg_id in get_option_value("disabled"))


def _set_validation_options(args):
    """Populates an instance of ``ValidationOptions`` from the `args` param.
    Args:
        args (argparse.Namespace): The arguments parsed and returned from
            ArgumentParser.parse_args().
    Returns:
        Instance of ``ValidationOptions``.
    """
    options = scripts.ValidationOptions()
    options.schema_validate = True

    if options.schema_validate and args.profile:
        options.profile_validate = True

    # best practice options, for stix1.x validator
    options.best_practice_validate = args.best_practices

    # input options
    options.lang_version = args.lang_version
    options.schema_dir = args.schema_dir
    options.in_profile = args.profile
    options.recursive = args.recursive
    options.use_schemaloc = args.use_schemaloc
    options.huge_tree = args.huge_tree

    # output options
    options.json_results = args.json
    options.quiet_output = args.quiet

    # validation class options
    options.xml_validation_class = validators.STIXSchemaValidator

    return options


def _validate_validator_args(args):
    """Checks that valid and compatible command line arguments were passed into
    the application.
    Args:
        args (argparse.Namespace): The arguments parsed and returned from
            ArgumentParser.parse_args().
    Raises:
        ArgumentError: If invalid or incompatible command line arguments were
            passed into the application.
    """
    schema_validate = True
    profile_validate = False

    if schema_validate and args.profile:
        profile_validate = True

    if all((args.lang_version, args.use_schemaloc)):
        raise scripts.ArgumentError(
            "Cannot set both --stix-version and --use-schemalocs"
        )

    if args.profile and not profile_validate:
        raise scripts.ArgumentError(
            "Profile specified but no validation options specified."
        )


def _get_validator_arg_parser():
    """Initializes and returns an argparse.ArgumentParser instance for the
    stix-validator application.

    Returns:
        Instance of ``argparse.ArgumentParser``
    """
    parser = argparse.ArgumentParser(
        description="STIX Document Validator v{}".format(sdv.__version__)
    )

    parser.add_argument(
        "--stix-version",
        dest="lang_version",
        default=None,
        help="The version of STIX to validate against"
    )

    parser.add_argument(
        "--schema-dir",
        dest="schema_dir",
        default=None,
        help="Schema directory. If not provided, the STIX schemas bundled "
             "with the stix-validator library will be used."
    )

    parser.add_argument(
        "--use-schemaloc",
        dest="use_schemaloc",
        action='store_true',
        default=False,
        help="Use schemaLocation attribute to determine schema locations."
    )

    parser.add_argument(
        "--best-practices",
        dest="best_practices",
        action='store_true',
        default=False,
        help="Check that the document follows authoring best practices."
    )

    parser.add_argument(
        "--profile",
        dest="profile",
        default=None,
        help="Path to STIX Profile .xlsx file."
    )

    parser.add_argument(
        "--quiet",
        dest="quiet",
        action="store_true",
        default=False,
        help="Only print results and errors if they occur."
    )

    parser.add_argument(
        "--json-results",
        dest="json",
        action="store_true",
        default=False,
        help="Print results as raw JSON. This also sets --quiet."
    )

    parser.add_argument(
        "--recursive",
        dest="recursive",
        action="store_true",
        default=False,
        help="Recursively descend into input directories."
    )

    parser.add_argument(
        "--huge-tree",
        dest="huge_tree",
        action="store_true",
        default=False,
        help="Disable libxml2 security restrictions on XML document size."
    )

    return parser


CHECK_CODES = [0,
               201, 202, 203, 204, 205,

               301, 302, 303, 304, 305, 306, 307, 308, 309, 310, 311, 312, 313, 314, 315, 316, 317, 318,

               401, 402,

               501, 502, 503, 504, 505, 506, 507, 508, 509, 510, 511, 512, 513, 514, 515, 516, 517, 518, 519, 520, 521,
               522, 523, 524, 525, 526, 527, 528, 529, 530, 531, 532, 533, 534, 535,

               601, 602, 603, 604, 605, 606, 607, 608, 609, 610, 611, 612, 613, 614,

               701, 702, 703
               ]
