import logging
import os

from six import text_type

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
        enable: Messages to enable.
        disable: Messages to disable.
        silent: If set, no stix2-slider log messages will be emitted.
        message_log_directory: If set, it will write all emitted messages to
            file. It will use the filename or package id to name the log file.

    Note:
        All messages are turned on by default.
    """
    def __init__(self, cmd_args=None, file_=None,
                 no_squirrel_gaps=False,
                 enable="", disable="",
                 silent=False, message_log_directory=None,
                 output_directory=None, log_level="INFO"):

        if cmd_args is not None:
            if hasattr(cmd_args, "file_"):
                self.file_ = cmd_args.file_
            self.no_squirrel_gaps = cmd_args.no_squirrel_gaps

            self.enable = cmd_args.enable
            self.disable = cmd_args.disable
            self.silent = cmd_args.silent
            self.message_log_directory = cmd_args.message_log_directory
            self.log_level = cmd_args.log_level
            if hasattr(cmd_args, "output_directory"):
                self.output_directory = cmd_args.output_directory

        else:
            self.file_ = file_
            self.no_squirrel_gaps = no_squirrel_gaps
            self.enable = enable
            self.disable = disable
            self.silent = silent
            self.message_log_directory = message_log_directory
            self.log_level = log_level
            self.output_directory = output_directory

        # Convert string of comma-separated checks to a list,
        # and convert check code numbers to names. By default all messages are
        # enabled.
        if self.disable:
            self.disabled = self.disable.split(",")
            self.disabled = [CHECK_CODES[x] if x in CHECK_CODES else x
                             for x in self.disabled]
        else:
            self.disabled = []

        if self.enable:
            self.enabled = self.enable.split(",")
            self.enabled = [CHECK_CODES[x] if x in CHECK_CODES else x
                            for x in self.enabled]
        else:
            self.enabled = [text_type(x) for x in CHECK_CODES]

        self.marking_container = None


def initialize_options(slider_args=None):
    global ALL_OPTIONS
    if not ALL_OPTIONS:
        ALL_OPTIONS = SliderOptions(slider_args)

        if ALL_OPTIONS.silent and ALL_OPTIONS.message_log_directory:
            warn("Both console and output log have disabled messages.", 202)


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
    msg_id = text_type(msg_id)

    if get_option_value("silent"):
        return False

    if not get_option_value("disabled"):
        return msg_id in get_option_value("enabled")
    else:
        return not (msg_id in get_option_value("disabled"))


# These codes are aligned with elevator_log_messages spreadsheet.
CHECK_CODES = [0,
               201, 202, 203, 204,

               301, 302, 303, 304, 305, 306, 307, 308, 309, 310, 311, 312, 313, 314,

               401, 402,

               501, 502, 503, 504, 505, 506, 507, 508, 509, 510, 511, 512, 513, 514, 515, 516, 517, 518, 519, 520, 521,
               522, 523, 524,

               601, 602, 603, 604, 605, 606, 607, 608, 609, 610, 611,

               701
               ]
