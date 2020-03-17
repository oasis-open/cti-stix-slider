# Standard Library
from argparse import Namespace

# external
import pytest

# internal
from stix2slider import options
from stix2slider.options import (
    SliderOptions, get_option_value, initialize_options
)


@pytest.mark.parametrize("opts", [
    SliderOptions(no_squirrel_gaps=False, use_namespace="foobar", log_level="DEBUG", disabled=[201, 302]),
    {"no_squirrel_gaps": False, "use_namespace": "foobar", "log_level": "DEBUG", "disabled": [201, 302]},
    Namespace(file_=None, no_squirrel_gaps=False, validator_args="", enabled=None, disabled=[201, 302],
              silent=False, message_log_directory=None, output_directory=None, log_level="DEBUG",
              use_namespace="foobar"),
])
def test_setup_options(opts):
    options.ALL_OPTIONS = None  # To make sure we can set it again
    initialize_options(opts)
    assert get_option_value("no_squirrel_gaps") is False
    assert get_option_value("use_namespace") == "foobar"
    assert get_option_value("log_level") == "DEBUG"
    assert get_option_value("disabled") == [201, 302]
