import io
import json
import logging
import sys

import cybox.utils.caches
import stix2
from sdv import codes, errors, scripts

from stix2slider.convert_stix import convert_bundle
from stix2slider.options import setup_logger, get_validator_options
# import stix2slider.utils  # flake8: noqa

# Module-level logger
log = logging.getLogger(__name__)


def slide_file(fn, encoding="utf-8"):
    cybox.utils.caches.cache_clear()

    setup_logger(fn)
    validator_options = get_validator_options()

    with io.open(fn, "r", encoding=encoding) as json_data:
        json_content = json.load(json_data)

    obj = stix2.parse(json_content, allow_custom=True)
    stix_package = convert_bundle(obj)

    if stix_package:
        xml = stix_package.to_xml(encoding=None)
        validator_options.in_files = io.StringIO(xml)

        try:
            scripts.set_output_level(validator_options)

            validation_results = scripts.validate_file(
                validator_options.in_files,
                validator_options
            )
            results = {stix_package.id_: validation_results}

            # Print stix-validator results
            scripts.print_results(results, validator_options)
        except (errors.ValidationError, IOError) as ex:
            scripts.error(
                "Validation error occurred: '%s'" % str(ex),
                codes.EXIT_VALIDATION_ERROR
            )
        except Exception:
            log.exception("Fatal error occurred", extra={'ecode': 0})
            sys.exit(codes.EXIT_FAILURE)

        return xml


def slide_string(string):
    cybox.utils.caches.cache_clear()

    obj = stix2.parse(string)
    setup_logger(obj["id"])
    validator_options = get_validator_options()

    stix_package = convert_bundle(obj)

    if stix_package:
        xml = stix_package.to_xml(encoding=None)
        validator_options.in_files = io.StringIO(xml)

        try:
            scripts.set_output_level(validator_options)

            validation_results = scripts.validate_file(
                validator_options.in_files,
                validator_options
            )
            results = {stix_package.id_: validation_results}

            # Print stix-validator results
            scripts.print_results(results, validator_options)
        except (errors.ValidationError, IOError) as ex:
            scripts.error(
                "Validation error occurred: '%s'" % str(ex),
                codes.EXIT_VALIDATION_ERROR
            )
        except Exception:
            log.exception("Fatal error occurred", extra={'ecode': 0})
            sys.exit(codes.EXIT_FAILURE)

        return xml


def slide_bundle(bundle):
    cybox.utils.caches.cache_clear()

    setup_logger(bundle["id"])
    stix_package = convert_bundle(bundle)
    validator_options = get_validator_options()

    if stix_package:
        xml = stix_package.to_xml(encoding=None)
        validator_options.in_files = io.StringIO(xml)

        try:
            scripts.set_output_level(validator_options)

            validation_results = scripts.validate_file(
                validator_options.in_files,
                validator_options
            )
            results = {stix_package.id_: validation_results}

            # Print stix-validator results
            scripts.print_results(results, validator_options)
        except (errors.ValidationError, IOError) as ex:
            scripts.error(
                "Validation error occurred: '%s'" % str(ex),
                codes.EXIT_VALIDATION_ERROR
            )
        except Exception:
            log.exception("Fatal error occurred", extra={'ecode': 0})
            sys.exit(codes.EXIT_FAILURE)

        return xml
