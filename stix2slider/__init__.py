import io
import json

import stix2

from stix2slider.convert_stix import convert_bundle
from stix2slider.options import setup_logger
import stix2slider.utils  # flake8: noqa


def slide_file(fn, encoding="utf-8"):
    setup_logger(fn)

    with io.open(fn, "r", encoding=encoding) as json_data:
        json_content = json.load(json_data)

    obj = stix2.parse(json_content)
    # TODO: validate STIX 2.0 content - what to do if it is invalid??
    stix_package = convert_bundle(obj)

    if stix_package:
        return stix_package.to_xml(encoding=None)


def slide_string(string):
    obj = stix2.parse(string)
    setup_logger(obj["id"])

    stix_package = convert_bundle(obj)

    if stix_package:
        return stix_package.to_xml(encoding=None)


def slide_bundle(bundle):
    setup_logger(bundle["id"])
    stix_package = convert_bundle(bundle)

    if stix_package:
        return stix_package.to_xml(encoding=None)
