import os

from stix2slider.cli import slide_file
from stix2slider.options import initialize_options, set_option_value
from stix2slider.utils import find_dir


def test_override_default_namespace():
    directory = os.path.dirname(__file__)
    json_idioms_dir = find_dir(directory, "idioms-json-2.0")
    json_path = os.path.join(json_idioms_dir, "cve-in-exploit-target.json")

    initialize_options()
    set_option_value("use_namespace", "somenamespace http://somenamespace.com")
    converted_xml = slide_file(json_path)

    assert "xmlns:somenamespace=\"http://somenamespace.com\"" in converted_xml
    assert "id=\"somenamespace:" in converted_xml
