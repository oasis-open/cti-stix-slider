from __future__ import print_function

import os

from six import StringIO
from six.moves import zip
from stix2slider.cli import slide_file
from stix2slider.options import initialize_options
from stix2slider.utils import find_dir
from stixmarx import markingmap, xml

TESTED_JSON_FILES = []
JSON_FILENAMES = []
MASTER_XML_FILES = []

IGNORE = (u"id", u"idref", u"timestamp", u"object_reference", u"phase_id", u"kill_chain_id")


def text_compare(t1, t2):
    if not t1 and not t2:
        return True
    if t1 == '*' or t2 == '*':
        return True
    return (t1 or '').strip() == (t2 or '').strip()


def xml_compare(x1, x2, reporter=None):
    if x1.tag in IGNORE:
        return True
    if x1.tag != x2.tag:
        if reporter:
            reporter('Tags do not match: %s and %s' % (x1.tag, x2.tag))
        return False
    for name, value in x1.attrib.items():
        if name in IGNORE:
            continue
        if x2.attrib.get(name) != value:
            if reporter:
                reporter('Attributes do not match: %s=%r, %s=%r' %
                         (name, value, name, x2.attrib.get(name)))
            return False
    for name in x2.attrib.keys():
        if name not in x1.attrib:
            if reporter:
                reporter('x2 has an attribute x1 is missing: %s' % name)
            return False
    if not text_compare(x1.text, x2.text):
        if reporter:
            reporter('text: %r != %r' % (x1.text, x2.text))
        return False
    if not text_compare(x1.tail, x2.tail):
        if reporter:
            reporter('tail: %r != %r' % (x1.tail, x2.tail))
        return False
    cl1 = x1.getchildren()
    cl2 = x2.getchildren()
    if len(cl1) != len(cl2):
        if reporter:
            reporter('children length differs, %i != %i' % (len(cl1), len(cl2)))
        return False
    i = 0
    for c1, c2 in zip(cl1, cl2):
        i += 1
        if not xml_compare(c1, c2, reporter=reporter):
            if reporter:
                reporter('children %i do not match: %s' % (i, c1.tag))
            return False
    return True


def marking_compare(x1, x2):
    m_specs_x1 = markingmap._get_marking_specifications(x1)
    m_specs_x2 = markingmap._get_marking_specifications(x2)

    nodeset_x1 = []
    nodeset_x2 = []

    for m_spec in m_specs_x1:
        control = markingmap._get_controlled_structure(m_spec)
        if control is None:
            continue
        nodeset = markingmap._get_marked_nodeset(control)
        if nodeset:
            nodeset_x1.extend(nodeset)

    for m_spec in m_specs_x2:
        control = markingmap._get_controlled_structure(m_spec)
        if control is None:
            continue
        nodeset = markingmap._get_marked_nodeset(control)
        if nodeset:
            nodeset_x2.extend(nodeset)

    for x1, x2 in zip(nodeset_x1, nodeset_x2):
        if xml.is_element(x1) and xml.is_element(x2):
            assert xml_compare(x1, x2, reporter=print)

    assert len(nodeset_x1) == len(nodeset_x2)


def setup_tests(version):
    directory = os.path.dirname(__file__)

    xml_idioms_dir = find_dir(directory, "idioms-xml-from" + "-" + version)
    json_idioms_dir = find_dir(directory, "idioms-json" + "-" + version)

    print("Setting up tests from following directories...")
    print(xml_idioms_dir)
    print(json_idioms_dir)

    for json_filename in sorted(os.listdir(json_idioms_dir)):
        if json_filename.endswith(".json"):
            json_path = os.path.join(json_idioms_dir, json_filename)
            xml_filename = json_filename.replace(".json", ".xml")
            xml_path = os.path.join(xml_idioms_dir, xml_filename)

            if os.path.exists(xml_path):
                loaded_xml = xml.to_etree(xml_path)

                MASTER_XML_FILES.append(loaded_xml)
                JSON_FILENAMES.append(json_filename.split(".")[0])
                TESTED_JSON_FILES.append(json_path)


def test_idiom_mapping(test_file, stored_master):
    """Test fresh conversion from XML to JSON matches stored JSON samples."""
    print("Checking - " + test_file)

    initialize_options()

    converted_new_xml = slide_file(test_file)
    converted_new_xml = StringIO(converted_new_xml)
    converted_new_xml = xml.to_etree(converted_new_xml)

    assert xml_compare(converted_new_xml.getroot(), stored_master.getroot(), reporter=print)
    marking_compare(converted_new_xml.getroot(), stored_master.getroot())


def pytest_generate_tests(metafunc):
    version = os.environ['VERSION']
    setup_tests(version)
    argnames = ["test_file", "stored_master"]
    argvalues = [(x, y) for x, y in zip(TESTED_JSON_FILES, MASTER_XML_FILES)]

    metafunc.parametrize(argnames=argnames, argvalues=argvalues, ids=JSON_FILENAMES, scope="function")
