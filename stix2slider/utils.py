# Standard Library
import base64
import os

# external
from mixbox import idgen, namespaces
import stix2


# This is not a final representation of an AIS marking in STIX 2.0
# Only a match from what stix2-elevator creates.
@stix2.v20.CustomMarking(type="ais", properties=[
    ("is_proprietary", stix2.properties.BooleanProperty(required=True)),
    ("is_cisa_proprietary", stix2.properties.BooleanProperty(required=True)),
    ("consent", stix2.properties.EnumProperty(required=True,
                                              allowed=["everyone", "usg", "none"])),
    ("tlp", stix2.properties.EnumProperty(required=True,
                                          allowed=["white", "green", "amber"]))
])
class AISMarkingV20(object):
    pass


@stix2.v21.CustomMarking(type="ais", properties=[
    ("is_proprietary", stix2.properties.BooleanProperty(required=True)),
    ("is_cisa_proprietary", stix2.properties.BooleanProperty(required=True)),
    ("consent", stix2.properties.EnumProperty(required=True,
                                              allowed=["everyone", "usg", "none"])),
    ("tlp", stix2.properties.EnumProperty(required=True,
                                          allowed=["white", "green", "amber"]))
])
class AISMarkingV21(object):
    pass


def find_dir(path, directory):
    """
    Args:
        path: str containing path of the script calling this method.
        directory: str containing directory to find.

    Returns:
        str: A string containing the absolute path to the directory.
        None otherwise.

    Note:
        It only finds directories under the cti-stix-slider package.

    Raises:
        RuntimeError: If trying to access other directories outside of the
        cti-stix-slider package.
    """
    working_dir = path.split("cti-stix-slider")

    if len(working_dir) <= 1 or not all(x for x in working_dir):
        msg = "Verify working directory. Only works under cti-stix-slider"
        raise RuntimeError(msg)

    working_dir = working_dir[0]

    for root, dirs, files in os.walk(working_dir, topdown=True):
        if directory in dirs and 'stix2slider' in dirs:
            found_dir = os.path.join(root, directory)
            return os.path.abspath(found_dir)


def set_default_namespace(prefix, ns_uri, schemaLocation=None):
    """Method to override the mixbox and slider 'example' namespace."""
    new_namespace = namespaces.Namespace(ns_uri, prefix, schemaLocation)
    idgen.set_id_namespace(new_namespace)


def decode_base64(base64_message):
    base64_bytes = base64_message.encode('utf-8')
    message_bytes = base64.b64decode(base64_bytes)
    return message_bytes.decode('utf-8')
