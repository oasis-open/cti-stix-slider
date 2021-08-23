# Standard Library
import datetime as dt
from functools import cmp_to_key
import time

# external
from cybox.common.environment_variable import (
    EnvironmentVariable, EnvironmentVariableList
)
from cybox.common.hashes import HashList
from cybox.common.object_properties import CustomProperties, Property
from cybox.common.vocabs import VocabString
from cybox.core import Observable, RelatedObject
from cybox.objects.address_object import Address, EmailAddress
from cybox.objects.archive_file_object import ArchiveFile
from cybox.objects.artifact_object import Artifact, Encoding, Packaging
from cybox.objects.as_object import AutonomousSystem
from cybox.objects.custom_object import Custom
from cybox.objects.domain_name_object import DomainName
from cybox.objects.email_message_object import (
    Attachments, EmailHeader, EmailMessage, EmailRecipients, ReceivedLine,
    ReceivedLineList
)
from cybox.objects.file_object import File
from cybox.objects.hostname_object import Hostname
from cybox.objects.http_session_object import (
    HTTPClientRequest, HTTPMessage, HTTPRequestHeader, HTTPRequestHeaderFields,
    HTTPRequestLine, HTTPRequestResponse, HTTPSession
)
from cybox.objects.image_file_object import ImageFile
from cybox.objects.mutex_object import Mutex
from cybox.objects.network_connection_object import (
    Layer7Connections, NetworkConnection, SocketAddress
)
from cybox.objects.network_packet_object import (
    ICMPv4Header, ICMPv4Packet, InternetLayer, NetworkPacket
)
from cybox.objects.network_socket_object import NetworkSocket, SocketOptions
from cybox.objects.pdf_file_object import (
    PDFDocumentInformationDictionary, PDFFile, PDFFileID, PDFFileMetadata,
    PDFTrailer, PDFTrailerList
)
from cybox.objects.port_object import Port
from cybox.objects.process_object import (
    ArgumentList, ChildPIDList, ImageInfo, NetworkConnectionList, Process
)
from cybox.objects.product_object import Product
from cybox.objects.unix_user_account_object import UnixUserAccount
from cybox.objects.uri_object import URI
from cybox.objects.user_account_object import UserAccount
from cybox.objects.win_executable_file_object import (
    Entropy, PEFileHeader, PEHeaders, PEOptionalHeader, PESection,
    PESectionHeaderStruct, PESectionList, WinExecutableFile
)
from cybox.objects.win_file_object import Stream, StreamList, WinFile
from cybox.objects.win_process_object import StartupInfo, WinProcess
from cybox.objects.win_registry_key_object import (
    RegistryValue, RegistryValues, WinRegistryKey
)
from cybox.objects.win_service_object import ServiceDescriptionList, WinService
from cybox.objects.win_user_account_object import WinUser
from cybox.objects.x509_certificate_object import (
    RSAPublicKey, SubjectPublicKey, Validity, X509Cert, X509Certificate,
    X509V3Extensions
)

# internal
from stix2slider.common import (
    AUTONOMOUS_SYSTEM_MAP, DIRECTORY_MAP, EMAIL_MESSAGE_MAP, FILE_MAP,
    HTTP_REQUEST_HEADERS_MAP, IMAGE_FILE_EXTENSION_MAP_2_0,
    IMAGE_FILE_EXTENSION_MAP_2_1, OTHER_EMAIL_HEADERS_MAP,
    PDF_DOCUMENT_INFORMATION_DICT_MAP, PE_BINARY_FILE_HEADER_MAP,
    PE_BINARY_OPTIONAL_HEADER_MAP, PROCESS_MAP_2_0, PROCESS_MAP_2_1,
    REGISTRY_KEY_MAP, REGISTRY_VALUE_MAP, SOCKET_MAP_2_0, SOCKET_MAP_2_1,
    SOCKET_OPTIONS_MAP, STARTUP_INFO_MAP, USER_ACCOUNT_MAP,
    WINDOWS_PROCESS_EXTENSION_MAP, WINDOWS_SERVICE_EXTENSION_MAP,
    X509_CERTIFICATE_MAP, X509_V3_EXTENSIONS_TYPE_MAP, add_host, convert_id2x,
    convert_pe_type, is_windows_directory
)
from stix2slider.options import error, get_option_value, info, warn
from stix2slider.utils import decode_base64

_EXTENSIONS_MAP = {
    "archive-ext": ArchiveFile,
    "ntfs-ext": WinFile,
    "pdf-ext": PDFFile,
    "raster-image-ext": ImageFile,
    "windows-pebinary-ext": WinExecutableFile,
    "windows-process-ext": WinProcess,
    "windows-service-ext": WinService,
    # handled elsewhere:
    # "http-request-ext": NetworkConnection
    # "icmp-ext": NetworkConnection
    # "socket-ext": NetworkConnection
    # "tcp-ext": NetworkConnection
    # "unix-account_ext": UserAccount
}


_STIX1X_OBJS = {}


_STIX1X_OBS_GLOBAL = {}


def add_to_stix1x_observable_from_stix2x_id(id2x, obs1x):
    global _STIX1X_OBS_GLOBAL
    _STIX1X_OBS_GLOBAL[id2x] = obs1x


def get_stix1x_item_from_stix2x_id(id2x, item_type):
    if id2x in _STIX1X_OBS_GLOBAL:
        if item_type == 'Observable':
            return _STIX1X_OBS_GLOBAL[id2x]
        elif item_type == 'Object':
            return _STIX1X_OBS_GLOBAL[id2x].object_
        elif item_type == 'Properties':
            return _STIX1X_OBS_GLOBAL[id2x].object_.properties
    else:
        # STIX 2.0 cyber observables indexed differently
        if id2x in _STIX1X_OBJS:
            return _STIX1X_OBJS[id2x]
        return None


def sort_objects_into_processing_order_for_hashes(objs):
    tuple_list = [(k, v) for k, v in objs.items()]
    return sorted(tuple_list, key=lambda x: x[0])


def determine_1x_object_type(c_o_object):
    basic_type = c_o_object["type"]
    if basic_type in ["file"]:
        if "extensions" in c_o_object:
            spec_extensions = []
            for ex in list(c_o_object["extensions"].keys()):
                if ex in ["archive-ext", "ntfs-ext", "pdf-ext", "raster-image-ext", "windows-pebinary-ext"]:
                    spec_extensions.append(ex)
                else:
                    warn("Custom extension %s of STIX 2.1 in %s are not supported", 531, ex, c_o_object["id"])
            if len(spec_extensions) == 1:
                return _EXTENSIONS_MAP[spec_extensions[0]]
            elif len(spec_extensions) > 1:
                warn("Multiple File extensions in %s not supported yet, using first %s", 502, c_o_object["id"], spec_extensions[0])
                return _EXTENSIONS_MAP[spec_extensions[0]]
        else:
            return File
    if basic_type in ["process"]:
        if "extensions" in c_o_object:
            extensions = list(c_o_object["extensions"].keys())
            object_type_1x = None
            for e in extensions:
                if e == "windows-service-ext":
                    return WinService
                if e == "windows-process-ext":
                    object_type_1x = WinProcess
            if object_type_1x:
                return object_type_1x
        else:
            return Process
    if basic_type in ["user-account"]:
        if "extensions" in c_o_object or c_o_object.get("account_type") == "unix":
            # only one extension is defined, for UNIX, which is cover by the basic user account in STIX 1.x
            return UnixUserAccount
        else:
            if "account_type" in c_o_object:
                if c_o_object["account_type"] in ["windows-local", "windows-domain"]:
                    return WinUser
        # otherwise
        return UserAccount
    if basic_type in ["artifact"]:
        return Artifact
    if basic_type in ["autonomous-system"]:
        return AutonomousSystem
    if basic_type in ["directory"]:
        return File
    if basic_type in ["domain-name"]:
        return DomainName
    if basic_type in ["email-message"]:
        return EmailMessage
    if basic_type in ['ipv4-addr', 'ipv6-addr', 'mac-addr']:
        return Address
    if basic_type in ['email-addr']:
        return EmailAddress
    if basic_type in ['mutex']:
        return Mutex
    if basic_type in ['network-traffic']:
        return NetworkConnection
    if basic_type in ['software']:
        return Product
    if basic_type in ['url']:
        return URI
    if basic_type in ['windows-registry-key']:
        return WinRegistryKey
    if basic_type in ['x509-certificate']:
        return X509Certificate
    else:
        return Custom


def convert_value(value, typeInfo, key):
    if getattr(typeInfo, "type_", None) and getattr(typeInfo.type_, "default_datatype", None) and typeInfo.type_.default_datatype == 'hexBinary':
        if isinstance(value, dt.datetime):
            x = int(time.mktime(value.timetuple()))
            return str(hex(x))[2:]
        elif not key.endswith("hex"):
            return str(hex(int(value)))[2:]
        else:
            return value
    else:
        return value


def convert_obj(obj2x, obj1x, mapping_table, obs2x_id, print_warn=True, specific_ignore_list=[]):
    ignore_list = ["extensions", "defanged", "id", "spec_version", "type"]
    ignore_list.extend(specific_ignore_list)
    for key, value in obj2x.items():
        if key in mapping_table:
            mapping_table[key].__set__(obj1x, convert_value(value, mapping_table[key], key))
        elif print_warn and key not in ignore_list:
            warn("%s is not representable in a STIX 1.x %s.  Found in %s", 503, key, obj1x.__class__.__name__, obs2x_id)


def handle_service_dll_refs(windows_service, process1x, selector, obs2x_id):
    if "service_dll_refs" in windows_service:
        file_object = get_stix1x_item_from_stix2x_id(windows_service["service_dll_refs"][0], selector)
        if file_object and file_object.file_name:
            process1x.service_dll = file_object.file_name
        else:
            warn("%s is not found. See %s", 306, windows_service["service_dll_refs"][0], obs2x_id)
        if len(windows_service["service_dll_refs"]) > 1:
            for dll_ref in windows_service["service_dll_refs"][1:]:
                warn(
                    "%s in STIX 2.x has multiple %s, only one is allowed in STIX 1.x. Using first in list - %s omitted",
                    401,
                    obs2x_id, "service_dll_refs", dll_ref)


def warn_about_missing_ref(ref, id):
    if get_option_value("version_of_stix2x") == "2.0":
        warn("%s is not found. See %s", 306, ref, id)
    else:
        warn("%s referenced in %s is not found", 317, ref, id)


def handle_ref(obj2x, obj1x, prop2x, prop1x, selector, sub_obj1x=None, accessor=None, obs2x_id=None):
    if prop2x in obj2x:
        item = get_stix1x_item_from_stix2x_id(obj2x[prop2x], selector)
        if item:
            if accessor:
                value = accessor(item)
                if not value:
                    warn("Unable to populate sub-property %s of %s, therefore %s cannot be represented in the STIX 1.x %s",
                         529,
                         prop1x,
                         item.parent.id_,
                         prop2x,
                         obj1x.__class__.__name__)
                    return
            else:
                value = item
            if sub_obj1x:
                sub_obj1x.__setattr__(prop1x, value)
            else:
                obj1x.__setattr__(prop1x, value)
        else:
            warn_about_missing_ref(obj2x[prop2x], obs2x_id if obs2x_id else obj2x["id"])


def handle_refs(obj2x, obj1x, prop2x, prop1x, selector, list_type=None, sub_obj1x=None, obs2x_id=None, accessor=None):
    if prop2x in obj2x:
        if list_type:
            if sub_obj1x:
                sub_obj1x.__setattr__(prop1x, list_type())
            else:
                obj1x.__setattr__(prop1x, list_type())
        for ref in obj2x[prop2x]:
            item = get_stix1x_item_from_stix2x_id(ref, selector)
            if item:
                if accessor:
                    ref_obj = accessor(item)
                else:
                    ref_obj = item
                if sub_obj1x:
                    getattr(sub_obj1x, prop1x).append(ref_obj)
                else:
                    getattr(obj1x, prop1x).append(ref_obj)
            else:
                warn_about_missing_ref(obj2x[prop2x], obs2x_id if obs2x_id else obj2x["id"])


def add_hashes_property(obj, hash_type, value):
    if hash_type == "MD5":
        obj.md5 = value
    elif hash_type == "SHA-1":
        obj.sha1 = value
    elif hash_type == "SHA-224":
        obj.sha224 = value
    elif hash_type == "SHA-256":
        obj.sha256 = value
    elif hash_type == "SHA-384":
        obj.sha384 = value
    elif hash_type == "SHA-512":
        obj.sha512 = value
    else:
        warn("Unknown hash type %s used in %s", 302, hash_type, obj.id_)


def convert_artifact_c_o(art2x, art1x, obs2x_id):
    if "mime_type" in art2x:
        art1x.content_type = art2x["mime_type"]
    # it is illegal in STIX 2.x to have both a payload_bin and url property - but we don't warn about it here
    if "payload_bin" in art2x:
        art1x.packed_data = art2x["payload_bin"]
    if "url" in art2x:
        art1x.raw_artifact_reference = art2x["url"]
    if "hashes" in art2x:
        art1x.hashes = HashList()
        for k, v in art2x["hashes"].items():
            add_hashes_property(art1x.hashes, k, v)
    encoding = Encoding(algorithm="Base64")
    packaging = Packaging(encoding=encoding)
    art1x.packaging = packaging


def convert_autonomous_system_c_o(as2x, as1x, obs2x_id):
    convert_obj(as2x, as1x, AUTONOMOUS_SYSTEM_MAP, obs2x_id)


def convert_domain_name_c_o(dn2x, dn1x, obs2x_id):
    dn1x.value = dn2x["value"]
    dn1x.type_ = "FQDN"
    if "resolves_to_refs" in dn2x:
        if get_option_value("version_of_stix2x") == "2.0":
            for ref in dn2x["resolves_to_refs"]:
                item = get_stix1x_item_from_stix2x_id(ref, "Properties")
                if item:
                    obj = item
                    dn1x.add_related(obj, "Resolved_To", inline=True)
                else:
                    warn("%s is not found. See %s", 306, ref, obs2x_id)


def convert_archive_file_extension(archive_ext, file1x, obs2x_id):
    if "version" in archive_ext and get_option_value("version_of_stix2x") == "2.0":
        file1x.version = archive_ext["version"]
    if "comment" in archive_ext:
        file1x.comment = archive_ext["comment"]
    if get_option_value("version_of_stix2x") == "2.0":
        handle_refs(archive_ext, file1x, "contains_refs", "archived_file", 'Properties', obs2x_id=obs2x_id)


def convert_pdf_file_extension(pdf_ext, file1x, obs2x_id):
    if "version" in pdf_ext:
        file1x.version = pdf_ext["version"]
    if "is_optimized" in pdf_ext or "document_info_dict" in pdf_ext:
        file1x.metadata = PDFFileMetadata()
        if "is_optimized" in pdf_ext:
            file1x.metadata.optimized = pdf_ext["is_optimized"]
        if "document_info_dict" in pdf_ext:
            file1x.metadata.document_information_dictionary = PDFDocumentInformationDictionary()
            convert_obj(pdf_ext["document_info_dict"],
                        file1x.metadata.document_information_dictionary,
                        PDF_DOCUMENT_INFORMATION_DICT_MAP,
                        obs2x_id)
    if "pdfid0" in pdf_ext or "pdfid1" in pdf_ext:
        warn("Order may not be maintained for pdfids in %s", 514, obs2x_id)
        file1x.trailers = PDFTrailerList()
        trailer = PDFTrailer()
        file1x.trailers.trailer.append(trailer)
        trailer.id_ = PDFFileID()
        if "pdfid0" in pdf_ext:
            trailer.id_.id_string.append(pdf_ext["pdfid0"])
        if "pdfid1" in pdf_ext:
            trailer.id_.id_string.append(pdf_ext["pdfid1"])


def convert_image_file_extension(image_ext, file1x, obs2x_id):
    convert_obj(image_ext, file1x,
                IMAGE_FILE_EXTENSION_MAP_2_0 if get_option_value("version_of_stix2x") == "2.0" else IMAGE_FILE_EXTENSION_MAP_2_1,
                obs2x_id,
                specific_ignore_list=["exif_tags"])
    if "exif_tags" in image_ext:
        exif_tags = image_ext["exif_tags"]
        if "Compression" in exif_tags:
            file1x.image_is_compressed = (exif_tags["Compression"] != 1)
        else:
            warn("%s is not representable in a STIX 1.x %s.  Found in %s", 503,
                 "exif_tags",
                 "ImageFile",
                 obs2x_id)


def convert_windows_pe_binary_file_extension(pe_bin_ext, file1x, obs2x_id):
    if "imphash" in pe_bin_ext:
        if not file1x.headers.hashes:
            file1x.headers.hashes = HashList()
        # imphash appears to be an MD5 hash
        add_hashes_property(file1x.headers.file_header.hashes, "MD5", pe_bin_ext["imphash"])
    if "number_of_sections" in pe_bin_ext:
        warn("%s is not representable in a STIX 1.x %s.  Found in  %s",
             503,
             "number_of_sections", "WinExecutableFile",
             obs2x_id)
    if "pe_type" in pe_bin_ext:
        file1x.type_ = convert_pe_type(pe_bin_ext["pe_type"], obs2x_id)
    if not file1x.headers:
        file1x.headers = PEHeaders()
    if any(x in pe_bin_ext for x in ("machine_hex", "time_date_stamp",
                                     "pointer_to_symbol_table_hex",
                                     "number_of_symbols",
                                     "size_of_optional_header",
                                     "characteristics_hex")
           ):
        file1x.headers.file_header = PEFileHeader()
        convert_obj(pe_bin_ext, file1x.headers.file_header, PE_BINARY_FILE_HEADER_MAP, obs2x_id,
                    specific_ignore_list=["optional_header", "sections", "pe_type"])
    if "file_header_hashes" in pe_bin_ext:
        file1x.headers.file_header.hashes = HashList()
        for k, v in sort_objects_into_processing_order_for_hashes(pe_bin_ext["file_header_hashes"]):
            add_hashes_property(file1x.headers.file_header.hashes, k, v)
    if "optional_header" in pe_bin_ext:
        op_header2x = pe_bin_ext["optional_header"]
        file1x.headers.optional_header = PEOptionalHeader()
        convert_obj(op_header2x, file1x.headers.optional_header, PE_BINARY_OPTIONAL_HEADER_MAP, obs2x_id)
        if "hashes" in op_header2x:
            file1x.headers.optional_header.hashes = HashList()
            for k, v in sort_objects_into_processing_order_for_hashes(op_header2x["hashes"]):
                add_hashes_property(file1x.headers.optional_header.hashes, k, v)
    if "sections" in pe_bin_ext:
        file1x.sections = PESectionList()
        for s in pe_bin_ext["sections"]:
            section = PESection()
            file1x.sections.section.append(section)
            if "name" in s or "size" in s:
                section.section_header = PESectionHeaderStruct()
                if "name" in s:
                    section.section_header.name = s["name"]
                if "size" in s:
                    section.section_header.size_of_raw_data = s["size"]
            if "entropy" in s:
                section.entropy = Entropy()
                section.entropy.value = s["entropy"]
            if "hashes" in s:
                section.data_hashes = HashList()
                for k, v in sort_objects_into_processing_order_for_hashes(s["hashes"]):
                    add_hashes_property(section.data_hashes, k, v)


def convert_ntfs_file_extension(ntfs_ext, file1x, obs2x_id):
    if "sid" in ntfs_ext:
        file1x.security_id = ntfs_ext["sid"]
    if "alternate_data_streams" in ntfs_ext:
        file1x.stream_list = StreamList()
        ads_list = ntfs_ext["alternate_data_streams"]
        for ads2x in ads_list:
            ads1x = Stream()
            if "name" in ads2x:
                ads1x.name = ads2x["name"]
            if "size" in ads2x:
                ads1x.size_in_bytes = ads2x["size"]
            if "hashes" in ads2x:
                for k, v in sort_objects_into_processing_order_for_hashes(ads2x["hashes"]):
                    add_hashes_property(ads1x, k, v)
            file1x.stream_list.append(ads1x)


def convert_file_extensions(file2x, file1x, obs2x_id):
    extensions = file2x["extensions"]
    if "archive-ext" in extensions:
        convert_archive_file_extension(extensions["archive-ext"], file1x, obs2x_id)
    if "pdf-ext" in extensions:
        convert_pdf_file_extension(extensions["pdf-ext"], file1x, obs2x_id)
    if "ntfs-ext" in extensions:
        convert_ntfs_file_extension(extensions["ntfs-ext"], file1x, obs2x_id)
    if "raster-image-ext" in extensions:
        convert_image_file_extension(extensions["raster-image-ext"], file1x, obs2x_id)
    if "windows-pebinary-ext" in extensions:
        convert_windows_pe_binary_file_extension(extensions["windows-pebinary-ext"], file1x, obs2x_id)


def handle_parent_directory_ref(file2x, file1x, selector, obs2x_id=None):
    if "parent_directory_ref" in file2x:
        item = get_stix1x_item_from_stix2x_id(file2x["parent_directory_ref"], selector)
        if item:
            directory_object = item
            directory_string = str(directory_object.full_path)
            file1x.full_path = directory_string + ("\\" if is_windows_directory(directory_string) else "/") + file2x["name"]


def convert_file_c_o(file2x, file1x, obs2x_id):
    if "hashes" in file2x:
        for k, v in sort_objects_into_processing_order_for_hashes(file2x["hashes"]):
            add_hashes_property(file1x, k, v)
    convert_obj(file2x, file1x, FILE_MAP, obs2x_id,
                specific_ignore_list=["is_encrypted", "encryption_algorithm", "decryption_key", "contains_refs",
                                      "hashes", "parent_directory_ref"])
    if get_option_value("version_of_stix2x") == "2.0":
        handle_parent_directory_ref(file2x, file1x, 'Properties', obs2x_id)
    if "is_encrypted" in file2x and get_option_value("version_of_stix2x") == "2.0":
        if file2x["is_encrypted"]:
            if "encryption_algorithm" in file2x:
                file1x.encryption_algorithm = file2x["encryption_algorithm"]
            else:
                info("is_encrypted in %s is true, but no encryption_algorithm is given", 309, obs2x_id)
            if "decryption_key" in file2x:
                file1x.decryption_key = file2x["decryption_key"]
            else:
                info("is_encrypted in %s is true, but no decryption_key is given", 311, obs2x_id)
        else:
            if "encryption_algorithm" in file2x:
                info("is_encrypted in %s is false, but encryption_algorithm is given", 310, obs2x_id)
            if "decryption_key" in file2x:
                info("is_encrypted in %s is false, but decryption_key is given", 312, obs2x_id)
    if "extensions" in file2x:
        convert_file_extensions(file2x, file1x, obs2x_id)
    # in STIX 2.x, there are two contains_ref properties, one in the basic File object, and one on the Archive File extension
    # the slider does not handle the one in the basic File object
    if "contains_refs" in file2x:
        warn("contains_refs in %s not handled", 607, obs2x_id)
    # TODO: content_ref
    return file1x


def convert_directory_c_o(directory2x, file1x, obs2x_id):
    convert_obj(directory2x, file1x, DIRECTORY_MAP, obs2x_id, specific_ignore_list=["contains_refs"])
    if "contains_refs" in directory2x and get_option_value("version_of_stix2x") == "2.0":
        add_related_objects(file1x, directory2x, "contains_refs", "Contains")


def populate_received_line(rl2x, rl1x, obs2x_id):
    # do we need to consider case?
    # can't there be multiple lines with the same prefix??
    if rl2x.startswith("from"):
        rl1x.from_ = rl2x
    elif rl2x.startswith("by"):
        rl1x.by = rl2x
    elif rl2x.startswith("via"):
        rl1x.via = rl2x
    elif rl2x.startswith("with"):
        rl1x.with_ = rl2x
    elif rl2x.startswith("for"):
        rl1x.for_ = rl2x
    elif rl2x.startswith("id"):
        rl1x.id_ = rl2x
    elif rl2x.startswith("timestamp"):
        rl1x.timestamp = rl2x
    else:
        warn("Received Line %s in %s has a prefix that is not representable in STIX 1.x", 507, rl2x), obs2x_id


def convert_email_message_c_o(em2x, em1x, obs2x_id):
    em1x.header = EmailHeader()
    convert_obj(em2x, em1x, EMAIL_MESSAGE_MAP, obs2x_id, print_warn=False)
    if get_option_value("version_of_stix2x") == "2.0":
        handle_ref(em2x, em1x, "from_ref", "from_", 'Properties', em1x.header)
        handle_ref(em2x, em1x, "sender_ref", "sender", 'Properties', em1x.header)
        handle_refs(em2x, em1x, "to_refs", "to", 'Properties', sub_obj1x=em1x.header, list_type=EmailRecipients)
        handle_refs(em2x, em1x, "cc_refs", "cc", 'Properties', sub_obj1x=em1x.header, list_type=EmailRecipients)
        handle_refs(em2x, em1x, "bcc_refs", "bcc", 'Properties', sub_obj1x=em1x.header, list_type=EmailRecipients)
    if "content_type" in em2x:
        em1x.header.content_type = em2x["content_type"]
    if "received_lines" in em2x:
        em1x.header.received_lines = ReceivedLineList()
        for rl2x in em2x["received_lines"]:
            rl1x = ReceivedLine()
            em1x.header.received_lines.append(rl1x)
            populate_received_line(rl2x, rl1x, obs2x_id)
    if "additional_header_fields" in em2x:
        convert_obj(em2x["additional_header_fields"], em1x.header, OTHER_EMAIL_HEADERS_MAP, obs2x_id)
        # TODO: what was the purpose of this warning??
        # warn("STIX 1.x can only store the body and headers of an email message in %s independently", 523, obs2x_id)
    if "raw_email_ref" in em2x and get_option_value("version_of_stix2x") == "2.0":
        handle_ref(em2x, em1x, "raw_email_ref", "raw_body", 'Properties',
                   accessor=lambda x: decode_base64(x.packed_data))
    if "body" in em2x:
        if em2x["is_multipart"]:
            warn("The is_multipart property in %s should be 'false' if the body property is present",
                 313,
                 obs2x_id)
        if not em1x.raw_body:
            em1x.raw_body = em2x["body"]
    else:
        if "body_multipart" in em2x and "is_multipart" in em2x and not em2x["is_multipart"]:
            warn("The is_multipart property in %s should not be 'false' if the body_multipart property is present",
                 313,
                 obs2x_id)
    if "body_multipart" in em2x:
        if not em2x["is_multipart"]:
            warn("The is_multipart property in %s should be 'true' if the body_multipart property is present",
                 313,
                 obs2x_id)
        attachments = []
        for part in em2x["body_multipart"]:
            # content_disposition is optional, so we can't depend upon it
            # if "content_disposition" in part and part["content_disposition"].find("attachment"):
            if "body_raw_ref" in part:
                if get_option_value("version_of_stix2x") == "2.0":
                    item = get_stix1x_item_from_stix2x_id(part["body_raw_ref"], 'Properties')
                    if item:
                        obj = item
                        # TODO: can we handle other object/content types?
                        if isinstance(obj, File) or isinstance(obj, Artifact):
                            attachments.append(obj)
                    else:
                        warn("%s is not found. See %s", 306, part["body_raw_ref"], obs2x_id)
            if "body" in part:
                em1x.raw_body = part["body"]
        if attachments:
            em1x.attachments = Attachments()
            for a in attachments:
                em1x.add_related(a, "Contains", inline=True)
                em1x.attachments.append(a.parent.id_)
    else:
        if em2x["is_multipart"]:
            warn("The is_multipart property in %s should be 'false' if the body_multipart property is not present",
                 313,
                 obs2x_id)


def add_related_objects(obj1x, obj2x, relationship2x, relationship1x):
    for ref in obj2x[relationship2x]:
        item = get_stix1x_item_from_stix2x_id(ref, 'Properties')
        if item:
            obj = item
            obj1x.add_related(obj, relationship1x, inline=True)
        else:
            warn("%s is not found. See %s", 306, ref, obj2x["id"])


def convert_addr_c_o(addr2x, addr1x, obs2x_id):
    # CIDR values are not treated in any different way
    addr1x.address_value = addr2x["value"]
    if addr2x["type"] == 'ipv4-addr':
        addr1x.category = Address.CAT_IPV4
    elif addr2x["type"] == 'ipv6-addr':
        addr1x.category = Address.CAT_IPV6
    elif addr2x["type"] == 'mac-addr':
        addr1x.category = Address.CAT_MAC
    if "resolves_to_refs" in addr2x:
        if get_option_value("version_of_stix2x") == "2.0":
            add_related_objects(addr1x, addr2x, "resolves_to_refs", "Resolved_To")
    if "belongs_to_refs" in addr2x:
        if get_option_value("version_of_stix2x") == "2.0":
            add_related_objects(addr1x, addr2x, "belongs_to_refs", "Belongs_To")


def convert_process_extensions(process2x, process1x, obs2x_id):
    extensions = process2x["extensions"]
    if "windows-process-ext" in extensions:
        windows_process = extensions["windows-process-ext"]
        # include "integrity_level" because it is handled in this method
        convert_obj(windows_process, process1x, WINDOWS_PROCESS_EXTENSION_MAP, obs2x_id,
                    ["startup_info", "integrity_level"])
        if "startup_info" in windows_process:
            process1x.startup_info = StartupInfo()
            convert_obj(windows_process["startup_info"], process1x.startup_info, STARTUP_INFO_MAP)
        elif "integrity_level" in windows_process and get_option_value("version_of_stix2x") == "2.1":
            warn("%s is not representable in a STIX 1.x %s.  Found in  %s", 503,
                 "integrity_level", "WinProcess",
                 obs2x_id)
    if "windows-service-ext" in extensions:
        windows_service = extensions["windows-service-ext"]
        convert_obj(windows_service, process1x, WINDOWS_SERVICE_EXTENSION_MAP, obs2x_id,
                    specific_ignore_list=["descriptions", "service_dll_refs"])
        if get_option_value("version_of_stix2x") == "2.0":
            # handle service_dll_refs later for 2.1
            handle_service_dll_refs(windows_service, process1x, "Properties", obs2x_id)
        if "descriptions" in windows_service:
            process1x.description_list = ServiceDescriptionList()
            for d in windows_service["descriptions"]:
                process1x.description_list.append(d)


def convert_process_c_o(process2x, process1x, obs2x_id):
    convert_obj(process2x,
                process1x,
                PROCESS_MAP_2_0 if get_option_value("version_of_stix2x") == "2.0" else PROCESS_MAP_2_1,
                obs2x_id,
                specific_ignore_list=["cwd", "arguments", "command_line", "environment_variables", "opened_connection_refs",
                                      "binary_ref", "image_ref", "parent_ref", "child_refs", "creator_user_ref"])
    if "cwd" in process2x:
        if not process1x.image_info:
            process1x.image_info = ImageInfo()
        process1x.image_info.current_directory = process2x["cwd"]
    if "arguments" in process2x and get_option_value("version_of_stix2x") == "2.0":
        process1x.argument_list = ArgumentList()
        for a in process2x["arguments"]:
            process1x.argument_list.append(a)
    if "command_line" in process2x:
        if not process1x.image_info:
            process1x.image_info = ImageInfo()
        process1x.image_info.command_line = process2x["command_line"]
    if "environment_variables" in process2x:
        process1x.environment_variable_list = EnvironmentVariableList()
        for k, v in process2x["environment_variables"].items():
            ev = EnvironmentVariable()
            process1x.environment_variable_list.append(ev)
            ev.name = k
            ev.value = v
    if "opened_connection_refs" in process2x:
        if get_option_value("version_of_stix2x") == "2.0":
            process1x.network_connection_list = NetworkConnectionList()
            for conn_ref in process2x["opened_connection_refs"]:
                item = get_stix1x_item_from_stix2x_id(conn_ref, 'Properties')
                if item:
                    process1x.network_connection_list.append(item)
                else:
                    warn("%s is not found. See %s", 306, conn_ref, obs2x_id)
    if ("binary_ref" in process2x and get_option_value("version_of_stix2x") == "2.0" or
            "image_ref" in process2x and get_option_value("version_of_stix2x") == "2.1"):
        if "binary_ref" in process2x:
            ref = "binary_ref"
        elif "image_ref" in process2x:
            ref = "image_ref"
        if not process1x.image_info:
            process1x.image_info = ImageInfo()
        # should it be the full path?
        if get_option_value("version_of_stix2x") == "2.0":
            handle_ref(process2x, process1x, ref, "file_name",
                       'Properties', process1x.image_info, accessor=lambda x: x.file_name, obs2x_id=obs2x_id)
            if not process1x.image_info.file_name:
                process1x.image_info = None
    if get_option_value("version_of_stix2x") == "2.0":
        handle_ref(process2x, process1x, "parent_ref", "parent_pid", 'Properties', accessor=lambda x: x.pid)
        handle_refs(process2x, process1x, "child_refs", "child_pid_list", 'Properties', list_type=ChildPIDList, accessor=lambda x: x.pid)
        handle_ref(process2x, process1x, "creator_user_ref", "username", 'Properties', accessor=lambda x: x.username)
    if "extensions" in process2x:
        convert_process_extensions(process2x, process1x, obs2x_id)


def convert_address_ref(obj2x, obj1x, direction, selector):
    prop2_prefix = "source" if direction == "src" else "destination"
    add_property2 = direction + "_ref"
    port_property2 = direction + "_port"
    sa = getattr(obj1x, prop2_prefix + "_socket_address", None)
    if add_property2 in obj2x:
        item = get_stix1x_item_from_stix2x_id(obj2x[add_property2], selector)
        if item:
            if not sa:
                sa = SocketAddress()
            obj = item
            if isinstance(obj, Address):
                sa.ip_address = obj
            elif isinstance(obj, DomainName):
                sa.hostname = Hostname()
                sa.hostname.hostname_value = obj.value
        else:
            warn("%s is not found. See %s", 306, obj2x[add_property2], obj2x["id"])
    if port_property2 in obj2x:
        if not sa:
            sa = SocketAddress()
        sa.port = Port()
        sa.port.port_value = obj2x[port_property2]
    return sa


def convert_network_traffic_to_http_session(http_request_ext, nc, obs2x_id):
    obj1x = HTTPSession()
    nc.layer7_connections = Layer7Connections()
    nc.layer7_connections.http_session = obj1x
    rr = HTTPRequestResponse()
    obj1x.http_request_response.append(rr)
    rr.http_client_request = HTTPClientRequest()
    request_line = HTTPRequestLine()
    request_line.http_method = http_request_ext["request_method"]
    request_line.value = http_request_ext["request_value"]
    if "request_version" in http_request_ext:
        request_line.version = http_request_ext["request_version"]
    rr.http_client_request.http_request_line = request_line
    if "request_header" in http_request_ext:
        rr.http_client_request.http_request_header = HTTPRequestHeader()
        rr.http_client_request.http_request_header.parsed_header = HTTPRequestHeaderFields()
        convert_obj(http_request_ext["request_header"],
                    rr.http_client_request.http_request_header.parsed_header,
                    HTTP_REQUEST_HEADERS_MAP,
                    obs2x_id,
                    specific_ignore_list=["Host", "From", "Referer", "X_Wap_Profile"])
        if "Host" in http_request_ext["request_header"]:
            rr.http_client_request.http_request_header.parsed_header.host = \
                add_host(http_request_ext["request_header"]["Host"])
        if "From" in http_request_ext["request_header"]:
            rr.http_client_request.http_request_header.parsed_header.from_ = \
                EmailAddress(http_request_ext["request_header"]["From"])
        if "Referer" in http_request_ext["request_header"]:
            rr.http_client_request.http_request_header.parsed_header.referer = \
                URI(http_request_ext["request_header"]["Referer"])
        if "X_Wap_Profile" in http_request_ext["request_header"]:
            rr.http_client_request.http_request_header.parsed_header.x_wap_profile = \
                URI(http_request_ext["request_header"]["X_Wap_Profile"])
    if "message_body_length" in http_request_ext or "message_body_data_ref" in http_request_ext:
        body = HTTPMessage()
        if "message_body_length" in http_request_ext:
            body.length = http_request_ext["message_body_length"]
        if "message_body_data_ref" in http_request_ext:
            if get_option_value("version_of_stix2x") == "2.0":
                item = get_stix1x_item_from_stix2x_id(http_request_ext["message_body_data_ref"], 'Properties')
                if item:
                    artifact_obj = item
                    body.message_body = artifact_obj.packed_data
                else:
                    warn("%s is not found. See %s", 306, http_request_ext["message_body_length"], obs2x_id)
        rr.http_client_request.http_message_body = body


def convert_network_traffic_to_network_icmp_packet(icmp_ext, nc, obs2x_id):
    obj1x = NetworkPacket()
    obj1x.internet_layer = InternetLayer()
    info("Assuming imcp packet in %s is v4", 701, obs2x_id)
    icmpv4 = ICMPv4Packet()
    icmpv4.icmpv4_header = ICMPv4Header()
    icmpv4.icmpv4_header.type_ = icmp_ext["icmp_type_hex"]
    icmpv4.icmpv4_header.code = icmp_ext["icmp_code_hex"]
    obj1x.internet_layer.icmpv4 = icmpv4
    nc.add_related(obj1x, VocabString("ICMP_Packet"), inline=True)


def convert_network_traffic_to_network_socket(socket_ext, nc, obs2x_id):
    obj1x = NetworkSocket()
    convert_obj(socket_ext,
                obj1x,
                SOCKET_MAP_2_0 if get_option_value("version_of_stix2x") == "2.0" else SOCKET_MAP_2_1,
                obs2x_id,
                specific_ignore_list=["options"])
    if "options" in socket_ext:
        obj1x.options = SocketOptions()
        convert_obj(socket_ext["options"],
                    obj1x.options,
                    SOCKET_OPTIONS_MAP,
                    obs2x_id)
    nc.add_related(obj1x, VocabString("Related_Socket"), inline=True)
    # obj1x.local_address = convert_address_ref(obj2x, "src")
    # obj1x.remote_address = convert_address_ref(obj2x, "dst")


def convert_network_traffic_c_o(obj2x, obj1x, obs2x_id):
    obj1x.source_socket_address = convert_address_ref(obj2x, obj1x, "src", 'Properties')
    obj1x.destination_socket_address = convert_address_ref(obj2x, obj1x, "dst", 'Properties')
    if "extensions" in obj2x:
        extensions = obj2x["extensions"]
        if "socket-ext" in extensions and get_option_value("version_of_stix2x") == "2.0":
            convert_network_traffic_to_network_socket(extensions["socket-ext"], obj1x, obs2x_id)
        elif "icmp-ext" in extensions and get_option_value("version_of_stix2x") == "2.0":
            convert_network_traffic_to_network_icmp_packet(extensions["icmp-ext"], obj1x, obs2x_id)
        elif "http-request-ext" in extensions:
            convert_network_traffic_to_http_session(extensions["http-request-ext"], obj1x, obs2x_id)
        elif "tcp-ext" in extensions:
            warn("tcp-ext in %s not handled, yet", 609, obs2x_id)
    if "protocols" in obj2x:
        warn("%s property in %s not handled, yet", 608, "protocols", obs2x_id)
    if "src_payload_ref" in obj2x:
        if get_option_value("version_of_stix2x") == "2.0":
            item = get_stix1x_item_from_stix2x_id(obj2x["src_payload_ref"], 'Properties')
            if item:
                obj = item
                obj1x.add_related(convert_artifact_c_o(obj), "Contains", inline=True)
            else:
                warn("%s is not found. See %s", 306, obj2x["src_payload_ref"], obs2x_id)
    # how is is_active related to tcp_state?
    for name in ("start", "end", "src_byte_count", "dst_byte_count", "src_packets", "dst_packets", "ipfix",
                 "src_payload_ref", "dst_payload_ref", "encapsulates_refs", "encapsulated_by_ref"):
        if name in obj2x:
            warn("%s is not representable in a STIX 1.x %s.  Found in %s",
                 503,
                 name, "NetworkConnection", obs2x_id)


def convert_software_c_o(soft2x, prod1x, obs2x_id):
    prod1x.product = soft2x["name"]
    if "cpe" in soft2x:
        warn("cpe is not representable in a STIX 1.x Product.  Found in %s", 503, obs2x_id)
    if "swid" in soft2x:
        warn("swid is not representable in a STIX 1.x Product.  Found in %s", 503, obs2x_id)
    if "languages" in soft2x:
        prod1x.language = soft2x["languages"][0]
        if len(soft2x["languages"]) > 1:
            for lang in soft2x["languages"][1:]:
                warn("%s in STIX 2.x has multiple %s, only one is allowed in STIX 1.x. Using first in list - %s omitted",
                     401, obs2x_id, "languages", lang)

    if "vendor" in soft2x:
        prod1x.vendor = soft2x["vendor"]
    if "version" in soft2x:
        prod1x.version = soft2x["version"]


def convert_unix_account_extensions(ua2x, ua1x, obs2x_id):
    if "extensions" in ua2x or ("account_type" in ua2x and ua2x["account_type"] == "unix"):
        # must be unix-account-ext
        if "user_id" in ua2x:
            ua1x.user_id = int(ua2x["user_id"])
    if "extensions" in ua2x:
        unix_account_ext = ua2x["extensions"]["unix-account-ext"]
        if "gid" in unix_account_ext:
            ua1x.group_id = unix_account_ext["gid"]
        if "groups" in unix_account_ext:
            for g in unix_account_ext["groups"]:
                warn("The 'groups' property of unix-account-ext contains strings, but the STIX 1.x property expects integers in %s",
                     515,
                     obs2x_id)
        if "home_dir" in unix_account_ext:
            ua1x.home_directory = unix_account_ext["home_dir"]
        if "shell" in unix_account_ext:
            ua1x.login_shell = unix_account_ext["shell"]


def convert_user_account_c_o(ua2x, ua1x, obs2x_id):
    convert_obj(ua2x, ua1x, USER_ACCOUNT_MAP, obs2x_id, specific_ignore_list=["user_id", "account_type"])
    # prefer account_login, but accept user_id
    if not ua1x.username:
        if "user_id" in ua2x:
            ua1x.username = ua2x["user_id"]
    convert_unix_account_extensions(ua2x, ua1x, obs2x_id)
    if not isinstance(ua1x, WinUser) and not isinstance(ua1x, UnixUserAccount) and "account_type" in ua2x:
        if not ua2x["account_type"] == "unix":
            warn("The user account type %s can not be explicitly represented in a STIX 1.x Account. See %s",
                 535,
                 ua2x["account_type"], obs2x_id)


def convert_window_registry_value(v2x, obs2x_id):
    v1x = RegistryValue()
    convert_obj(v2x, v1x, REGISTRY_VALUE_MAP, obs2x_id)
    return v1x


def convert_windows_registry_key_c_o(wrk2x, wrk1x, obs2x_id):
    convert_obj(wrk2x, wrk1x, REGISTRY_KEY_MAP, obs2x_id, specific_ignore_list=["values", "creator_user_ref", "creator_username"])
    if "values" in wrk2x:
        values = []
        for v in wrk2x["values"]:
            values.append(convert_window_registry_value(v, obs2x_id))
        wrk1x.values = RegistryValues()
        wrk1x.values.value = values
    if get_option_value("version_of_stix2x") == "2.0":
        handle_ref(wrk2x, wrk1x, "creator_user_ref", "creator_username", "Properties", accessor=lambda x: x.username)


def convert_subfield(obj, rhs_value, property, sub_object_class, setting_function):
    sub_object = getattr(obj, property)
    if not sub_object:
        sub_object = sub_object_class()
        setattr(obj, property, sub_object)
    setting_function.__set__(sub_object, rhs_value)


def convert_x509_certificate_c_o(c_o_object, obj1x, obs2x_id):
    obj1x.certificate = X509Cert()
    convert_obj(c_o_object, obj1x.certificate, X509_CERTIFICATE_MAP, obs2x_id,
                specific_ignore_list=["validity_not_before", "validity_not_after", "subject_public_key_algorithm",
                                      "subject_public_key_modulus", "subject_public_key_exponent", "x509_v3_extensions"])
    if "validity_not_before" in c_o_object or "validity_not_after" in c_o_object:
        obj1x.certificate.validity = Validity()
        if "validity_not_before" in c_o_object:
            obj1x.certificate.validity.not_before = c_o_object["validity_not_before"]
        if "validity_not_after" in c_o_object:
            obj1x.certificate.validity.not_after = c_o_object["validity_not_after"]
    if ("subject_public_key_algorithm" in c_o_object or
            "subject_public_key_modulus" in c_o_object or
            "subject_public_key_exponent" in c_o_object):
        obj1x.certificate.subject_public_key = SubjectPublicKey()
        if "subject_public_key_algorithm" in c_o_object:
            obj1x.certificate.subject_public_key.public_key_algorithm = c_o_object["subject_public_key_algorithm"]
        if "subject_public_key_modulus" in c_o_object or "subject_public_key_exponent" in c_o_object:
            obj1x.certificate.subject_public_key.rsa_public_key = RSAPublicKey()
            if "subject_public_key_modulus" in c_o_object:
                obj1x.certificate.subject_public_key.rsa_public_key.modulus = c_o_object["subject_public_key_modulus"]
            if "subject_public_key_exponent" in c_o_object:
                obj1x.certificate.subject_public_key.rsa_public_key.exponent = c_o_object["subject_public_key_exponent"]
    if "x509_v3_extensions" in c_o_object:
        v3_ext = c_o_object["x509_v3_extensions"]
        obj1x.certificate.standard_extensions = X509V3Extensions()
        convert_obj(v3_ext, obj1x.certificate.standard_extensions, X509_V3_EXTENSIONS_TYPE_MAP, obs2x_id)


def convert_custom_c_o(c_o_object, obj1x, obs2x_id):
    # fill in id
    obj1x.custom_name = c_o_object["type"]
    custom_properties = CustomProperties()
    obj1x.custom_properties = custom_properties
    for k, v in c_o_object.items():
        if k != "extensions" and k != "type" and k != "id":
            new_prop = Property()
            new_prop.name = k
            new_prop.value = v
            custom_properties.append(new_prop)


def convert_cyber_observable(c_o_object, obs2x_id):
    type1x = determine_1x_object_type(c_o_object)
    if type1x:
        obj1x = type1x()
    else:
        error("Unable to determine STIX 1.x type for %s", 603, obs2x_id)
    type_name2x = c_o_object["type"]
    if type_name2x == "artifact":
        convert_artifact_c_o(c_o_object, obj1x, obs2x_id)
    elif type_name2x == "autonomous-system":
        convert_autonomous_system_c_o(c_o_object, obj1x, obs2x_id)
    elif type_name2x == "directory":
        convert_directory_c_o(c_o_object, obj1x, obs2x_id)
    elif type_name2x == "domain-name":
        convert_domain_name_c_o(c_o_object, obj1x, obs2x_id)
    elif type_name2x == "email-message":
        convert_email_message_c_o(c_o_object, obj1x, obs2x_id)
    elif type_name2x == "file":
        convert_file_c_o(c_o_object, obj1x, obs2x_id)
    elif type_name2x in ['ipv4-addr', 'ipv6-addr', 'mac-addr', 'email-addr']:
        # TODO: email_address have display_name property
        convert_addr_c_o(c_o_object, obj1x, obs2x_id)
    elif type_name2x == "mutex":
        obj1x.name = c_o_object["name"]
        obj1x.named = True
    elif type_name2x == "network-traffic":
        convert_network_traffic_c_o(c_o_object, obj1x, obs2x_id)
    elif type_name2x == "process":
        convert_process_c_o(c_o_object, obj1x, obs2x_id)
    elif type_name2x == 'software':
        convert_software_c_o(c_o_object, obj1x, obs2x_id)
    elif type_name2x == "url":
        obj1x.value = c_o_object["value"]
        obj1x.type_ = URI.TYPE_URL
    elif type_name2x == "user-account":
        convert_user_account_c_o(c_o_object, obj1x, obs2x_id)
    elif type_name2x == "windows-registry-key":
        convert_windows_registry_key_c_o(c_o_object, obj1x, obs2x_id)
    elif type_name2x == "x509-certificate":
        convert_x509_certificate_c_o(c_o_object, obj1x, obs2x_id)
    return obj1x


def convert_sco(c_o_object):
    o1x = Observable()
    type1x = determine_1x_object_type(c_o_object)
    type_name2x = c_o_object["type"]
    obs2x_id = c_o_object["id"]
    if type1x:
        obj1x = type1x()
    else:
        error("Unable to determine STIX 1.x type for %s", 603, obs2x_id)

    if type_name2x == "artifact":
        convert_artifact_c_o(c_o_object, obj1x, obs2x_id)
    elif type_name2x == "autonomous-system":
        convert_autonomous_system_c_o(c_o_object, obj1x, obs2x_id)
    elif type_name2x == "directory":
        convert_directory_c_o(c_o_object, obj1x, obs2x_id)
    elif type_name2x == "domain-name":
        convert_domain_name_c_o(c_o_object, obj1x, obs2x_id)
    elif type_name2x == "email-message":
        convert_email_message_c_o(c_o_object, obj1x, obs2x_id)
    elif type_name2x == "file":
        convert_file_c_o(c_o_object, obj1x, obs2x_id)
    elif type_name2x in ['ipv4-addr', 'ipv6-addr', 'mac-addr', 'email-addr']:
        # TODO: email_address have display_name property
        convert_addr_c_o(c_o_object, obj1x, obs2x_id)
    elif type_name2x == "mutex":
        obj1x.name = c_o_object["name"]
        obj1x.named = True
    elif type_name2x == "network-traffic":
        convert_network_traffic_c_o(c_o_object, obj1x, obs2x_id)
    elif type_name2x == "process":
        convert_process_c_o(c_o_object, obj1x, obs2x_id)
    elif type_name2x == 'software':
        convert_software_c_o(c_o_object, obj1x, obs2x_id)
    elif type_name2x == "url":
        obj1x.value = c_o_object["value"]
        obj1x.type_ = URI.TYPE_URL
    elif type_name2x == "user-account":
        convert_user_account_c_o(c_o_object, obj1x, obs2x_id)
    elif type_name2x == "windows-registry-key":
        convert_windows_registry_key_c_o(c_o_object, obj1x, obs2x_id)
    elif type_name2x == "x509-certificate":
        convert_x509_certificate_c_o(c_o_object, obj1x, obs2x_id)
    else:
        convert_custom_c_o(c_o_object, obj1x, obs2x_id)
    add_to_stix1x_observable_from_stix2x_id(obs2x_id, o1x)
    o1x.object_ = obj1x
    # set the id to the c_o_object's id, converted to STIX 1.x
    type1xName = type1x.__name__
    o1x.object_.id_ = convert_id2x(c_o_object["id"], type1xName)
    return o1x


# avoid circularities in the graph by choosing one relationship direction only
# not always reliable, because bi-directional relationships may not be populated
def possible_circularity(obj, k):
    if "type" in obj:
        if obj["type"] == "file" and k == "parent_directory_ref":
            return True


def get_refs(obj):
    refs = list()
    type2x = obj["type"] if "type" in obj else None
    for k, v in obj.items():
        if k.endswith("ref"):
            if not obj[k] in refs and not possible_circularity(obj, k):
                refs.append(obj[k])
        if k.endswith("refs"):
            if not possible_circularity(obj, k):
                for ref in obj[k]:
                    if ref not in refs:
                        refs.append(ref)
        if k == "extensions":
            for e_k, e_v in v.items():
                ext_refs = get_refs(e_v)
                if ext_refs:
                    for ref in ext_refs:
                        if ref not in refs:
                            refs.append(ref)
    # TODO: other similiar types?
    if type2x == "email-message":
        if "body_multipart" in obj:
            for o in obj["body_multipart"]:
                refs.extend(get_refs(o))

    return refs


def process_before(key_obj1, key_obj2):
    # if the key of obj2 is referenced by obj1, obj2 must be processed before
    # if obj1 has no references, then process first
    refs1 = get_refs(key_obj1[1])
    refs2 = get_refs(key_obj2[1])
    if refs1 and key_obj2[0] in refs1:
        return 1  # order correct
    elif refs2 and key_obj1[0] in refs2:
        return -1  # switch
    elif refs1 and not refs2:
        return 1  # order correct
    elif not refs1 and refs2:
        return -1  # switch
    else:
        return 0  # doesn't matter


def sort_objects_into_obj_processing_order(objs):
    tuple_list = [(k, v) for k, v in objs.items()]
    return sorted(tuple_list, key=cmp_to_key(process_before))


def convert_cyber_observables(c_o_objects, obs2x_id):
    global _STIX1X_OBJS
    _STIX1X_OBJS = {}
    sorted_obj = sort_objects_into_obj_processing_order(c_o_objects)
    for tup in sorted_obj:
        _STIX1X_OBJS[tup[0]] = convert_cyber_observable(tup[1], obs2x_id)
    # return the parent, so you get related objects
    return _STIX1X_OBJS[sorted_obj[-1][0]].parent


def add_refs_email_message(obj2x, obj1x):
    handle_ref(obj2x, obj1x, "from_ref", "from_", 'Properties', obj1x.header)
    handle_ref(obj2x, obj1x, "sender_ref", "sender", 'Properties', obj1x.header)
    handle_refs(obj2x, obj1x, "to_refs", "to", 'Properties', list_type=EmailRecipients, sub_obj1x=obj1x.header)
    handle_refs(obj2x, obj1x, "cc_refs", "cc", 'Properties', list_type=EmailRecipients, sub_obj1x=obj1x.header)
    handle_refs(obj2x, obj1x, "bcc_refs", "bcc", 'Properties', list_type=EmailRecipients, sub_obj1x=obj1x.header)
    handle_ref(obj2x, obj1x, "raw_email_ref", "raw_body", 'Properties', accessor=lambda x: decode_base64(x.packed_data))


def add_refs_file(obj2x, obj1x, pkg):
    # TODO: check for consistency of contains_refs and parent_directory_refs
    handle_parent_directory_ref(obj2x, obj1x, 'Properties')
    if "extensions" in obj2x:
        extensions = obj2x["extensions"]
        if "archive-ext" in extensions:
            handle_refs(extensions["archive-ext"], obj1x, "contains_refs", "archived_file", 'Properties')
            for file_ref in extensions["archive-ext"]["contains_refs"]:
                item = get_stix1x_item_from_stix2x_id(file_ref, 'Observable')
                pkg.observables.remove(item)


def add_refs_network_traffic(obj2x, obj1x, pkg):
    if "src_ref" in obj2x:
        obj1x.source_socket_address = convert_address_ref(obj2x, obj1x, "src", 'Object')
        item = get_stix1x_item_from_stix2x_id(obj2x["src_ref"], 'Observable')
        if item in pkg.observables:
            pkg.observables.remove(item)
    if "dst_ref" in obj2x:
        obj1x.destination_socket_address = convert_address_ref(obj2x, obj1x, "dst", 'Object')
        item = get_stix1x_item_from_stix2x_id(obj2x["dst_ref"], 'Observable')
        if item in pkg.observables:
            pkg.observables.remove(item)
    # TODO: payload refs, encapsulates
    if "extensions" in obj2x:
        extensions = obj2x["extensions"]
        if "http-request-ext" in extensions:
            handle_ref(extensions["http-request-ext"], obj1x, "message_body_data_ref", "archived_file",
                       'Object', obj1x.layer7_connections.http_session.http_request_response)


def add_refs_process(obj2x, obj1x):
    handle_refs(obj2x, obj1x, "opened_connection_refs", "network_connection_list", 'Properties', NetworkConnectionList)
    handle_ref(obj2x, obj1x, "creator_user_ref", "username", 'Properties', accessor=lambda x: x.username)
    handle_ref(obj2x, obj1x, "image_ref", "file_name", 'Properties', obj1x.image_info, accessor=lambda x: x.file_name)
    handle_ref(obj2x, obj1x, "parent_ref", "parent_pid", 'Properties', accessor=lambda x: x.pid)
    handle_refs(obj2x, obj1x, "child_refs", "child_pid_list", 'Properties', list_type=ChildPIDList, accessor=lambda x: x.pid)
    if "extensions" in obj2x:
        extensions = obj2x["extensions"]
        if "windows-service-ext" in extensions:
            service_ext = extensions["windows-service-ext"]
            handle_service_dll_refs(service_ext, obj1x, 'Properties', obj2x["id"])


def add_refs_registry_key(obj2x, obj1x):
    handle_ref(obj2x, obj1x, "creator_user_ref", "creator_username", 'Properties', accessor=lambda x: x.username)


def add_refs(obj2x, pkg):
    sco_type = obj2x["type"]
    obj1x = get_stix1x_item_from_stix2x_id(obj2x["id"], 'Properties')
    # TODO: ip addresses, domain_name
    if sco_type == "email-message":
        add_refs_email_message(obj2x, obj1x)
    elif sco_type == "file":
        add_refs_file(obj2x, obj1x, pkg)
    elif sco_type == "network-traffic":
        add_refs_network_traffic(obj2x, obj1x, pkg)
    elif sco_type == "process":
        add_refs_process(obj2x, obj1x)
    elif sco_type == "windows-registry-key":
        add_refs_registry_key(obj2x, obj1x)


def create_object_ref_graph(object_refs, stix2x_objs):
    parent_graph = dict()
    child_graph = dict()
    for ref in object_refs:
        obj = stix2x_objs[ref]
        if ref not in parent_graph:
            parent_graph[ref] = list()
        obs_refs = get_refs(obj)
        child_graph[ref] = obs_refs
        for o_id in obs_refs:
            if o_id not in parent_graph:
                parent_graph[o_id] = list()
            parent_graph[o_id].append(ref)
    return parent_graph, child_graph


def add_related(parent_obj, child_obj, relationship_name, inline):
    # save already generated related objects - they will be lost in the RelatedObject constructor
    related_objects = child_obj.related_objects
    # parent might occur in more than one observed-data, so avoid adding it more than once.
    if not any([child_obj.id_ == x.id_ for x in parent_obj.related_objects]):
        ro = RelatedObject(child_obj.properties,
                           relationship=relationship_name,
                           inline=inline,
                           id_=child_obj.id_)
        # re-establish related_objects
        ro.related_objects = related_objects
        parent_obj.related_objects.append(ro)


def handle_ref_as_related_object(obj2x, object_root, prop2x, relationship_name, objects_inline):
    if prop2x in obj2x:
        child_obj = get_stix1x_item_from_stix2x_id(obj2x[prop2x], 'Object')
        add_related(object_root, child_obj, relationship_name, child_obj.id_ not in objects_inline)
        objects_inline[child_obj] = True


def handle_refs_as_related_object(obj2x, object_root, prop2x, relationship_name, objects_inline):
    if prop2x in obj2x:
        for id in obj2x[prop2x]:
            child_obj = get_stix1x_item_from_stix2x_id(id, "Object")
            add_related(object_root, child_obj, relationship_name, child_obj.id_ not in objects_inline)
            objects_inline[child_obj.id_] = True


def add_any_related_objects(root_id, object_root, stix2x_objs, child_graph, objects_inline, visited):
    if root_id in child_graph:
        for c in child_graph[root_id]:
            if c not in visited:
                visited[c] = True
                add_any_related_objects(c, get_stix1x_item_from_stix2x_id(c, 'Object'), stix2x_objs, child_graph, objects_inline, visited)
    stix2x_obj = stix2x_objs[root_id]
    root_type = stix2x_obj["type"]

    if root_type == "email-message":
        if "body_multipart" in stix2x_obj:
            object_root.properties.attachments = Attachments()
            for part in stix2x_obj["body_multipart"]:
                handle_ref_as_related_object(part, object_root, "body_raw_ref", "Contains", objects_inline)
                if "body_raw_ref" in part:
                    object_root.properties.attachments.append(part["body_raw_ref"])
    elif root_type == "email-addr":
        handle_ref_as_related_object(stix2x_obj, object_root, "belongs_to_ref", "Related_To", objects_inline)
        # TODO: find a way to determine when this warning should be generated
        # if "belongs_to_ref" in stix2x_obj:
        #     warn("%s is not representable in a STIX 1.x %s. Found in %s", 503, "belongs_to_ref", "email-addr", stix2x_obj["id"])
    elif root_type == "file" or root_type == "directory":
        handle_refs_as_related_object(stix2x_obj, object_root, "contains_refs", "Contains", objects_inline)
        handle_ref_as_related_object(stix2x_obj, object_root, "content_ref", "Contains", objects_inline)
    elif root_type in ["domain-name", "ipv4-addr", "ipv6-addr"]:
        handle_refs_as_related_object(stix2x_obj, object_root, "resolves_to_refs", "Resolved_To", objects_inline)
        handle_refs_as_related_object(stix2x_obj, object_root, "belongs_to_refs", "Related_To", objects_inline)
    elif root_type == "network-traffic":
        if "extensions" in stix2x_obj:
            extensions = stix2x_obj["extensions"]
            if "icmp-ext" in extensions:
                convert_network_traffic_to_network_icmp_packet(extensions["icmp-ext"], object_root, stix2x_obj["id"])
            if "socket-ext" in extensions:
                convert_network_traffic_to_network_socket(extensions["socket-ext"], object_root, stix2x_obj["id"])
        handle_ref_as_related_object(stix2x_obj, object_root, "dst_payload_ref", "Contains", objects_inline)


def does_not_have_extra_information(root_id, child_id):
    if root_id.startswith("process") or root_id.startswith("windows-registry-key"):
        if child_id.startswith("user-account") or child_id.startswith("file"):
            return False
    return True


def same_uuid(id1x, id2x):
    id1x_split = id1x.split("-")
    id2x_split = id2x.split("--")
    return "-".join(id1x_split[1:]) == id2x_split[1]


def remove_false_related(root_id, child_graph, pkg):
    for child_id in child_graph[root_id]:
        item = get_stix1x_item_from_stix2x_id(child_id, 'Observable')
        if item in pkg.observables:
            if does_not_have_extra_information(root_id, child_id):
                pkg.observables.remove(item)
        if child_id in child_graph:
            remove_false_related(child_id, child_graph, pkg)


def add_object_refs(o, stix2x_objs, stix1x_obs_list, objects_inline, pkg):
    parent_graph, child_graph = create_object_ref_graph(o["object_refs"], stix2x_objs)
    for k, v in parent_graph.items():
        # find the root - it has no parents!
        # TODO: disconnected SCO have no parents either!!!
        if v == []:
            root_id = k
            break
    # remember that the top-level object will be generated inline for the observable
    root = get_stix1x_item_from_stix2x_id(root_id, 'Object')
    # boolean value is just so we can use a dict
    objects_inline[root.id_] = True
    obs = stix1x_obs_list[o["id"]]
    visited = dict()
    add_any_related_objects(root_id,
                            root,
                            stix2x_objs,
                            child_graph,
                            objects_inline,
                            visited)
    obs.object_ = root
    # remove any observables not created for orphaned SCOs
    remove_false_roots = []
    for pkg_o in pkg.observables:
        if pkg_o.object_ and same_uuid(pkg_o.object_.id_, root_id) and pkg_o.id_ != obs.id_:
            remove_false_roots.append(pkg_o)
    for false_o in remove_false_roots:
        pkg.observables.remove(false_o)
    if root_id in child_graph:
        remove_false_related(root_id, child_graph, pkg)
