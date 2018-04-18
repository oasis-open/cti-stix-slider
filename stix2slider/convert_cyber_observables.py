from functools import cmp_to_key

from cybox.common.environment_variable import (EnvironmentVariable,
                                               EnvironmentVariableList)
from cybox.common.hashes import HashList
from cybox.common.structured_text import StructuredText
from cybox.common.vocabs import VocabString
from cybox.objects.address_object import Address, EmailAddress
from cybox.objects.archive_file_object import ArchiveFile
from cybox.objects.artifact_object import Artifact
from cybox.objects.as_object import AutonomousSystem
from cybox.objects.domain_name_object import DomainName
from cybox.objects.email_message_object import (Attachments, EmailHeader,
                                                EmailMessage, ReceivedLine,
                                                ReceivedLineList)
from cybox.objects.file_object import File
from cybox.objects.hostname_object import Hostname
from cybox.objects.http_session_object import (HTTPClientRequest, HTTPMessage,
                                               HTTPRequestHeader,
                                               HTTPRequestHeaderFields,
                                               HTTPRequestLine,
                                               HTTPRequestResponse,
                                               HTTPSession)
from cybox.objects.image_file_object import ImageFile
from cybox.objects.mutex_object import Mutex
from cybox.objects.network_connection_object import (Layer7Connections,
                                                     NetworkConnection,
                                                     SocketAddress)
from cybox.objects.network_packet_object import (ICMPv4Header, ICMPv4Packet,
                                                 InternetLayer, NetworkPacket)
from cybox.objects.network_socket_object import NetworkSocket, SocketOptions
from cybox.objects.pdf_file_object import (PDFDocumentInformationDictionary,
                                           PDFFile, PDFFileID, PDFFileMetadata,
                                           PDFTrailer, PDFTrailerList)
from cybox.objects.port_object import Port
from cybox.objects.process_object import (ArgumentList, ChildPIDList,
                                          ImageInfo, NetworkConnectionList,
                                          Process)
from cybox.objects.product_object import Product
from cybox.objects.unix_user_account_object import UnixUserAccount
from cybox.objects.uri_object import URI
from cybox.objects.win_executable_file_object import (Entropy, PEFileHeader,
                                                      PEHeaders,
                                                      PEOptionalHeader,
                                                      PESection,
                                                      PESectionHeaderStruct,
                                                      PESectionList,
                                                      WinExecutableFile)
from cybox.objects.win_file_object import Stream, StreamList, WinFile
from cybox.objects.win_process_object import StartupInfo, WinProcess
from cybox.objects.win_registry_key_object import (RegistryValue,
                                                   RegistryValues,
                                                   WinRegistryKey)
from cybox.objects.win_service_object import ServiceDescriptionList, WinService
from cybox.objects.win_user_object import UserAccount, WinUser
from cybox.objects.x509_certificate_object import (RSAPublicKey,
                                                   SubjectPublicKey, Validity,
                                                   X509Cert, X509Certificate,
                                                   X509V3Extensions)
from six import text_type
from stix2slider.common import (AUTONOMOUS_SYSTEM_MAP, DIRECTORY_MAP,
                                EMAIL_MESSAGE_MAP, FILE_MAP,
                                HTTP_REQUEST_HEADERS_MAP,
                                IMAGE_FILE_EXTENSION_MAP,
                                OTHER_EMAIL_HEADERS_MAP,
                                PDF_DOCUMENT_INFORMATION_DICT_MAP,
                                PE_BINARY_FILE_HEADER_MAP,
                                PE_BINARY_OPTIONAL_HEADER_MAP, PROCESS_MAP,
                                REGISTRY_KEY_MAP, REGISTRY_VALUE_MAP,
                                SOCKET_MAP, SOCKET_OPTIONS_MAP,
                                STARTUP_INFO_MAP, USER_ACCOUNT_MAP,
                                WINDOWS_PROCESS_EXTENSION_MAP,
                                WINDOWS_SERVICE_EXTENSION_MAP,
                                X509_CERTIFICATE_MAP,
                                X509_V3_EXTENSIONS_TYPE_MAP, add_host,
                                convert_pe_type, is_windows_directory)
from stix2slider.options import error, get_option_value, info, warn

_EXTENSIONS_MAP = {
    "archive-ext": ArchiveFile,
    "ntfs-ext": WinFile,
    "pdf-ext": PDFFile,
    "raster-image-ext": ImageFile,
    "windows-pebinary-ext": WinExecutableFile,
    "windows-process-ext": WinProcess,
    "windows-service-ext": WinService,
    # "http-request-ext": NetworkConnection
    # "icmp-ext": NetworkConnection
    # "socket-ext": NetworkConnection
    # "tcp-ext": NetworkConnection
    # "unix-account_ext": UserAccount
}

_STIX1X_OBJS = {}


def sort_objects_into_processing_order(objs):
    tuple_list = [(k, v) for k, v in objs.items()]
    return sorted(tuple_list, key=lambda x: x[0])


def determine_1x_object_type(c_o_object):
    basic_type = c_o_object["type"]
    if basic_type in ["file"]:
        if "extensions" in c_o_object:
            extensions = list(c_o_object["extensions"].keys())
            if len(extensions) == 1:
                return _EXTENSIONS_MAP[extensions[0]]
            else:
                pass
                warn("Multiple File extensions in %s not supported yet", 502, c_o_object["id"])
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
            # extensions = list(c_o_object["extensions"].keys())
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


def convert_obj(obj20, obj1x, mapping_table, obs20_id):
    for key, value in obj20.items():
        if key in mapping_table:
            mapping_table[key].__set__(obj1x, value)
        # else:
        #    warn("%s property in %s is not not representable in STIX 1.x", 0, key, obs20_id)


def add_missing_property_to_description(obj1x, property_name, property_value):
    if not get_option_value("no_squirrel_gaps"):
        if not obj1x.parent.description:
            obj1x.parent.description = StructuredText("")
        new_text = property_name + ": " + text_type(property_value)
        obj1x.parent.description.value = obj1x.parent.description.value + "\n" if obj1x.parent.description.value else "" + new_text


def add_missing_list_property_to_description(obj1x, property_name, property_values):
    if not get_option_value("no_squirrel_gaps"):
        if not obj1x.parent.description:
            obj1x.parent.description = StructuredText("")
        new_text = property_name + ": " + ", ".join(text_type(x) for x in property_values)
        obj1x.parent.description.value = obj1x.parent.description.value + "\n" + new_text


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


def convert_artifact_c_o(art20, art1x, obs20_id):
    if "mime_type" in art20:
        art1x.content_type = art20["mime_type"]
    # it is illegal in STIX 2.0 to have both a payload_bin and url property - be we don't warn about it here
    if "payload_bin" in art20:
        art1x.packed_data = art20["payload_bin"]
    if "url" in art20:
        art1x.raw_artifact_reference = art20["url"]
    if "hashes" in art20:
        art1x.hashes = HashList()
        for k, v in art20["hashes"].items():
            add_hashes_property(art1x.hashes, k, v)
    # art1x.packaging.encoding.algorithm = "Base64"


def convert_autonomous_system_c_o(as20, as1x, obs20_id):
    convert_obj(as20, as1x, AUTONOMOUS_SYSTEM_MAP, obs20_id)


def convert_domain_name_c_o(dn20, dn1x, obs20_id):
    dn1x.value = dn20["value"]
    dn1x.type_ = "FQDN"
    if "resolves_to_refs" in dn20:
        for ref in dn20["resolves_to_refs"]:
            if ref in _STIX1X_OBJS:
                obj = _STIX1X_OBJS[ref]
                dn1x.add_related(obj, "Resolved_To", inline=True)
            else:
                warn("%s is not an index found in %s", 306, ref, obs20_id)


def convert_archive_file_extension(archive_ext, file1x, obs20_id):
    if "version" in archive_ext:
        file1x.version = archive_ext["version"]
    if "comment" in archive_ext:
        file1x.comment = archive_ext["comment"]
    for ref in archive_ext["contains_refs"]:
        if ref in _STIX1X_OBJS:
            file1x.archived_file.append(_STIX1X_OBJS[ref])
        else:
            warn("%s is not an index found in %s", 306, ref, obs20_id)


def convert_pdf_file_extension(pdf_ext, file1x, obs20_id):
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
                        obs20_id)
    if "pdfid0" in pdf_ext or "pdfid1" in pdf_ext:
        warn("Order may not be maintained for pdfids in %s", 514, obs20_id)
        file1x.trailers = PDFTrailerList()
        trailer = PDFTrailer()
        file1x.trailers.trailer.append(trailer)
        trailer.id_ = PDFFileID()
        if "pdfid0" in pdf_ext:
            trailer.id_.id_string.append(pdf_ext["pdfid0"])
        if "pdfid1" in pdf_ext:
            trailer.id_.id_string.append(pdf_ext["pdfid1"])


def convert_image_file_extension(image_ext, file1x, obs20_id):
    convert_obj(image_ext, file1x, IMAGE_FILE_EXTENSION_MAP, obs20_id)
    if "exif_tags" in image_ext:
        exif_tags = image_ext["exif_tags"]
        if "Compression" in exif_tags:
            file1x.image_is_compressed = (exif_tags["Compression"] != 1)
        else:
            warn("%s not representable in a STIX 1.x %s.  Found in %s", 503,
                 "exif_tags",
                 "ImageFile",
                 obs20_id)


def convert_windows_pe_binary_file_extension(pe_bin_ext, file1x, obs20_id):
    if "imphash" in pe_bin_ext:
        if not file1x.headers.hashes:
            file1x.headers.hashes = HashList()
        # imphash appears to be an MD5 hash
        add_hashes_property(file1x.headers.file_header.hashes, "MD5", pe_bin_ext["imphash"])
    if "number_of_sections" in pe_bin_ext:
        add_missing_property_to_description(file1x, "number_of_sections", pe_bin_ext["number_of_sections"])
    if "pe_type" in pe_bin_ext:
        file1x.type_ = convert_pe_type(pe_bin_ext["pe_type"], obs20_id)
    if not file1x.headers:
        file1x.headers = PEHeaders()
    if any(x in pe_bin_ext for x in ("machine_hex", "time_date_stamp",
                                     "pointer_to_symbol_table_hex",
                                     "number_of_symbols",
                                     "size_of_optional_header",
                                     "characteristics_hex",
                                     "file_header_hashes")
           ):
        file1x.headers.file_header = PEFileHeader()
        convert_obj(pe_bin_ext, file1x.headers.file_header, PE_BINARY_FILE_HEADER_MAP, obs20_id)
    if "file_header_hashes" in pe_bin_ext:
        file1x.headers.file_header.hashes = HashList()
        for k, v in sort_objects_into_processing_order(pe_bin_ext["file_header_hashes"]):
            add_hashes_property(file1x.headers.file_header.hashes, k, v)
    if "optional_header" in pe_bin_ext:
        op_header20 = pe_bin_ext["optional_header"]
        file1x.headers.optional_header = PEOptionalHeader()
        convert_obj(op_header20, file1x.headers.optional_header, PE_BINARY_OPTIONAL_HEADER_MAP, obs20_id)
        if "hashes" in op_header20:
            file1x.headers.optional_header.hashes = HashList()
            for k, v in sort_objects_into_processing_order(op_header20["hashes"]):
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
                for k, v in sort_objects_into_processing_order(s["hashes"]):
                    add_hashes_property(section.data_hashes, k, v)


def convert_ntfs_file_extension(ntfs_ext, file1x, obs20_id):
    if "sid" in ntfs_ext:
        file1x.security_id = ntfs_ext["sid"]
    if "alternate_data_streams" in ntfs_ext:
        file1x.stream_list = StreamList()
        ads_list = ntfs_ext["alternate_data_streams"]
        for ads20 in ads_list:
            ads1x = Stream()
            if "name" in ads20:
                ads1x.name = ads20["name"]
            if "size" in ads20:
                ads1x.size_in_bytes = ads20["size"]
            if "hashes" in ads20:
                for k, v in sort_objects_into_processing_order(ads20["hashes"]):
                    add_hashes_property(ads1x, k, v)
            file1x.stream_list.append(ads1x)


def convert_file_extensions(file20, file1x, obs20_id):
    extensions = file20["extensions"]
    if "archive-ext" in extensions:
        convert_archive_file_extension(extensions["archive-ext"], file1x, obs20_id)
    if "pdf-ext" in extensions:
        convert_pdf_file_extension(extensions["pdf-ext"], file1x, obs20_id)
    if "ntfs-ext" in extensions:
        convert_ntfs_file_extension(extensions["ntfs-ext"], file1x, obs20_id)
    if "raster-image-ext" in extensions:
        convert_image_file_extension(extensions["raster-image-ext"], file1x, obs20_id)
    if "windows-pebinary-ext" in extensions:
        convert_windows_pe_binary_file_extension(extensions["windows-pebinary-ext"], file1x, obs20_id)


def convert_file_c_o(file20, file1x, obs20_id):
    if "hashes" in file20:
        for k, v in sort_objects_into_processing_order(file20["hashes"]):
            add_hashes_property(file1x, k, v)
    convert_obj(file20, file1x, FILE_MAP, obs20_id)
    if "parent_directory_ref" in file20:
        if file20["parent_directory_ref"] in _STIX1X_OBJS:
            directory_object = _STIX1X_OBJS[file20["parent_directory_ref"]]
            directory_string = str(directory_object.full_path)
            file1x.full_path = directory_string + ("\\" if is_windows_directory(directory_string) else "/") + file20["name"]
        else:
            warn("%s is not an index found in %s", 306, file20["parent_directory_ref"], obs20_id)
    if "is_encrypted" in file20:
        if file20["is_encrypted"]:
            if "encryption_algorithm" in file20:
                file1x.encryption_algorithm = file20["encryption_algorithm"]
            else:
                info("is_encrypted in %s is true, but no encryption_algorithm is given", 309, obs20_id)
            if "decryption_key" in file20:
                file1x.decryption_key = file20["decryption_key"]
            else:
                info("is_encrypted in %s is true, but no decryption_key is given", 311, obs20_id)
        else:
            if "encryption_algorithm" in file20:
                info("is_encrypted in %s is false, but encryption_algorithm is given", 310, obs20_id)
            if "decryption_key" in file20:
                info("is_encrypted in %s is false, but decryption_key is given", 312, obs20_id)
    if "extensions" in file20:
        convert_file_extensions(file20, file1x, obs20_id)
    # in STIX 2.0, there are two contains_ref properties, one in the basic File object, and one on the Archive File extension
    # the slider does not handle the one in the basic File object
    if "contains_refs" in file20:
        warn("contains_refs in %s not handled", 607, obs20_id)


def convert_directory_c_o(directory20, file1x, obs20_id):
    convert_obj(directory20, file1x, DIRECTORY_MAP, obs20_id)


def populate_received_line(rl20, rl1x, obs20_id):
    # do we need to consider case?
    # can't there be multiple lines with the same prefix??
    if rl20.startswith("from"):
        rl1x.from_ = rl20
    elif rl20.startswith("by"):
        rl1x.by = rl20
    elif rl20.startswith("via"):
        rl1x.via = rl20
    elif rl20.startswith("with"):
        rl1x.with_ = rl20
    elif rl20.startswith("for"):
        rl1x.for_ = rl20
    elif rl20.startswith("id"):
        rl1x.id_ = rl20
    elif rl20.startswith("timestamp"):
        rl1x.timestamp = rl20
    else:
        warn("Received Line %s in %s has a prefix that is not representable in STIX 1.x", 507, rl20), obs20_id


def populate_other_header_fields(headers20, header1x, obs20_id):
    # keys must match the ones from RFC 2822
    for k, v in headers20.items():
        # delimiter is used

        # if isinstance(v, list):
        #     v = v[0]
        #     if len(v) > 1:
        #         for h in v[1:]:
        #             warn("%s in STIX 2.0 has multiple %s, only one is allowed in STIX 1.x. Using first in list - %s omitted",
        #                  401,
        #                  obs20_id, k, h)
        convert_obj(headers20, header1x, OTHER_EMAIL_HEADERS_MAP, obs20_id)


def convert_email_message_c_o(em20, em1x, obs20_id):
    em1x.header = EmailHeader()
    convert_obj(em20, em1x, EMAIL_MESSAGE_MAP, obs20_id)

    if "from_ref" in em20:
        if em20["from_ref"] in _STIX1X_OBJS:
            em1x.header.from_ = _STIX1X_OBJS[em20["from_ref"]]
        else:
            warn("%s is not an index found in %s, property 'from_ref'", 306, em20["from_ref"], obs20_id)
    if "sender_ref" in em20:
        if em20["sender_ref"] in _STIX1X_OBJS:
            em1x.header.sender = _STIX1X_OBJS[em20["sender_ref"]]
        else:
            warn("%s is not an index found in %s, property 'sender_refs'", 306, em20["sender_ref"], obs20_id)
    if "to_refs" in em20:
        to_address_objects = []
        for to_ref in em20["to_refs"]:
            if to_ref in _STIX1X_OBJS:
                to_address_objects.append(_STIX1X_OBJS[to_ref])
                em1x.header.to = to_address_objects
            else:
                warn("%s is not an index found in %s, property 'to_refs'", 306, to_ref, obs20_id)
    if "cc_refs" in em20:
        cc_address_objects = []
        for cc_ref in em20["cc_refs"]:
            if cc_ref in _STIX1X_OBJS:
                cc_address_objects.append(_STIX1X_OBJS[cc_ref])
                em1x.header.cc = cc_address_objects
            else:
                warn("%s is not an index found in %s, property 'cc_refs'", 306, cc_ref, obs20_id)
    if "bcc_refs" in em20:
        bcc_address_objects = []
        for bcc_ref in em20["bcc_refs"]:
            if bcc_ref in _STIX1X_OBJS:
                bcc_address_objects.append(_STIX1X_OBJS[bcc_ref])
                em1x.header.bcc = bcc_address_objects
            else:
                warn("%s is not an index found in %s, property 'bcc_refs'", 306, bcc_ref, obs20_id)
    if "content_type" in em20:
        em1x.header.content_type = em20["content_type"]
    if "received_lines" in em20:
        em1x.header.received_lines = ReceivedLineList()
        for rl20 in em20["received_lines"]:
            rl1x = ReceivedLine()
            em1x.header.received_lines.append(rl1x)
            populate_received_line(rl20, rl1x, obs20_id)
    if "additional_header_fields" in em20:
        populate_other_header_fields(em20["additional_header_fields"], em1x.header, obs20_id)
    if "raw_email_refs" in em20:
        warn("STIX 1.x can only store the body and headers of an email message in %s independently", 523, obs20_id)
    if "body" in em20:
        if em20["is_multipart"]:
            warn("The is_multipart property in %s should be 'false' if the body property is present",
                 313,
                 obs20_id)
        em1x.raw_body = em20["body"]
    else:
        if em20["is_multipart"]:
            warn("The is_multipart property in %s should be 'true' if the body property is not present",
                 313,
                 obs20_id)
    if "body_multipart" in em20:
        if not em20["is_multipart"]:
            warn("The is_multipart property in %s should be 'true' if the body_multipart property is present",
                 313,
                 obs20_id)
        attachments = []
        for part in em20["body_multipart"]:
            # content_disposition is optional, so we can't depend upon it
            # if "content_disposition" in part and part["content_disposition"].find("attachment"):
            if "body_raw_ref" in part:
                if part["body_raw_ref"] in _STIX1X_OBJS:
                    obj = _STIX1X_OBJS[part["body_raw_ref"]]
                    # TODO: can we handle other object/content types?
                    if isinstance(obj, File) or isinstance(obj, Artifact):
                        attachments.append(obj)
                else:
                    warn("%s is not an index found in %s", 306, part["body_raw_ref"], obs20_id)
            if "body" in part:
                em1x.raw_body = part["body"]
        if attachments:
            em1x.attachments = Attachments()
            for a in attachments:
                em1x.add_related(a, "Contains", inline=True)
                em1x.attachments.append(a.parent.id_)
    else:
        if em20["is_multipart"]:
            warn("The is_multipart property in %s should be 'false' if the body_multipart property is not present",
                 313,
                 obs20_id)


def convert_addr_c_o(addr20, addr1x, obs20_id):
    # CIDR values are not treated in any different way
    addr1x.address_value = addr20["value"]
    if addr20["type"] == 'ipv4-addr':
        addr1x.category = Address.CAT_IPV4
    elif addr20["type"] == 'ipv6-addr':
        addr1x.category = Address.CAT_IPV6
    elif addr20["type"] == 'mac-addr':
        addr1x.category = Address.CAT_MAC
    if "resolves_to_refs" in addr20:
        for ref in addr20["resolves_to_refs"]:
            if ref in _STIX1X_OBJS:
                obj = _STIX1X_OBJS[ref]
                addr1x.add_related(obj, "Resolved_To", inline=True)
            else:
                warn("%s is not an index found in %s", 306, ref, obs20_id)
    if "belongs_to_refs" in addr20:
        warn("%s property in %s not handled yet", 606, "belongs_to_refs", obs20_id)


def convert_process_extensions(process20, process1x, obs20_id):
    extensions = process20["extensions"]
    if "windows-process-ext" in extensions:
        windows_process = extensions["windows-process-ext"]
        convert_obj(windows_process, process1x, WINDOWS_PROCESS_EXTENSION_MAP, obs20_id)
        if "startup_info" in windows_process:
            process1x.startup_info = StartupInfo()
            convert_obj(windows_process["startup_info"], process1x.startup_info, STARTUP_INFO_MAP)
    if "windows-service-ext" in extensions:
        windows_service = extensions["windows-service-ext"]
        convert_obj(windows_service, process1x, WINDOWS_SERVICE_EXTENSION_MAP, obs20_id)
        if "service_dll_refs" in windows_service:
            if windows_service["service_dll_refs"][0] in _STIX1X_OBJS:
                file_object = _STIX1X_OBJS[windows_service["service_dll_refs"][0]]
                if "name" in file_object:
                    process1x.service_dll = file_object.file_name
            else:
                warn("%s is not an index found in %s", 306, windows_service["service_dll_refs"][0], obs20_id)
            if len(windows_service["service_dll_refs"]) > 1:
                for dll_ref in windows_service["service_dll_refs"][1:]:
                    warn("%s in STIX 2.0 has multiple %s, only one is allowed in STIX 1.x. Using first in list - %s omitted",
                         401,
                         obs20_id, "service_dll_refs", dll_ref)
        if "descriptions" in windows_service:
            process1x.description_list = ServiceDescriptionList()
            for d in windows_service["descriptions"]:
                process1x.description_list.append(d)


def convert_process_c_o(process20, process1x, obs20_id):
    convert_obj(process20, process1x, PROCESS_MAP, obs20_id)
    if "cwd" in process20:
        if not process1x.image_info:
            process1x.image_info = ImageInfo()
        process1x.image_info.current_directory = process20["cwd"]
    if "arguments" in process20:
        process1x.argument_list = ArgumentList()
        for a in process20["arguments"]:
            process1x.argument_list.append(a)
    if "command_line" in process20:
        if not process1x.image_info:
            process1x.image_info = ImageInfo()
        process1x.image_info.command_line = process20["command_line"]
    if "environment_variables" in process20:
        process1x.environment_variable_list = EnvironmentVariableList()
        for k, v in process20["environment_variables"].items():
            ev = EnvironmentVariable()
            process1x.environment_variable_list.append(ev)
            ev.name = k
            ev.value = v
    if "opened_connection_refs" in process20:
        process1x.network_connection_list = NetworkConnectionList()
        for conn_ref in process20["opened_connection_refs"]:
            if conn_ref in _STIX1X_OBJS:
                process1x.network_connection_list.append(_STIX1X_OBJS[conn_ref])
            else:
                warn("%s is not an index found in %s", 306, conn_ref, obs20_id)
    if "creator_user_ref" in process20:
        if process20["creator_user_ref"] in _STIX1X_OBJS:
            account_object = _STIX1X_OBJS[process20["creator_user_ref"]]
            if "account_login" in account_object:
                process1x.username = account_object.username
        else:
            warn("%s is not an index found in %s", 306, process20["creator_user_ref"], obs20_id)
    if "binary_ref" in process20:
        if process20["binary_ref"] in _STIX1X_OBJS:
            file_obj = _STIX1X_OBJS[process20["binary_ref"]]
            if file_obj.file_name:
                if not process1x.image_info:
                    process1x.image_info = ImageInfo()
                process1x.image_info.file_name = file_obj.file_name
                # TODO: file_obj.full_path
                if file_obj.hashes:
                    warn("Hashes of the binary_ref of %s process cannot be represented in the STIX 1.x Process object", 517, obs20_id)
            else:
                warn("No file name provided for binary_ref of %s, therefore it cannot be represented in the STIX 1.x Process object", 516, obs20_id)
        else:
            warn("%s is not an index found in %s", 306, process20["binary_ref"], obs20_id)
    if "parent_ref" in process20:
        if process20["parent_ref"] in _STIX1X_OBJS:
            process_object = _STIX1X_OBJS[process20["parent_ref"]]
            if "pid" in process_object:
                process1x.parent_pid = process_object.pid
        else:
            warn("%s is not an index found in %s", 306, process20["parent_ref"], obs20_id)
    if "child_refs" in process20:
        process1x.child_pid_list = ChildPIDList()
        for cr in process20["child_refs"]:
            process_object = _STIX1X_OBJS[cr]
            if "pid" in process_object:
                process1x.child_pid_list.append(process_object.pid)
    if "extensions" in process20:
        convert_process_extensions(process20, process1x, obs20_id)


def convert_address_ref(obj20, direction, obs20_id):
    sa = None
    add_property = direction + "_ref"
    port_property = direction + "_port"
    if add_property in obj20:
        if obj20[add_property] in _STIX1X_OBJS:
            sa = SocketAddress()
            obj = _STIX1X_OBJS[obj20[add_property]]
            if isinstance(obj, Address):
                sa.ip_address = obj
            elif isinstance(obj, DomainName):
                sa.hostname = Hostname()
                sa.hostname.hostname_value = obj.value
        else:
            warn("%s is not an index found in %s", 306, obj20[add_property], obs20_id)
    if port_property in obj20:
        if not sa:
            sa = SocketAddress()
        sa.port = Port()
        sa.port.port_value = obj20[port_property]
    return sa


def convert_network_traffic_to_http_session(http_request_ext, nc, obs20_id):
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
                    obs20_id)
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
            if http_request_ext["message_body_length"] in _STIX1X_OBJS:
                artifact_obj = _STIX1X_OBJS[http_request_ext["message_body_length"]]
                body.message_body = artifact_obj.packed_data
            else:
                warn("%s is not an index found in %s", 306, http_request_ext["message_body_length"], obs20_id)
        rr.http_client_request.http_message_body = body


def convert_network_traffic_to_network_icmp_packet(icmp_ext, nc, obs20_id):
    obj1x = NetworkPacket()
    obj1x.internet_layer = InternetLayer()
    info("Assuming imcp packet in %s is v4", 701, obs20_id)
    icmpv4 = ICMPv4Packet()
    icmpv4.icmpv4_header = ICMPv4Header()
    icmpv4.icmpv4_header.type_ = icmp_ext["icmp_type_hex"]
    icmpv4.icmpv4_header.code = icmp_ext["icmp_code_hex"]
    obj1x.internet_layer.icmpv4 = icmpv4
    nc.add_related(obj1x, VocabString("ICMP_Packet"), inline=True)


def convert_network_traffic_to_network_socket(socket_ext, nc, obs20_id):
    obj1x = NetworkSocket()
    convert_obj(socket_ext, obj1x, SOCKET_MAP, obs20_id)
    if "options" in socket_ext:
        obj1x.options = SocketOptions()
        convert_obj(socket_ext["options"],
                    obj1x.options,
                    SOCKET_OPTIONS_MAP,
                    obs20_id)
    if "socket_handle" in socket_ext:
        warn("%s not representable in a STIX 1.x %s.  Found in %s", 503, "socket_handle", "NetworkSocket", obs20_id)
    nc.add_related(obj1x, VocabString("Related_Socket"), inline=True)
    # obj1x.local_address = convert_address_ref(obj20, "src")
    # obj1x.remote_address = convert_address_ref(obj20, "dst")


def convert_network_traffic_c_o(obj20, obj1x, obs20_id):
    obj1x.source_socket_address = convert_address_ref(obj20, "src", obs20_id)
    obj1x.destination_socket_address = convert_address_ref(obj20, "dst", obs20_id)
    if "extensions" in obj20:
        extensions = obj20["extensions"]
        if "socket-ext" in extensions:
            convert_network_traffic_to_network_socket(extensions["socket-ext"], obj1x, obs20_id)
        elif "icmp-ext" in extensions:
            convert_network_traffic_to_network_icmp_packet(extensions["icmp-ext"], obj1x, obs20_id)
        elif "http-request-ext" in extensions:
            convert_network_traffic_to_http_session(extensions["http-request-ext"], obj1x, obs20_id)
        elif "tcp-ext" in extensions:
            warn("tcp-ext in %s not handled, yet", 609, obs20_id)
    if "protocols" in obj20:
        warn("%s property in %s not handled, yet", 608, "protocols", obs20_id)
    # how is is_active related to tcp_state?
    for name in ("start", "end", "src_byte_count", "dst_byte_count", "src_packets", "dst_packets", "ipfix",
                 "src_payload_ref", "dst_payload_ref", "encapsulates_refs", "encapsulated_by_ref"):
        if name in obj20:
            warn("%s not representable in a STIX 1.x %s.  Found in %s",
                 503,
                 name, "NetworkConnection", obs20_id)


def convert_software_c_o(soft20, prod1x, obs20_id):
    prod1x.product = soft20["name"]
    if "cpe" in soft20:
        warn("cpe not representable in a STIX 1.x Product.  Found in %s", 503, obs20_id)
    if "languages" in soft20:
        prod1x.language = soft20["languages"][0]
        if len(soft20["languages"]) > 1:
            for l in soft20["languages"][1:]:
                warn("%s in STIX 2.0 has multiple %s, only one is allowed in STIX 1.x. Using first in list - %s omitted",
                     401, obs20_id, "languages", l)

    if "vendor" in soft20:
        prod1x.vendor = soft20["vendor"]
    if "version" in soft20:
        prod1x.version = soft20["version"]


def convert_unix_account_extensions(ua20, ua1x, obs20_id):
    if "extensions" in ua20:
        # must be unix-account-ext
        if "user_id" in ua20:
            ua1x.user_id = int(ua20["user_id"])
        unix_account_ext = ua20["extensions"]["unix-account-ext"]
        if "gid" in unix_account_ext:
            ua1x.group_id = unix_account_ext["gid"]
        if "groups" in unix_account_ext:
            for g in unix_account_ext["groups"]:
                warn("The 'groups' property of unix-account-ext contains strings, but the STIX 1.x property expects integers in %s",
                     515,
                     obs20_id)
        if "home_dir" in unix_account_ext:
            ua1x.home_directory = unix_account_ext["home_dir"]
        if "shell" in unix_account_ext:
            ua1x.login_shell = unix_account_ext["shell"]


def convert_user_account_c_o(ua20, ua1x, obs20_id):
    convert_obj(ua20, ua1x, USER_ACCOUNT_MAP, obs20_id)
    convert_unix_account_extensions(ua20, ua1x, obs20_id)


def convert_window_registry_value(v20, obs20_id):
    v1x = RegistryValue()
    convert_obj(v20, v1x, REGISTRY_VALUE_MAP, obs20_id)
    return v1x


def convert_windows_registry_key_c_o(wrk20, wrk1x, obs20_id):
    convert_obj(wrk20, wrk1x, REGISTRY_KEY_MAP, obs20_id)
    if "values" in wrk20:
        values = []
        for v in wrk20["values"]:
            values.append(convert_window_registry_value(v, obs20_id))
        wrk1x.values = RegistryValues()
        wrk1x.values.value = values
    if "creator_user_ref" in wrk20:
        if wrk20["creator_user_ref"] in _STIX1X_OBJS:
            account_object = _STIX1X_OBJS[wrk20["creator_user_ref"]]
            wrk1x.creator_username = account_object.username
        else:
            warn("%s is not an index found in %s", 306, wrk20["creator_user_ref"], obs20_id)


def convert_subfield(obj, rhs_value, property, sub_object_class, setting_function):
    sub_object = getattr(obj, property)
    if not sub_object:
        sub_object = sub_object_class()
        setattr(obj, property, sub_object)
    setting_function.__set__(sub_object, rhs_value)


def convert_x509_certificate_c_o(c_o_object, obj1x, obs20_id):
    obj1x.certificate = X509Cert()
    convert_obj(c_o_object, obj1x.certificate, X509_CERTIFICATE_MAP, obs20_id)
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
        convert_obj(v3_ext, obj1x.certificate.standard_extensions, X509_V3_EXTENSIONS_TYPE_MAP, obs20_id)


def convert_cyber_observable(c_o_object, obs20_id):
    type1x = determine_1x_object_type(c_o_object)
    if type1x:
        obj1x = type1x()
    else:
        error("Unable to determine STIX 1.x type for %s", 603, obs20_id)
    type_name20 = c_o_object["type"]
    if type_name20 == "artifact":
        convert_artifact_c_o(c_o_object, obj1x, obs20_id)
    elif type_name20 == "autonomous-system":
        convert_autonomous_system_c_o(c_o_object, obj1x, obs20_id)
    elif type_name20 == "directory":
        convert_directory_c_o(c_o_object, obj1x, obs20_id)
    elif type_name20 == "domain-name":
        convert_domain_name_c_o(c_o_object, obj1x, obs20_id)
    elif type_name20 == "email-message":
        convert_email_message_c_o(c_o_object, obj1x, obs20_id)
    elif type_name20 == "file":
        convert_file_c_o(c_o_object, obj1x, obs20_id)
    elif type_name20 in ['ipv4-addr', 'ipv6-addr', 'mac-addr', 'email-addr']:
        # TODO: email_address have display_name property
        convert_addr_c_o(c_o_object, obj1x, obs20_id)
    elif type_name20 == "mutex":
        obj1x.name = c_o_object["name"]
        obj1x.named = True
    elif type_name20 == "network-traffic":
        convert_network_traffic_c_o(c_o_object, obj1x, obs20_id)
    elif type_name20 == "process":
        convert_process_c_o(c_o_object, obj1x, obs20_id)
    elif type_name20 == 'software':
        convert_software_c_o(c_o_object, obj1x, obs20_id)
    elif type_name20 == "url":
        obj1x.value = c_o_object["value"]
        obj1x.type_ = URI.TYPE_URL
    elif type_name20 == "user-account":
        convert_user_account_c_o(c_o_object, obj1x, obs20_id)
    elif type_name20 == "windows-registry-key":
        convert_windows_registry_key_c_o(c_o_object, obj1x, obs20_id)
    elif type_name20 == "x509-certificate":
        convert_x509_certificate_c_o(c_o_object, obj1x, obs20_id)
    return obj1x


def get_refs(obj):
    refs = list()
    for k, v in obj.items():
        if k.endswith("ref"):
            refs.append(obj[k])
        if k.endswith("refs"):
            refs.extend(obj[k])
        if k == "extensions":
            for e_k, e_v in v.items():
                ext_refs = get_refs(e_v)
                if ext_refs:
                    refs.extend(ext_refs)
    return refs


def process_before(key_obj1, key_obj2):
    # if the key of obj2 is referenced by obj1, obj2 must be processed before
    # if obj1 has no references, then process first
    refs = get_refs(key_obj1[1])
    if refs and key_obj2[0] in refs:
        return 1  # order correct
    elif refs:
        return 0  # same
    else:
        return -1  # switch


def sort_objects_into_obj_processing_order(objs):
    tuple_list = [(k, v) for k, v in objs.items()]
    return sorted(tuple_list, key=cmp_to_key(process_before))


def convert_cyber_observables(c_o_objects, obs20_id):
    global _STIX1X_OBJS
    _STIX1X_OBJS = {}
    sorted_obj = sort_objects_into_obj_processing_order(c_o_objects)
    for tup in sorted_obj:
        _STIX1X_OBJS[tup[0]] = convert_cyber_observable(tup[1], obs20_id)
    # return the parent, so you get related objects
    return _STIX1X_OBJS[sorted_obj[-1][0]].parent
