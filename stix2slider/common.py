# Standard Library
import uuid

# external
from cybox.objects.account_object import Account
from cybox.objects.as_object import AutonomousSystem
from cybox.objects.email_message_object import EmailHeader, EmailMessage
from cybox.objects.file_object import File
from cybox.objects.http_session_object import (
    HostField, HTTPRequestHeaderFields
)
from cybox.objects.image_file_object import ImageFile
from cybox.objects.network_socket_object import NetworkSocket, SocketOptions
from cybox.objects.pdf_file_object import PDFDocumentInformationDictionary
from cybox.objects.port_object import Port
from cybox.objects.process_object import Process
from cybox.objects.uri_object import URI
from cybox.objects.user_account_object import UserAccount
from cybox.objects.win_executable_file_object import (
    PEFileHeader, PEOptionalHeader
)
from cybox.objects.win_process_object import StartupInfo, WinProcess
from cybox.objects.win_registry_key_object import RegistryValue, WinRegistryKey
from cybox.objects.win_service_object import WinService
from cybox.objects.x509_certificate_object import X509Cert, X509V3Extensions

# internal
from stix2slider.options import warn

AUTONOMOUS_SYSTEM_MAP = {
    "number": AutonomousSystem.number,
    "name": AutonomousSystem.name,
    "rir": AutonomousSystem.regional_internet_registry
}


DIRECTORY_MAP = {
    # TODO contains_refs
    "path": File.full_path,
    # TODO: path_enc
    "created": File.created_time,
    "modified": File.modified_time,
    "accessed": File.accessed_time,
    # WD07
    "ctime": File.created_time,
    "mtime": File.modified_time,
    "atime": File.accessed_time,
}


EMAIL_MESSAGE_MAP = {
    "date": EmailMessage.date,
    "subject": EmailMessage.subject,
    "body": EmailMessage.raw_body
}


OTHER_EMAIL_HEADERS_MAP = {
    "In-Reply-To": EmailHeader.in_reply_to,
    "Message-ID": EmailHeader.message_id,
    "Reply-To": EmailHeader.reply_to,
    "Errors-To": EmailHeader.errors_to,
    "Boundary": EmailHeader.boundary,
    "Mime-Version": EmailHeader.mime_version,
    "Precedence": EmailHeader.precedence,
    "User-Agent": EmailHeader.user_agent,
    "X-Mailer": EmailHeader.x_mailer,
    "X-Originating-IP": EmailHeader.x_originating_ip,
    "X-Priority": EmailHeader.x_priority,
}


FILE_MAP = {
    "size": File.size_in_bytes,
    "name": File.file_name,
    # TODO: name_enc
    "magic_number_hex": File.magic_number,
    # TODO: mime_type
    "created": File.created_time,
    "modified": File.modified_time,
    "accessed": File.accessed_time,
    # WD07
    "ctime": File.created_time,
    "mtime": File.modified_time,
    "atime": File.accessed_time,
}


PDF_DOCUMENT_INFORMATION_DICT_MAP = {
    "Title": PDFDocumentInformationDictionary.title,
    "Author": PDFDocumentInformationDictionary.author,
    "Subject": PDFDocumentInformationDictionary.subject,
    "Keywords": PDFDocumentInformationDictionary.keywords,
    "Creator": PDFDocumentInformationDictionary.creator,
    "Producer": PDFDocumentInformationDictionary.producer,
    "CreationData": PDFDocumentInformationDictionary.creationdate,
    "ModDate": PDFDocumentInformationDictionary.moddate,
    "Trapped": PDFDocumentInformationDictionary.trapped
}


IMAGE_FILE_EXTENSION_MAP_2_0 = {
    "image_height": ImageFile.image_height,
    "image_width": ImageFile.image_width,
    "bits_per_pixel": ImageFile.bits_per_pixel,
    "image_compression_algorithm": ImageFile.compression_algorithm
}

IMAGE_FILE_EXTENSION_MAP_2_1 = {
    "image_height": ImageFile.image_height,
    "image_width": ImageFile.image_width,
    "bits_per_pixel": ImageFile.bits_per_pixel,
}


PE_BINARY_FILE_HEADER_MAP = {
    "machine_hex": PEFileHeader.machine,
    "time_date_stamp": PEFileHeader.time_date_stamp,
    "pointer_to_symbol_table_hex": PEFileHeader.pointer_to_symbol_table,
    "number_of_symbols": PEFileHeader.number_of_symbols,
    "size_of_optional_header": PEFileHeader.size_of_optional_header,
    "characteristics_hex": PEFileHeader.characteristics
}


PE_BINARY_OPTIONAL_HEADER_MAP = {
    "magic_hex": PEOptionalHeader.magic,
    "major_linker_version": PEOptionalHeader.major_linker_version,
    "minor_linker_version": PEOptionalHeader.minor_linker_version,
    "size_of_code": PEOptionalHeader.size_of_code,
    "size_of_initialized_data": PEOptionalHeader.size_of_initialized_data,
    "size_of_uninitialized_data": PEOptionalHeader.size_of_uninitialized_data,
    "address_of_entry_point": PEOptionalHeader.address_of_entry_point,
    "base_of_code": PEOptionalHeader.base_of_code,
    "base_of_data": PEOptionalHeader.base_of_data,
    "image_base": PEOptionalHeader.image_base,
    "section_alignment": PEOptionalHeader.section_alignment,
    "file_alignment": PEOptionalHeader.file_alignment,
    "major_os_version": PEOptionalHeader.major_os_version,
    "minor_os_version": PEOptionalHeader.minor_os_version,
    "major_image_version": PEOptionalHeader.major_image_version,
    "minor_image_version": PEOptionalHeader.minor_image_version,
    "major_subsystem_version": PEOptionalHeader.major_subsystem_version,
    "minor_subsystem_version": PEOptionalHeader.minor_subsystem_version,
    "win32_version_value_hex": PEOptionalHeader.win32_version_value,
    "size_of_image": PEOptionalHeader.size_of_image,
    "size_of_headers": PEOptionalHeader.size_of_headers,
    "checksum_hex": PEOptionalHeader.checksum,
    "subsystem_hex": PEOptionalHeader.subsystem,
    "dll_characteristics_hex": PEOptionalHeader.dll_characteristics,
    "size_of_stack_reserve": PEOptionalHeader.size_of_stack_reserve,
    "size_of_stack_commit": PEOptionalHeader.size_of_stack_commit,
    "size_of_heap_reserve": PEOptionalHeader.size_of_heap_reserve,
    "size_of_heap_commit": PEOptionalHeader.size_of_heap_commit,
    "loader_flags_hex": PEOptionalHeader.loader_flags,
    "number_of_rva_and_sizes": PEOptionalHeader.number_of_rva_and_sizes
}


PROCESS_MAP_2_0 = {
    "is_hidden": Process.is_hidden,
    "pid": Process.pid,
    "name": Process.name,
    "created": Process.creation_time
}

PROCESS_MAP_2_1 = {
    "is_hidden": Process.is_hidden,
    "pid": Process.pid,
    "created": Process.creation_time
}

WINDOWS_PROCESS_EXTENSION_MAP = {
    "aslr_enabled": WinProcess.aslr_enabled,
    "dep_enabled": WinProcess.dep_enabled,
    "priority": WinProcess.priority,
    "owner_sid": WinProcess.security_id,
    "window_title": WinProcess.window_title
}


WINDOWS_SERVICE_EXTENSION_MAP = {
    "service_name": WinService.service_name,
    "display_name": WinService.display_name,
    "group_name": WinService.group_name,
    "start_type": WinService.startup_type,
    "service_type": WinService.service_type,
    "service_status": WinService.service_status

}


STARTUP_INFO_MAP = {
    "lpdesktop": StartupInfo.lpdesktop,
    "lptitle": StartupInfo.lptitle,
    "dwx": StartupInfo.dwx,
    "dwy": StartupInfo.dwy,
    "dwxsize": StartupInfo.dwxsize,
    "dwysize": StartupInfo.dwysize,
    "dwxcountchars": StartupInfo.dwxcountchars,
    "dwycountchars": StartupInfo.dwycountchars,
    "dwfillattribute": StartupInfo.dwfillattribute,
    "dwflags": StartupInfo.dwflags,
    "wshowwindow": StartupInfo.wshowwindow,
    "hstdinput": StartupInfo.hstdinput,
    "hstdoutput": StartupInfo.hstdoutput,
    "hstderror": StartupInfo.hstderror
}


def add_host(host_info):
    uri_port = host_info.split(":")
    hf = HostField()
    if len(uri_port) > 1:
        port = Port()
        port.port_value = uri_port[1]
        hf.port = port
    hf.domain_name = URI(uri_port[0], URI.TYPE_DOMAIN)
    return hf


# see https://en.wikipedia.org/wiki/List_of_HTTP_header_fields

HTTP_REQUEST_HEADERS_MAP = {
    "Accept": HTTPRequestHeaderFields.accept,
    "Accept-Charset": HTTPRequestHeaderFields.accept_charset,
    "Accept-Language": HTTPRequestHeaderFields.accept_language,
    "Accept-Dateime": HTTPRequestHeaderFields.accept_datetime,
    "Accept-Encoding": HTTPRequestHeaderFields.accept_encoding,
    "Authorization": HTTPRequestHeaderFields.authorization,
    "Cache-Control": HTTPRequestHeaderFields.cache_control,
    "Connection": HTTPRequestHeaderFields.connection,
    "Cookie": HTTPRequestHeaderFields.cookie,
    "Content-Length": HTTPRequestHeaderFields.content_length,
    "Content-MD5": HTTPRequestHeaderFields.content_md5,
    "Content-Type": HTTPRequestHeaderFields.content_type,
    "Date": HTTPRequestHeaderFields.date,
    "Expect": HTTPRequestHeaderFields.expect,
    # From - handled elsewhere
    # Forwarded? - no cybox
    # Host - handled elsewhere
    "If-Match": HTTPRequestHeaderFields.if_match,
    "If-Modified-Since": HTTPRequestHeaderFields.if_modified_since,
    "If-None-Match": HTTPRequestHeaderFields.if_none_match,
    "If-Range": HTTPRequestHeaderFields.if_range,
    "If-Unmodified-Since": HTTPRequestHeaderFields.if_unmodified_since,
    "Max-Forwards": HTTPRequestHeaderFields.max_forwards,
    # Origin? - no cybox
    "Pragma": HTTPRequestHeaderFields.pragma,
    "Proxy-Authorization": HTTPRequestHeaderFields.proxy_authorization,
    # Proxy-Connection? - no cybox
    "Range": HTTPRequestHeaderFields.range_,
    # Referer - handled elsewhere
    "TE": HTTPRequestHeaderFields.te,
    # Upgrade? - no cybox
    "User-Agent": HTTPRequestHeaderFields.user_agent,
    "Via": HTTPRequestHeaderFields.via,
    "Warning": HTTPRequestHeaderFields.warning,
    "DNT": HTTPRequestHeaderFields.dnt,
    "X-Requested_With": HTTPRequestHeaderFields.x_requested_with,
    "X-Forward-For": HTTPRequestHeaderFields.x_forwarded_for,
    "X-Forward-Pronto": HTTPRequestHeaderFields.x_forwarded_proto,
    "X-ATT-DeviceId": HTTPRequestHeaderFields.x_att_deviceid
    # X-Request_ID? - no cybox
    # X_Wap_Profile - handled elsewhere
}


SOCKET_OPTIONS_MAP = {
    "IP_MULTICAST_IF": SocketOptions.ip_multicast_if,
    "IP_MULTICAST_IF2": SocketOptions.ip_multicast_if2,
    "IP_MULTICAST_LOOP": SocketOptions.ip_multicast_loop,
    "IP_TOS": SocketOptions.ip_tos,
    "SO_BROADCAST": SocketOptions.so_broadcast,
    "SO_CONDITIONAL_ACCEPT": SocketOptions.so_conditional_accept,
    "SO_KEEPALIVE": SocketOptions.so_keepalive,
    "SO_DONTROUTE": SocketOptions.so_dontroute,
    "SO_LINGER": SocketOptions.so_linger,
    "SO_DONTLINGER": SocketOptions.so_dontlinger,
    "SO_OOBINLINE": SocketOptions.so_oobinline,
    "SO_RCVBUF": SocketOptions.so_rcvbuf,
    "SO_GROUP_PRIORITY": SocketOptions.so_group_priority,
    "SO_REUSEADDR": SocketOptions.so_reuseaddr,
    "SO_DEBUG": SocketOptions.so_debug,
    "SO_RCVTIMEO": SocketOptions.so_rcvtimeo,
    "SO_SNDBUF": SocketOptions.so_sndbuf,
    "SO_SNDTIMEO": SocketOptions.so_sndtimeo,
    "SO_UPDATE_ACCEPT_CONTEXT": SocketOptions.so_update_accept_context,
    "SO_TIMEOUT": SocketOptions.so_timeout,
    "TCP_NODELAY": SocketOptions.tcp_nodelay
}


SOCKET_MAP_2_0 = {
    "address_family": NetworkSocket.address_family,
    "protocol_family": NetworkSocket.domain,
    "is_blocking": NetworkSocket.is_blocking,
    "is_listening": NetworkSocket.is_listening,
    "socket_type": NetworkSocket.type_,
    "socket_descriptor": NetworkSocket.socket_descriptor
}

SOCKET_MAP_2_1 = {
    "address_family": NetworkSocket.address_family,
    "is_blocking": NetworkSocket.is_blocking,
    "is_listening": NetworkSocket.is_listening,
    "socket_type": NetworkSocket.type_,
    "socket_descriptor": NetworkSocket.socket_descriptor
}

USER_ACCOUNT_MAP = {
    # TODO: ua20["user_id"]?
    "account_login": UserAccount.username,
    # TODO: account_type -> Account.Domain??
    # TODO: display_name
    # TODO: is_service_account
    # TODO: is_privileged -> UserAccount.Privilege_List?
    # TODO: can_escalate_privs -> UserAccount.Privilege_List?
    "is_disabled": UserAccount.disabled,
    "account_created": Account.creation_date,
    # TODO: account_expires
    # TODO: password_last_changed (2.0) / credential_last_changed (2.1)
    # TODO: account_first_login
    "account_last_login": UserAccount.last_login
}


REGISTRY_KEY_MAP = {
    "key": WinRegistryKey.key,
    "modified": WinRegistryKey.modified_time,
    "number_of_subkeys": WinRegistryKey.number_subkeys,
    # WD07
    "modified_time": WinRegistryKey.modified_time,
}


REGISTRY_VALUE_MAP = {
    "name": RegistryValue.name,
    "data": RegistryValue.data,
    "data_type": RegistryValue.datatype
}


X509_CERTIFICATE_MAP = {
    # "is_self_signed": ,
    # "hashes": ,
    "version": X509Cert.version,
    "serial_number": X509Cert.serial_number,
    "signature_algorithm": X509Cert.signature_algorithm,
    "issuer": X509Cert.issuer,
    "subject": X509Cert.subject
}


X509_V3_EXTENSIONS_TYPE_MAP = {
    "basic_constraints": X509V3Extensions.basic_constraints,
    "name_constraints": X509V3Extensions.name_constraints,
    "policy_constraints": X509V3Extensions.policy_constraints
}


def convert_pe_type(pe_type2x, obs2x_id):
    if pe_type2x == "exe":
        return "Executable"
    elif pe_type2x == "dll":
        return "Dll"
    elif pe_type2x == "sys":
        warn("pe_type SYS in %s is valid in STIX 2.x, but not in STIX 1.x", 511, obs2x_id)
        return "Invalid"
    else:
        warn("pe_type %s in %s is allowed in STIX 2.x, but not in STIX 1.x", 512, pe_type2x, obs2x_id)
        return "Invalid"


def determine_2x_address_type(address):
    if "." in address:
        return "ipv4-addr"
    elif ":" in address:
        parts = address.split(":")
        if len(parts[0]) == 2:
            return "mac-addr"
        else:
            return "ipv6-addr"


def is_windows_directory(directory_string):
    # TODO: is there a more definitive way to determine this?
    return '\\' in directory_string


def id_to_print(obj):
    return obj.parent.id_


def is_domain_name_address(s):
    if "." in s:
        parts = s.split(".")
        return not s.isdigit(parts[0])
    else:
        return False


_TYPE_MAP_FROM_2_0_TO_1_x = {"attack-pattern": "ttp",
                             "observed-data": "observable",
                             "bundle": "STIXPackage",
                             "malware": "ttp",
                             "marking-definition": "markingstructure",
                             "toolinformation": "tool",
                             "vulnerability": "et"}


_ID_NAMESPACE = "example"


def convert_id2x(id2x, sco_type_name=None):
    id_parts = id2x.split("--")
    if sco_type_name:
        type_name = sco_type_name
    elif id_parts[0] in _TYPE_MAP_FROM_2_0_TO_1_x:
        type_name = _TYPE_MAP_FROM_2_0_TO_1_x[id_parts[0]]
    else:
        type_name = id_parts[0]
    return "%s:%s-%s" % (_ID_NAMESPACE, type_name, id_parts[1])


def create_id1x(type_name_1x):
    return "%s:%s-%s" % (_ID_NAMESPACE, type_name_1x, uuid.uuid4())
