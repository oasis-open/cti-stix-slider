from cybox.common.environment_variable import (EnvironmentVariable,
                                               EnvironmentVariableList)
from cybox.common.hashes import Hash, HashList
from cybox.core import Observable
from cybox.core.observable import ObservableComposition
from cybox.objects.address_object import Address
from cybox.objects.archive_file_object import ArchiveFile
from cybox.objects.artifact_object import Artifact
from cybox.objects.as_object import AutonomousSystem
from cybox.objects.domain_name_object import DomainName
from cybox.objects.email_message_object import (EmailAddress, EmailHeader,
                                                EmailMessage, EmailRecipients)
from cybox.objects.file_object import File
from cybox.objects.image_file_object import ImageFile
from cybox.objects.mutex_object import Mutex
from cybox.objects.pdf_file_object import (PDFDocumentInformationDictionary,
                                           PDFFile, PDFFileID, PDFFileMetadata, PDFTrailer, PDFTrailerList)
from cybox.objects.process_object import (ArgumentList, ChildPIDList,
                                          ImageInfo, Process)
from cybox.objects.product_object import Product
from cybox.objects.uri_object import URI
from cybox.objects.user_account_object import UserAccount
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
from cybox.objects.win_user_object import WinUser
from cybox.objects.x509_certificate_object import (RSAPublicKey,
                                                   SubjectPublicKey, X509Cert,
                                                   X509Certificate,
                                                   X509V3Extensions)
import stix2
from stix2.patterns import (BasicObjectPathComponent, ListObjectPathComponent,
                            ObjectPath, _ComparisonExpression)

from stix2slider.common import (AUTONOMOUS_SYSTEM_MAP, FILE_MAP,
                                IMAGE_FILE_EXTENSION_MAP,
                                OTHER_EMAIL_HEADERS_MAP,
                                PDF_DOCUMENT_INFORMATION_DICT_MAP,
                                PE_BINARY_FILE_HEADER_MAP,
                                PE_BINARY_OPTIONAL_HEADER_MAP, PROCESS_MAP,
                                STARTUP_INFO_MAP,
                                WINDOWS_PROCESS_EXTENSION_MAP,
                                WINDOWS_SERVICE_EXTENSION_MAP,
                                X509_CERTIFICATE_MAP,
                                X509_V3_EXTENSIONS_TYPE_MAP, convert_pe_type)
from stix2slider.convert_cyber_observables import (convert_addr_c_o,
                                                   convert_artifact_c_o,
                                                   convert_file_c_o)
from stix2slider.options import warn

_CYBOX_OBJECT_MAP = {
    "artifact": Artifact,
    "autonomous-system": AutonomousSystem,
    "domain-name": DomainName,
    "directory": File,
    "email-message": EmailMessage,
    "file": File,
    "archive-ext": ArchiveFile,
    "pdf-ext": PDFFile,
    "raster-image-ext": ImageFile,
    "ntfs-ext": WinFile,
    "windows-pebinary-ext": WinExecutableFile,
    "ipv4-addr": Address,
    "ipv6-addr": Address,
    "mutex": Mutex,
    "process": Process,
    "software": Product,
    "url": URI,
    "user-account": WinUser,
    "unix-account-ext": UserAccount,
    "windows-registry-key": WinRegistryKey,
    "x509-certificate": X509Certificate
}


class ObjectPathForSlider(ObjectPath):
    def determine_expression_type(self, rhs):
        if isinstance(self.property_path[0], BasicObjectPathComponent) and self.property_path[0].property_name == 'extensions':
            return set([self.property_path[1].property_name, self.object_type_name])
        else:
            # special case for user accounts
            if self.object_type_name == "user-account" and (self.property_path[0].property_name == 'user_id' or
                                                            (self.property_path[0].property_name == 'account_type' and
                                                             rhs.value == 'unix')):
                return set(["user-account", "unix-account-ext"])
            else:
                return set([self.object_type_name])


class ComparisonExpressionForSlider(_ComparisonExpression):
    def toSTIX1x(self, id20, existing_obj=None):
        if not existing_obj:
            cyboxClassConstructor = map_extensions_to_cybox_class(self.determine_expression_type())
            existing_obj = cyboxClassConstructor()
        if isinstance(existing_obj, Address):
            convert_addr_pattern(self, existing_obj, id20)
        elif isinstance(existing_obj, Artifact):
            convert_artifact_pattern(self, existing_obj, id20)
        elif isinstance(existing_obj, AutonomousSystem):
            convert_autonomous_system_pattern(self, existing_obj, id20)
        elif isinstance(existing_obj, DomainName):
            convert_domain_name_pattern(self, existing_obj, id20)
        elif isinstance(existing_obj, EmailAddress):
            convert_addr_pattern(self, existing_obj, id20)
        elif isinstance(existing_obj, EmailMessage):
            convert_email_message_pattern(self, existing_obj, id20)
        elif isinstance(existing_obj, File):
            convert_file_pattern(self, existing_obj, id20)
        elif isinstance(existing_obj, Mutex):
            convert_mutex_pattern(self, existing_obj, id20)
        elif (isinstance(existing_obj, Process) or
              isinstance(existing_obj, WinProcess) or
              isinstance(existing_obj, WinService)):
            convert_process_pattern(self, existing_obj, id20)
        elif isinstance(existing_obj, Product):
            convert_software_pattern(self, existing_obj, id20)
        elif isinstance(existing_obj, URI):
            convert_url_pattern(self, existing_obj, id20)
        elif (isinstance(existing_obj, UserAccount) or
              isinstance(existing_obj, WinUser)):
            convert_user_account_pattern(self, existing_obj, id20)
        elif isinstance(existing_obj, WinRegistryKey):
            convert_registry_key_pattern(self, existing_obj, id20)
        elif isinstance(existing_obj, X509Certificate):
            convert_x509_certificate_pattern(self, existing_obj, id20)
        return Observable(existing_obj)

    def determine_expression_type(self):
        return self.lhs.determine_expression_type(self.rhs)


class EqualityComparisonExpressionForSlider(ComparisonExpressionForSlider):
    def __init__(self, lhs, rhs, negated=False):
        super(EqualityComparisonExpressionForSlider, self).__init__("=", lhs, rhs, negated)


class MatchesComparisonExpressionForSlider(ComparisonExpressionForSlider):
    def __init__(self, lhs, rhs, negated=False):
        super(MatchesComparisonExpressionForSlider, self).__init__("MATCHES", lhs, rhs, negated)


class GreaterThanComparisonExpressionForSlider(ComparisonExpressionForSlider):
    def __init__(self, lhs, rhs, negated=False):
        super(GreaterThanComparisonExpressionForSlider, self).__init__(">", lhs, rhs, negated)


class LessThanComparisonExpressionForSlider(ComparisonExpressionForSlider):
    def __init__(self, lhs, rhs, negated=False):
        super(LessThanComparisonExpressionForSlider, self).__init__("<", lhs, rhs, negated)


class GreaterThanEqualComparisonExpressionForSlider(ComparisonExpressionForSlider):
    def __init__(self, lhs, rhs, negated=False):
        super(GreaterThanEqualComparisonExpressionForSlider, self).__init__(">=", lhs, rhs, negated)


class LessThanEqualComparisonExpressionForSlider(ComparisonExpressionForSlider):
    def __init__(self, lhs, rhs, negated=False):
        super(LessThanEqualComparisonExpressionForSlider, self).__init__("<=", lhs, rhs, negated)


# class InComparisonExpressionForSlider(ComparisonExpressionForSlider):
#     def __init__(self, lhs, rhs, negated=False):
#         super(InComparisonExpressionForSlider, self).__init__("IN", lhs, rhs, negated)


class LikeComparisonExpressionForSlider(ComparisonExpressionForSlider):
    def __init__(self, lhs, rhs, negated=False):
        super(LikeComparisonExpressionForSlider, self).__init__("LIKE", lhs, rhs, negated)


class AndBooleanExpressionForSlider(stix2.AndBooleanExpression):
    def toSTIX1x(self, id20, existing_obj=None):
        if not existing_obj:
            cyboxClasses = self.determine_expression_type()
            if cyboxClasses:
                cyboxClassConstructor = map_extensions_to_cybox_class(cyboxClasses)
                existing_obj = cyboxClassConstructor()
        if existing_obj:
            for operand in self.operands:
                observable = operand.toSTIX1x(id20, existing_obj)
            return observable
        else:
            terms = []
            for operand in self.operands:
                terms.append(operand.toSTIX1x(id20))
            return ObservableComposition(operator="AND", observables=terms)

    def determine_expression_type(self):
        types = set()
        first = True
        for o in self.operands:
            types = merge_operand_types(types, o.determine_expression_type(), first)
            first = False
        return types


class OrBooleanExpressionForSlider(stix2.OrBooleanExpression):
    def toSTIX1x(self, id20, existing_obj=None):
        # Or operands don't have to be the same class, and each operand is matched separately, so existing_obj is ignored
        terms = []
        for operand in self.operands:
            terms.append(operand.toSTIX1x(id20))
        return ObservableComposition(operator="OR", observables=terms)

    def determine_expression_type(self):
        return set()


class ObservationExpressionForSlider(stix2.ObservationExpression):
    def toSTIX1x(self, id20, existing_obj=None):
        return self.operand.toSTIX1x(id20, existing_obj)


class AndObservationExpressionForSlider(stix2.AndObservationExpression):
    def toSTIX1x(self, id20, existing_obj=None):
        terms = []
        for operand in self.operands:
            terms.append(operand.toSTIX1x(id20, existing_obj))
        return ObservableComposition(operator="AND", observables=terms)


class OrObservationExpressionForSlider(stix2.OrObservationExpression):
    def toSTIX1x(self, id20, existing_obj=None):
        terms = []
        for operand in self.operands:
            terms.append(operand.toSTIX1x(id20, existing_obj))
        return ObservableComposition(operator="OR", observables=terms)


class QualifiedObservationExpressionForSlider(stix2.QualifiedObservationExpression):
    def toSTIX1x(self, id20, existing_obj=None):
        if self.qualifier:
            pass
            # warn: no Qualifiers in STIX 1.x
        return self.observation_expression.toSTIX1x(id20, existing_obj)


class ParentheticalExpressionForSlider(stix2.ParentheticalExpression):
    def toSTIX1x(self, id20, existing_obj=None):
        return self.expression.toSTIX1x(id20, existing_obj)

    def determine_expression_type(self):
        return self.expression.determine_expression_type()


def map_extensions_to_cybox_class(types):
    if len(types) == 1:
        stix2_type_name = types.pop()
        return _CYBOX_OBJECT_MAP[stix2_type_name]
    elif len(types) == 2:
        if "file" in types:
            types = types - set(["file"])
            stix2_type_name = types.pop()
            return _CYBOX_OBJECT_MAP[stix2_type_name]
        elif "user-account" in types:
            types = types - set(["user-account"])
            stix2_type_name = types.pop()
            return _CYBOX_OBJECT_MAP[stix2_type_name]
    else:
        pass
        # warn: don't handle more than one extension yet


def merge_operand_types(current_types, operand_types, first):
    if not operand_types:
        return set()
    else:
        if first:
            return operand_types
        for t in operand_types:
            if t not in current_types:
                return set()
        return current_types | operand_types


def convert_operator(op, obj, id20):
    if op == "=":
        obj.condition = "Equals"
    elif op == "!=":
        obj.condition = "DoesNotEqual"
    elif op == "IN":
        obj.condition = "Contains"
    elif op == ">":
        obj.condition = "GreaterThan"
    elif op == ">=":
        obj.condition = "GreaterThanOrEqual"
    elif op == "<":
        obj.condition = "LessThan"
    elif op == "<=":
        obj.condition = "LessThanOrEqual"
    elif op == "MATCHES":
        obj.condition = "FitsPattern"
        obj.pattern_type = "Regex"
    else:
        warn("%s cannot be converted to a STIX 1.x operator in the pattern of %s", 505, op, id20)


def convert_pattern(obj, property_name, rhs, op, mapping_table, id20):
    for key, value in mapping_table.items():
        if property_name == key:
            mapping_table[key].__set__(obj, rhs.value)
            convert_operator(op, mapping_table[key].__get__(obj), id20)
            return True
    return False


def add_scalar_artifact_property_pattern(obj, properties, rhs, op, id20):
    prop_name = properties[0].property_name
    if prop_name == "mime_type":
        obj.content_type = rhs.value
        # no op because its an XML attribute
        if op != "=":
            warn("%s is an XML attribute of %s in STIX 1.x, so the operator 'equals' is assumed in %s",
                 0,
                 "mime_type", "Artifact", id20)
    # it is illegal in STIX 2.0 to have both a payload_bin and url property - be we don't warn about it here
    elif prop_name == "payload_bin":
        obj.packed_data = rhs.value
        # TODO: op?
    elif prop_name == "url":
        obj.raw_artifact_reference = rhs.value
    # art1x.packaging.encoding.algorithm = "Base64"
    else:
        warn("%s is not a legal property in the pattern of %s", 303, prop_name, id20)


def convert_artifact_pattern(exp20, obj1x, id20):
    if isinstance(exp20.lhs.property_path[0], stix2.ListObjectPathComponent):
        pass  # add_list_artifact_property_pattern(obj1x, exp20.lhs.property_path, exp20.rhs, exp20.operator)
    elif len(exp20.lhs.property_path) == 2 and \
            isinstance(exp20.lhs.property_path[0], stix2.BasicObjectPathComponent) and \
            exp20.lhs.property_path[0].property_name == 'hashes':
        add_hashes_pattern(obj1x, exp20.lhs.property_path[1].property_name, exp20.rhs, exp20.operator, id20)
    else:
        add_scalar_artifact_property_pattern(obj1x, exp20.lhs.property_path, exp20.rhs, exp20.operator, id20)


# _AUTONOMOUS_SYSTEM_MAP = {
#     "number": AutonomousSystem.number,
#     "name": AutonomousSystem.name,
#     "rir": AutonomousSystem.regional_internet_registry
# }


def convert_autonomous_system_pattern(exp20, obj1x, id20):
    prop_name = exp20.lhs.property_path[0].property_name
    if not convert_pattern(obj1x,
                           prop_name,
                           exp20.rhs,
                           exp20.operator,
                           AUTONOMOUS_SYSTEM_MAP,
                           id20):
        warn("%s is not a legal property in the pattern of %s", 303, prop_name, id20)


def convert_addr_pattern(exp20, obj1x, id20):
    properties = exp20.lhs.property_path
    rhs_value = exp20.rhs.value
    op = exp20.operator
    prop_name = properties[0].property_name
    if prop_name == "value":
        obj1x.address_value = rhs_value
        convert_operator(op, obj1x, id20)
        # TODO: handle cidrs
        ip_add_type = exp20.root_type
        if ip_add_type == 'ipv4-addr':
            obj1x.category = Address.CAT_IPV4
        elif ip_add_type == 'ipv6-addr':
            obj1x.category = Address.CAT_IPV6
        elif ip_add_type == 'mac-addr':
            obj1x.category = Address.CAT_MAC
        elif ip_add_type == 'email-addr':
            obj1x.category = Address.CAT_EMAIL
        else:
            warn("Unknown address type %s used in %s", 304, ip_add_type, id20)
    elif prop_name == "resolves_to_refs":
        if properties[0].index == "*":
            ref_obj = Address()
            convert_addr_c_o({"value": rhs_value, "type": 'mac-addr'}, ref_obj, id20)
            obj1x.add_related(ref_obj, "Resolved_To", inline=True)
    # TODO: belongs_to_refs


def convert_domain_name_pattern(exp20, obj1x, id20):
    obj1x.value = exp20.rhs.value
    convert_operator(exp20.operator, obj1x, id20)
    obj1x.type_ = "FQDN"
    # TODO: warn no resolves_to in STIX 1.x


def add_scalar_email_message_property_pattern(obj, properties, rhs, op, id20):
    prop_name = properties[0].property_name
    # TODO: is_multipart
    if prop_name == "date":
        obj.date = rhs.value
        convert_operator(op, obj.date, id20)
    elif prop_name == "content_type":
        obj.header.content_type = rhs.value
        convert_operator(op, obj.header.content_type, id20)
    elif prop_name == "from_ref":
        obj.header.from_ = rhs.value
        convert_operator(op, obj.header.from_, id20)
    elif prop_name == "sender_ref":
        obj.header.sender = rhs.value
        convert_operator(op, obj.header.sender, id20)
    elif prop_name == "subject":
        obj.subject = rhs.value
        convert_operator(op, obj.header.subject, id20)
    else:
        warn("%s is not a legal property in the pattern of %s", 303, prop_name, id20)


def add_list_email_message_property_pattern(obj, properties, rhs, op, id20):
    prop_name = properties[0].property_name
    if prop_name == "to_refs":
        if properties[0].index == "*":
            if not obj.to:
                obj.to = EmailRecipients()
            add_obj = EmailAddress(rhs.value)
            convert_operator(op, add_obj, id20)
            obj.to.append(add_obj)
        else:
            warn("number indicies in %s not handled, yet", 602, id20)
    elif prop_name == "cc_refs":
        if properties[0].index == "*":
            if not obj.cc:
                obj.cc = EmailRecipients()
            add_obj = EmailAddress(rhs.value)
            convert_operator(op, add_obj, id20)
            obj.cc.append(add_obj)
        else:
            warn("number indicies in %s not handled, yet", 602, id20)
    elif prop_name == "bcc_refs":
        if properties[0].index == "*":
            if not obj.bcc:
                obj.bcc = EmailRecipients()
            add_obj = EmailAddress(rhs.value)
            convert_operator(op, add_obj, id20)
            obj.bcc.append(add_obj)
        else:
            warn("number indicies in %s not handled, yet", 602, id20)
    elif prop_name == "additional_header_fields":
        prop_name1 = properties[1].property_name
        if not convert_pattern(obj, prop_name1, rhs, op, OTHER_EMAIL_HEADERS_MAP, id20):
            warn("%s property is not representable in a STIX 1.x %s. Found in the pattern of %s", 504, prop_name1, "EmailMessage", id20)
    else:
        warn("%s is not a legal property in the pattern of %s", 303, prop_name, id20)


def convert_email_message_pattern(exp20, obj1x, id20):
    if not obj1x.header:
        obj1x.header = EmailHeader()
    if isinstance(exp20.lhs.property_path[0], stix2.ListObjectPathComponent):
        add_list_email_message_property_pattern(obj1x, exp20.lhs.property_path, exp20.rhs, exp20.operator, id20)
    else:
        add_scalar_email_message_property_pattern(obj1x, exp20.lhs.property_path, exp20.rhs, exp20.operator, id20)


# _FILE_MAP = {
#     "size": File.size_in_bytes,
#     "name": File.file_name,
#     # TODO: name_enc
#     "magic_number_hex": File.magic_number,
#     # TODO: mime_type
#     "created": File.created_time,
#     "modified": File.modified_time,
#     "accessed": File.accessed_time,
#     # TODO: is_encrypted
#     "encrpytion_algorithm": File.encryption_algorithm,
#     "decryption_key": File.decryption_key
# }


def add_scalar_file_property_pattern(file_obj, properties, rhs, op, id20):
    prop_name = properties[0].property_name
    if convert_pattern(file_obj, prop_name, rhs, op, FILE_MAP, id20):
        return
    elif prop_name == 'parent_directory_ref':
        if properties[1].property_name == 'path':
            # TODO: what if name isn't available
            # TODO: determine correct separator
            file_obj.full_path = rhs.value + "/" + str(file_obj.file_name)
            # condition?
        else:
            pass
            # TODO: path is the only directory property supportable in STIX 1.x
    elif prop_name == 'content_ref':
        # TODO: what if there are mutiple references to the same object?
        obs = Artifact()
        convert_artifact_c_o({properties[1].property_name: rhs.value}, obs)
        # operator??
        file_obj.add_related(obs, "Contains", inline=True)
    else:
        warn("%s is not a legal property in the pattern of %s", 303, prop_name, id20)


def add_list_file_property_pattern(file_obj, properties, rhs, op, id20):
    prop_name = properties[0].property_name
    if prop_name == 'contains_refs':
        warn("The %s property in %s can refer to any object, so it is not handled yet.", 601, prop_name, id20)
    else:
        warn("%s is not a legal property in the pattern of %s", 303, prop_name, id20)


def add_hashes_pattern(obj, hash_type, rhs, op, id20):
    if hash_type == "MD5":
        obj.md5 = rhs.value
        convert_operator(op, obj.hashes._hash_lookup(Hash.TYPE_MD5).simple_hash_value, id20)
    elif hash_type == "SHA-1":
        obj.sha1 = rhs.value
        convert_operator(op, obj.hashes._hash_lookup(Hash.TYPE_SHA1).simple_hash_value, id20)
    elif hash_type == "SHA-224":
        obj.sha224 = rhs.value
        convert_operator(op, obj.hashes._hash_lookup(Hash.TYPE_SHA224).simple_hash_value, id20)
    elif hash_type == "SHA-256":
        obj.sha256 = rhs.value
        convert_operator(op, obj.hashes._hash_lookup(Hash.TYPE_SHA256).simple_hash_value, id20)
    elif hash_type == "SHA-384":
        obj.sha384 = rhs.value
        convert_operator(op, obj.hashes._hash_lookup(Hash.TYPE_SHA384).simple_hash_value, id20)
    elif hash_type == "SHA-512":
        obj.sha512 = rhs.value
        convert_operator(op, obj.hashes._hash_lookup(Hash.TYPE_SHA512).simple_hash_value, id20)
    else:
        warn("Unknown hash type %s used in %s", 302, hash_type, id20)


# _IMAGE_FILE_EXTENSION_MAP = {
#     "image_height": ImageFile.image_height,
#     "image_width": ImageFile.image_width,
#     "bits_per_pixel": ImageFile.bits_per_pixel,
#     "image_compression_algorithm": ImageFile.compression_algorithm
# }
#


def add_file_archive_extension_pattern(file_obj, properties, rhs, op, id20):
    prop_name1 = properties[1].property_name
    if prop_name1 == "comment":
        file_obj.comment = rhs.value
        convert_operator(op, file_obj.comment, id20)
    elif prop_name1 == "version":
        file_obj.version = rhs.value
        convert_operator(op, file_obj.version, id20)
    elif prop_name1 == "contains_refs":
        # TODO:  what if the referenced file is also an extension - should it be a File class?
        if isinstance(properties[0], ListObjectPathComponent):
            if properties[0].index == "*":
                ref_obj = File()
                convert_file_c_o({"name": rhs.value}, ref_obj)
                # ref_obj. = convert_operator(op)
                file_obj.archived_file.append(ref_obj)
            else:
                warn("number indicies in %s not handled, yet", 602, id20)
    else:
        warn("%s is not a legal property in the pattern of %s", 303, prop_name1, id20)


def add_file_ntfs_extension_pattern(file_obj, properties, rhs, op, id20):
    prop_name1 = properties[1].property_name
    if prop_name1 == "sid":
        file_obj.security_id = rhs.value
    elif prop_name1 == "alternate_data_streams":
        if properties[1].index == "*":
            prop_name2 = properties[2].property_name
            if not file_obj.stream_list:
                file_obj.stream_list = StreamList()
                ads1x = Stream()
                file_obj.stream_list.append(ads1x)
            if prop_name2 == "name":
                ads1x.name = rhs.value
            elif prop_name2 == "size":
                ads1x.size_in_bytes = rhs.value
            elif prop_name2 == "hashes":
                add_hashes_pattern(ads1x, properties[3].property_name, rhs, op, id20)
            else:
                warn("number indicies in %s not handled, yet", 601, id20)


def add_file_pdf_extension_pattern(file_obj, properties, rhs, op, id20):
    prop_name1 = properties[1].property_name
    # TODO: pdfid0, pdfid1
    if prop_name1 == "version":
        file_obj.version = rhs.value
        convert_operator(op, file_obj.version, id20)
    elif prop_name1 == "is_optimized" or prop_name1 == "document_info_dict":
        if not file_obj.metadata:
            file_obj.metadata = PDFFileMetadata()
        if prop_name1 == "is_optimized":
            file_obj.metadata.optimized = rhs.value
            convert_operator(op, file_obj.metadata.optimized, id20)
        elif prop_name1 == "document_info_dict":
            if not file_obj.metadata.document_information_dictionary:
                file_obj.metadata.document_information_dictionary = PDFDocumentInformationDictionary()
            convert_pattern(file_obj.metadata.document_information_dictionary,
                            properties[2].property_name,
                            rhs,
                            op,
                            PDF_DOCUMENT_INFORMATION_DICT_MAP,
                            id20)
    elif prop_name1 == "pdfid0" or prop_name1 == "pdfid1":
        warn("Order may not be maintained for pdfids in %s", 514, id20)
        if not file_obj.trailers:
            file_obj.trailers = PDFTrailerList()
            trailer = PDFTrailer()
            file_obj.trailers.trailer.append(trailer)
            trailer.id_ = PDFFileID()
        if prop_name1 == "pdfid0":
            trailer.id_.id_string.append(rhs.value)
        if prop_name1 == "pdfid1":
            trailer.id_.id_string.append(rhs.value)
    else:
        warn("%s is not a legal property in the pattern of %s", 303, prop_name1, id20)

def add_file_windows_pebinary_extension_pattern(file_obj, properties, rhs, op, id20):
    # TODO: imphash
    # TODO: number_of_sections
    prop_name1 = properties[1].property_name
    if prop_name1 == "pe_type":
        file_obj.type_ = convert_pe_type(rhs.value, id20)
    elif (prop_name1 == "machine_hex" or
            prop_name1 == "time_date_stamp" or
            prop_name1 == "pointer_to_symbol_table_hex" or
            prop_name1 == "number_of_symbols" or
            prop_name1 == "size_of_optional_header" or
            prop_name1 == "characteristics_hex"):
        if not file_obj.headers:
            file_obj.headers = PEHeaders()
        if not file_obj.headers.file_header:
            file_obj.headers.file_header = PEFileHeader()
        if convert_pattern(file_obj.headers.file_header, prop_name1, rhs, op, PE_BINARY_FILE_HEADER_MAP, id20):
            return
    elif prop_name1 == "file_header_hashes":
        if not file_obj.headers:
            file_obj.headers = PEHeaders()
        if not file_obj.headers.file_header:
            file_obj.headers.file_header = PEFileHeader()
        if not file_obj.headers.file_header.hashes:
            file_obj.headers.file_header.hashes = HashList()
        add_hashes_pattern(file_obj.headers.file_header.hashes, properties[2].property_name, rhs, op, id20)
    elif prop_name1 == "optional_header":
        if not file_obj.headers:
            file_obj.headers = PEHeaders()
        if not file_obj.headers.optional_header:
            file_obj.headers.optional_header = PEOptionalHeader()
        prop_name2 = properties[2].property_name
        convert_pattern(file_obj.headers.optional_header, prop_name2, rhs, op, PE_BINARY_OPTIONAL_HEADER_MAP, id20)
        if prop_name2 == "hashes":
            file_obj.headers.optional_header.hashes = HashList()
            add_hashes_pattern(file_obj.headers.file_header.hashes, properties[3].property_name, rhs, op, id20)
    elif prop_name1 == "sections":
        if properties[1].index == "*":
            if not file_obj.sections:
                file_obj.sections = PESectionList()
                section = PESection()
                file_obj.sections.section.append(section)
            prop_name2 = properties[2].property_name
            if prop_name2 == "name" or prop_name2 == "size":
                if not file_obj.sections.section.section_header:
                    file_obj.sections.section.section_header = PESectionHeaderStruct()
                    if prop_name2 == "name":
                        section.section_header.name = rhs.value
                        convert_operator(op, section.section_header.name, id20)
                    elif prop_name2 == "size":
                        section.section_header.size_of_raw_data = rhs.value
                        convert_operator(op, section.section_header.size_of_raw_data, id20)
            elif prop_name2 == "entropy":
                section.entropy = Entropy()
                section.entropy.value = rhs.value
                convert_operator(op, section.entropy.value, id20)
            elif prop_name2 == "hashes":
                if section.data_hashes:
                    section.data_hashes = HashList()
                add_hashes_pattern(section.data_hashes, properties[3].property_name, rhs, op, id20)
        else:
            warn("number indicies in %s not handled, yet", 601, id20)


def add_file_extension_pattern(file_obj, properties, rhs, op, id20):
    prop_name0 = properties[0].property_name
    if prop_name0 == "archive-ext":
        add_file_archive_extension_pattern(file_obj, properties, rhs, op, id20)
    elif prop_name0 == "raster-image-ext":
        convert_pattern(file_obj, prop_name0, rhs, op, IMAGE_FILE_EXTENSION_MAP, id20)
    elif prop_name0 == "ntfs-file-ext":
        add_file_ntfs_extension_pattern(file_obj, properties, rhs, op, id20)
    elif prop_name0 == "pdf-ext":
        add_file_pdf_extension_pattern(file_obj, properties, rhs, op, id20)
    elif prop_name0 == "windows-pebinary-ext":
        add_file_windows_pebinary_extension_pattern(file_obj, properties, rhs, op, id20)
    else:
        warn("%s is not a legal property in the pattern of %s", 303, prop_name0, id20)


def convert_file_pattern(exp20, obj1x, id20):
    if isinstance(exp20.lhs.property_path[0], stix2.ListObjectPathComponent):
        add_list_file_property_pattern(obj1x, exp20.lhs.property_path, exp20.rhs, exp20.operator, id20)
    elif len(exp20.lhs.property_path) == 2 and \
            isinstance(exp20.lhs.property_path[0], stix2.BasicObjectPathComponent) and \
            exp20.lhs.property_path[0].property_name == 'hashes':
        add_hashes_pattern(obj1x, exp20.lhs.property_path[1].property_name, exp20.rhs, exp20.operator, id20)
    elif len(exp20.lhs.property_path) > 2 and \
            isinstance(exp20.lhs.property_path[0], stix2.BasicObjectPathComponent) and \
            exp20.lhs.property_path[0].property_name == 'extensions':
        add_file_extension_pattern(obj1x, exp20.lhs.property_path[1:], exp20.rhs, exp20.operator, id20)
    else:
        add_scalar_file_property_pattern(obj1x, exp20.lhs.property_path, exp20.rhs, exp20.operator, id20)


def convert_url_pattern(exp20, obj1x, id20):
    prop_name = exp20.lhs.property_path[0].property_name
    if prop_name == "value":
        obj1x.value = exp20.rhs.value
        convert_operator(exp20.operator, obj1x.value, id20)
    else:
        warn("%s is not a legal property in the pattern of %s", 303, prop_name, id20)


# _WINDOWS_PROCESS_EXTENSION_MAP = {
#     "aslr_enabled": WinProcess.aslr_enabled,
#     "dep_enabled": WinProcess.dep_enabled,
#     "priority": WinProcess.priority,
#     "owner_sid": WinProcess.security_id,
#     "window_title": WinProcess.window_title
# }
#
#
# _PROCESS_MAP = {
#     "is_hidden": Process.is_hidden,
#     "pid": Process.pid,
#     "name": Process.name,
#     "created": Process.creation_time
# }


def add_scalar_process_property_pattern(process_obj, properties, rhs, op, id20):
    prop_name0 = properties[0].property_name
    if convert_pattern(process_obj, prop_name0, rhs, op, PROCESS_MAP, id20):
        return
    elif prop_name0 == "command_line":
        process_obj.image_info = ImageInfo()
        process_obj.image_info.command_line = rhs.value
        convert_operator(op, process_obj.image_info.command_line, id20)
    # TODO: opened_connection_ref
    elif prop_name0 == "creator_user_ref":
        prop_name1 = properties[1].property_name
        if prop_name1 == 'account_login':
            process_obj.username = rhs.value
            convert_operator(op, process_obj.username, id20)
        else:
            warn("%s not representable in a STIX 1.x %s.  Found in the pattern of %s", 504, prop_name1, "Account", id20)
    elif prop_name0 == "binary_ref":
        # TODO: what if there are mutiple references to the same object?
        obs = convert_file_c_o({properties[1].property_name: rhs.value}, File())
        # operator??
        process_obj.add_related(obs, "Contains", inline=True)
    elif prop_name0 == "parent_ref":
        prop_name1 = properties[1].property_name
        if prop_name1 == 'pid':
            process_obj.parent_pid = rhs.value
            convert_operator(op, process_obj.parent_pid, id20)
        else:
            warn("%s not representable in a STIX 1.x %s.  Found in the pattern of %s", 504, prop_name1, "Process", id20)


def convert_mutex_pattern(exp20, obj1x, id20):
    prop_name = exp20.lhs.properties[0].property_name
    if prop_name == "name":
        obj1x.name = exp20.rhs.value
        convert_operator(exp20.operator, obj1x.name, id20)
        obj1x.named = True
        # TODO: do we need an operator?
    else:
        warn("%s is not a legal property in the pattern of %s", 303, prop_name, id20)


def add_list_process_property_pattern(process_obj, properties, rhs, op, id20):
    prop_name = properties[0].property_name
    if prop_name == "arguments":
        if properties[0].index == "*":
            if not process_obj.argument_list:
                process_obj.argument_list = ArgumentList()
            process_obj.argument_list.append(rhs.value)
            # condition??
        else:
            warn("number indicies in %s not handled, yet", 601, id20)
    elif prop_name == "environment_variables":
        prop_name1 = properties[1].property_name
        if not process_obj.environment_variable_list:
            process_obj.environment_variable_list = EnvironmentVariableList()
        ev = EnvironmentVariable()
        process_obj.environment_variable_list.append(ev)
        ev.name = prop_name1
        ev.value = rhs.value
    # TODO: opened_connection_ref
    elif prop_name == "child_refs":
        if properties[0].index == "*":
            prop_name1 = properties[1].property_name
            if prop_name1 == 'pid':
                if not process_obj.child_pid_list:
                    process_obj.child_pid_list = ChildPIDList()
                process_obj.child_pid_list.append(rhs.value)
                # condition??
            else:
                warn("%s not representable in a STIX 1.x %s.  Found in the pattern of %s", 504, "Process", prop_name1, id20)
        else:
            warn("number indicies in %s not handled, yet", 601, id20)
    else:
        warn("%s is not a legal property in the pattern of %s", 303, prop_name, id20)

# _WINDOWS_PROCESS_EXTENSION_MAP = {
#     "aslr_enabled": WinProcess.aslr_enabled,
#     "dep_enabled": WinProcess.dep_enabled,
#     "priority": WinProcess.priority,
#     "owner_sid": WinProcess.security_id,
#     "window_title": WinProcess.window_title
# }
#
#
# _STARTUP_INFO_MAP = {
#     "lpdesktop": StartupInfo.lpdesktop,
#     "lptitle": StartupInfo.lptitle,
#     "dwx": StartupInfo.dwx,
#     "dwy": StartupInfo.dwy,
#     "dwxsize": StartupInfo.dwxsize,
#     "dwysize": StartupInfo.dwysize,
#     "dwxcountchars": StartupInfo.dwxcountchars,
#     "dwycountchars": StartupInfo.dwycountchars,
#     "dwfillattribute": StartupInfo.dwfillattribute,
#     "dwflags": StartupInfo.dwflags,
#     "wshowwindow": StartupInfo.wshowwindow,
#     "hstdinput": StartupInfo.hstdinput,
#     "hstdoutput": StartupInfo.hstdoutput,
#     "hstderror": StartupInfo.hstderror
# }
#
#
# _WINDOWS_SERVICE_EXTENSION_MAP = {
#     "service_name": WinService.service_name,
#     "display_name": WinService.display_name,
#     "group_name": WinService.group_name,
#     "start_type": WinService.startup_type,
#     "service_type": WinService.service_type,
#     "service_status": WinService.service_status
#
# }


def add_process_extension_pattern(process_obj, properties, rhs, op, id20):
    prop_name0 = properties[0].property_name
    prop_name1 = properties[1].property_name
    if prop_name0 == "win-process-ext":
        if not convert_pattern(process_obj, prop_name1, rhs, op, WINDOWS_PROCESS_EXTENSION_MAP, id20):
            if prop_name1 == "startup_info":
                if not process_obj.startup_info:
                    process_obj.startup_info = StartupInfo()
                convert_pattern(process_obj.startup_info, properties[2].property_name, rhs, op, STARTUP_INFO_MAP, id20)
    elif prop_name0 == "win-service-ext":
        if not convert_pattern(process_obj, prop_name1, rhs, op, WINDOWS_SERVICE_EXTENSION_MAP, id20):
            if prop_name1 == "service_dll_refs":
                if properties[1].index == "*":
                    if process_obj.service_dll:
                        warn("Only one dll can be represented in STIX 1.x for %s, using first one - ignoring %s",
                             402,
                             rhs.value, id20)
                    else:
                        process_obj.service_dll = rhs.value
            if prop_name1 == "descriptions":
                if not process_obj.descriptions:
                    process_obj.descriptions = ServiceDescriptionList()
                # TODO:  is this they way to make this assignment?
                process_obj.descriptions.description = rhs.value


def convert_process_pattern(exp20, obj1x, id20):
    if isinstance(exp20.lhs.property_path[0], stix2.ListObjectPathComponent):
        add_list_process_property_pattern(obj1x, exp20.lhs.property_path, exp20.rhs, exp20.operator, id20)
    elif len(exp20.lhs.property_path) > 2 and \
            isinstance(exp20.lhs.property_path[0], stix2.BasicObjectPathComponent) and \
            exp20.lhs.property_path[0].property_name == 'extensions':
        add_process_extension_pattern(obj1x, exp20.lhs.property_path[1, ], exp20.rhs, exp20.operator, id20)
    else:
        add_scalar_process_property_pattern(obj1x, exp20.lhs.property_path, exp20.rhs, exp20.operator, id20)


def add_list_software_property_pattern(software_obj, properties, rhs, op, id20):
    prop_name = properties[0].property_name
    if properties[0].property_name == "languages":
        if properties[0].index == "*":
            if software_obj.language:
                pass
                # warn: current value will be overridden
            software_obj.language = rhs.value
    else:
        warn("%s is not a legal property in the pattern of %s", 303, prop_name, id20)


def add_scalar_software_property_pattern(software_obj, properties, rhs, op, id20):
    software_obj.product = rhs.value
    prop_name = properties[0].property_name
    convert_operator(op, software_obj.product, id20)
    # TODO cpe
    if prop_name == "vendor":
        software_obj.vendor = rhs.value
        convert_operator(op, software_obj.vendor, id20)
    elif prop_name == "version":
        software_obj.version = rhs.value
        convert_operator(op, software_obj.version, id20)
    else:
        warn("%s is not a legal property in the pattern of %s", 303, prop_name, id20)


def convert_software_pattern(exp20, obj1x, id20):
    if isinstance(exp20.lhs.property_path[0], stix2.ListObjectPathComponent):
        add_list_software_property_pattern(obj1x, exp20.lhs.property_path, exp20.rhs, exp20.operator, id20)
    else:
        add_scalar_software_property_pattern(obj1x, exp20.lhs.property_path, exp20.rhs, exp20.operator, id20)


def convert_user_account_pattern(exp20, obj1x, id20):
    properties = exp20.lhs.property_path
    rhs_value = exp20.rhs.value
    op = exp20.operator
    prop_name = properties[0].property_name
    if prop_name == "user_id":
        pass
    # warn - in STIX 1.x, but not python-stix???
    #    obj1x.user_id = rhs_value
    #    convert_operator(op, obj1x.user_id)
    elif prop_name == "account_login":
        obj1x.username = rhs_value
        convert_operator(op, obj1x.username, id20)
    elif prop_name == "account_type":
        warn("account_type property of %s in STIX 2.0 is not directly represented as a property in STIX 1.x", 506, id20)
    # TODO: account_type -> Account.Domain??
    # TODO: display_name
    # TODO: is_service_account
    # TODO: is_privileged -> UserAccount.Privilige_List?
    # TODO: can_escalate_privs -> UserAccount.Privilige_List?
    elif prop_name == "is_disabled":
        obj1x.disabled = rhs_value
        convert_operator(op, obj1x.disabled, id20)
    elif prop_name == "account-created":
        obj1x.created_time = rhs_value
        convert_operator(op, obj1x.created_time, id20)
    # TODO: account_expires
    # TODO: password_last_changed
    # TODO: account_first_login
    elif prop_name == "account_last_login":
        obj1x.last_login = rhs_value
        convert_operator(op, obj1x.last_login, id20)
    else:
        warn("%s is not a legal property in the pattern of %s", 303, prop_name, id20)


def add_list_registry_key_property_pattern(registry_key_obj, properties, rhs, op, id20):
    prop_name = properties[0].property_name
    if properties[0].property_name == "values":
        if properties[0].index == "*":
            registry_key_obj.values = RegistryValues()
            value = RegistryValue()
            value.data = rhs.value
            registry_key_obj.values.value = [value]
            convert_operator(op, registry_key_obj.values.value[0].data, id20)
        else:
            warn("number indicies in %s not handled, yet", 601, id20)
    else:
        warn("%s is not a legal property in the pattern of %s", 303, prop_name, id20)


def add_scalar_registry_key_property_pattern(registry_key_obj, properties, rhs, op, id20):
    prop_name = properties[0].property_name
    if prop_name == "key":
        registry_key_obj.key = rhs.value
        convert_operator(op, registry_key_obj.key, id20)
    elif prop_name == "modified":
        registry_key_obj.modified_time = rhs.value
        convert_operator(op, registry_key_obj.modified_time, id20)
    elif prop_name == "creator_user_ref":
        prop_name1 = properties[1].property_name
        if prop_name1 == 'account_login':
            registry_key_obj.creator_username = rhs.value
            convert_operator(op, registry_key_obj.creator_username, id20)
        else:
            warn("%s not representable in a STIX 1.x %s.  Found in the pattern of %s", 504, "WinRegistryKey", prop_name1, id20)
    elif prop_name == "number_of_subkeys":
        registry_key_obj.number_subkeys = rhs.value
        convert_operator(op, registry_key_obj.number_subkeys, id20)
    else:
        warn("%s is not a legal property in the pattern of %s", 303, prop_name, id20)


def convert_registry_key_pattern(exp20, obj1x, id20):
    if isinstance(exp20.lhs.property_path[0], stix2.ListObjectPathComponent):
        add_list_registry_key_property_pattern(obj1x, exp20.lhs.property_path, exp20.rhs, exp20.operator, id20)
    else:
        add_scalar_registry_key_property_pattern(obj1x, exp20.lhs.property_path, exp20.rhs, exp20.operator, id20)


# _X509_CERTIFICATE_MAP = {
#     # "is_self_signed": ,
#     # "hashes": ,
#     "version": X509Cert.version,  #
#     "serial_number": X509Cert.serial_number, #
#     "signature_algorithm": X509Cert.signature_algorithm, #
#     "issuer": X509Cert.issuer, #
#     "validity_not_before": lambda obj, rhs_value: convert_subfield(obj, rhs_value, "validity", Validity, Validity.not_before),
#     "validity_not_after": lambda obj, rhs_value: convert_subfield(obj, rhs_value, "validity", Validity, Validity.not_after),
#     "subject": X509Cert.subject
# }
#
#
# _X509_V3_EXTENSIONS_TYPE_MAP = {
#     "basic_constraints": X509V3Extensions.basic_constraints,
#     "name_constraints": X509V3Extensions.name_constraints,
#     "policy_constraints": X509V3Extensions.policy_constraints
# }
#

def convert_x509_certificate_pattern(exp20, obj1x, id20):
    prop_name = exp20.lhs.property_path[0].property_name
    rhs = exp20.rhs
    op = exp20.operator
    if not obj1x.certificate:
        obj1x.certificate = X509Cert()
    if not convert_pattern(obj1x.certificate,
                           prop_name,
                           rhs,
                           op,
                           X509_CERTIFICATE_MAP,
                           id20):
        if (prop_name == "subject_public_key_algorithm" or
                prop_name == "subject_public_key_modulus" or
                prop_name == "subject_public_key_exponent"):
            if not obj1x.certificate.subject_public_key:
                obj1x.certificate.subject_public_key = SubjectPublicKey
            if prop_name == "subject_public_key_algorithm":
                obj1x.certificate.subject_public_key.public_key_algorithm = rhs.value
                convert_operator(op, obj1x.certificate.subject_public_key.public_key_algorithm, id20)
            else:
                if not obj1x.certificate.subject_public_key.rsa_public_key:
                    obj1x.certificate.subject_public_key.rsa_public_key = RSAPublicKey()
                if prop_name == "subject_public_key_modulus":
                    obj1x.certificate.subject_public_key.rsa_public_key.modulus = rhs.value
                    convert_operator(op, obj1x.certificate.subject_public_key.public_key_algorithm.modulus, id20)
                elif prop_name == "subject_public_key_exponent":
                    obj1x.certificate.subject_public_key.rsa_public_key.exponent = rhs.value
                    convert_operator(op, obj1x.certificate.subject_public_key.public_key_algorithm.modulus, id20)
        elif prop_name == "x509_v3_extensions":
            prop_name1 = exp20.lhs.property_path[1].property_name
            if not obj1x.certificate.standard_extensions:
                obj1x.certificate.standard_extensions = X509V3Extensions()
            if not convert_pattern(obj1x.certificate.standard_extensions,
                                   prop_name1,
                                   rhs,
                                   op,
                                   X509_V3_EXTENSIONS_TYPE_MAP,
                                   id20):
                warn("%s is not a legal property in the pattern of %s", 303, prop_name1, id20)
        else:
            warn("%s is not a legal property in the pattern of %s", 303, prop_name, id20)
