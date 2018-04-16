import uuid

import stixmarx
from cybox.core import Observable
from six import text_type
from stix2slider.convert_cyber_observables import convert_cyber_observables
from stix2slider.options import debug, error, get_option_value, warn
from stix2slider.pattern_grammar import create_pattern_object
from stix2slider.vocab_mappings import (ATTACK_MOTIVATION_MAP, COA_LABEL_MAP,
                                        INDICATOR_LABEL_MAP,
                                        MALWARE_LABELS_MAP, REPORT_LABELS_MAP,
                                        SECTORS_MAP, THREAT_ACTOR_LABEL_MAP,
                                        THREAT_ACTOR_SOPHISTICATION_MAP)
from stix.campaign import Campaign, Names
from stix.coa import CourseOfAction
from stix.common.datetimewithprecision import DateTimeWithPrecision
from stix.common.identity import Identity
from stix.common.information_source import InformationSource
from stix.common.kill_chains import (KillChain, KillChainPhase,
                                     KillChainPhaseReference,
                                     KillChainPhasesReference)
from stix.common.references import References
from stix.common.statement import Statement
from stix.common.vocabs import VocabString
from stix.core import STIXHeader
from stix.data_marking import Marking, MarkingSpecification, MarkingStructure
from stix.exploit_target import ExploitTarget
from stix.exploit_target.vulnerability import Vulnerability
from stix.extensions.identity.ciq_identity_3_0 import (CIQIdentity3_0Instance,
                                                       OrganisationInfo,
                                                       PartyName,
                                                       STIXCIQIdentity3_0)
from stix.extensions.marking.ais import (AISConsentType, AISMarkingStructure,
                                         IsProprietary, NotProprietary,
                                         TLPMarkingType)
from stix.extensions.marking.terms_of_use_marking import \
    TermsOfUseMarkingStructure
from stix.extensions.marking.tlp import TLPMarkingStructure
from stix.indicator import Indicator, ValidTime
from stix.indicator.sightings import (RelatedObservable, RelatedObservables,
                                      Sighting, Sightings)
from stix.report import Report
from stix.report.header import Header
from stix.threat_actor import ThreatActor
from stix.ttp import TTP, Behavior, Resource
from stix.ttp.attack_pattern import AttackPattern
from stix.ttp.malware_instance import MalwareInstance
from stix.ttp.resource import ToolInformation, Tools
from stix.ttp.victim_targeting import VictimTargeting

CONTAINER = None

_ID_NAMESPACE = "example"

_STIX_1_VERSION = "1.2"

_TYPE_MAP_FROM_2_0_TO_1_x = {"attack-pattern": "ttp",
                             "observed-data": "observable",
                             "bundle": "STIXPackage",
                             "malware": "ttp",
                             "marking-definition": "markingstructure",
                             "toolinformation": "tool",
                             "vulnerability": "et"}


def handle_identity(identity_ref_20, target_obj_idref_1x):
    identity1x_tuple = _IDENTITIES[identity_ref_20]
    if identity1x_tuple[1]:
        return target_obj_idref_1x, identity1x_tuple
    else:
        return identity1x_tuple[0], identity1x_tuple


def set_ta_identity(source, target_ref, target_obj_idref_1x):
    target, identity1x_tuple = handle_identity(target_ref, target_obj_idref_1x)
    if source.identity:
        warn("Threat Actor in STIX 2.0 has multiple attributed-to relationships, only one is allowed in STIX 1.x. Using first in list - %s omitted",
             401,
             target_ref)
        # Remove marking to CIQ identity if any.
        # If not removed, stixmarx will cause an exception upon serialization
        for mark_spec in CONTAINER.get_markings(target):
            CONTAINER.remove_marking(target, mark_spec, True)
    else:
        source.identity = target
        identity1x_tuple[1] = True


_VICTIM_TARGET_TTPS = []


def create_victim_target(source, target_ref, target_obj_ref_1x):
    global _VICTIM_TARGET_TTPS
    target, identity1x_tuple = handle_identity(target_ref, target_obj_ref_1x)
    ttp = TTP()
    ttp.victim_targeting = VictimTargeting()
    ttp.victim_targeting.identity = target
    _VICTIM_TARGET_TTPS.append(ttp)
    source.observed_ttps.append(ttp)
    identity1x_tuple[1] = True


# most of the TODOs in this map represent relationships not explicitly called out in STIX 1.x


_RELATIONSHIP_MAP = {
    # TODO: self-reference?
    # ("attack_pattern", "malware", "uses"):
    #     {"method": lambda source, target_ref: source.related_ttps.append(target_ref),
    #      "reverse": False,
    #      "stix1x_source_type": TTP,
    #      "stix1x_target_type": TTP},
    ("campaign", "threat-actor", "attributed-to"):
        {"method": lambda source, target_ref: source.associated_campaigns.append(target_ref),
         "reverse": True,
         "stix1x_source_type": Campaign,
         "stix1x_target_type": ThreatActor},
    # TODO: campaign targets identity
    # TODO: campaign targets vulnerability
    ("campaign", "attack_pattern", "uses"):
        {"method": Campaign.related_ttps,
         "reverse": False,
         "stix1x_source_type": Campaign,
         "stix1x_target_type": TTP},
    ("campaign", "malware", "uses"):
        {"method": Campaign.related_ttps,
         "reverse": False,
         "stix1x_source_type": Campaign,
         "stix1x_target_type": TTP},
    ("campaign", "tool", "indicates"):
        {"method": Campaign.related_indicators,
         "reverse": False,
         "stix1x_source_type": Campaign,
         "stix1x_target_type": TTP},
    ("campaign", "indicator", "uses"):
        {"method": Campaign.related_ttps,
         "reverse": True,
         "stix1x_source_type": Campaign,
         "stix1x_target_type": Indicator},
    # TODO: course-of-action mitigates attack-pattern
    # TODO: course-of-action mitigates malware
    # TODO: course-of-action mitigates tools
    ("course-of-action", "vulnerability", "mitigates"):
        {"method": lambda source, target_ref: source.potential_coas.append(target_ref),
         "reverse": True,
         "stix1x_source_type": CourseOfAction,
         "stix1x_target_type": ExploitTarget},
    # TODO: identity relationships?
    ("indicator", "attack_pattern", "indicates"):
        {"method": Indicator.add_indicated_ttp,
         "reverse": False,
         "stix1x_source_type": Indicator,
         "stix1x_target_type": TTP},
    ("indicator", "campaign", "indicates"):
        {"method": Indicator.add_related_campaign,
         "reverse": False,
         "stix1x_source_type": Indicator,
         "stix1x_target_type": Campaign},
    # ("indicator", "CourseOfAction"): Indicator.suggested_coas,
    ("indicator", "malware", "indicates"):
        {"method": Indicator.add_indicated_ttp,
         "reverse": False,
         "stix1x_source_type": Indicator,
         "stix1x_target_type": TTP},
    # TODO: indicator indicates threat-actor
    # TODO: indicator indicates tool
    ("malware", "vulnerability", "targets"):
        {"method": TTP.add_exploit_target,
         "reverse": False,
         "stix1x_source_type": TTP,
         "stix1x_target_type": ExploitTarget},
    ("malware", "tool", "user"):
        {"method": TTP.add_related_ttp,
         "reverse": False,
         "stix1x_source_type": TTP,
         "stix1x_target_type": TTP},
    ("malware", "malware", "variant-of"):
        {"method": TTP.add_related_ttp,
         "reverse": False,
         "stix1x_source_type": TTP,
         "stix1x_target_type": TTP},
    ("threat-actor", "attack-pattern", "uses"):
        {"method": lambda source, target_ref: source.observed_ttps.append(target_ref),
         "reverse": False,
         "stix1x_source_type": ThreatActor,
         "stix1x_target_type": TTP},
    ("threat-actor", "identity", "attributed-to"):
        {"method": set_ta_identity,
         "reverse": False,
         "stix1x_source_type": ThreatActor,
         "stix1x_target_type": Identity},
    # TODO: threat-actor impersonates identity
    ("threat-actor", "identity", "targets"):
        {"method": create_victim_target,
         "reverse": False,
         "stix1x_source_type": ThreatActor,
         "stix1x_target_type": Identity},
    # TODO: threat-actor targets vulnerability
    ("threat-actor", "malware", "uses"):
        {"method": lambda source, target_ref: source.observed_ttps.append(target_ref),
         "reverse": False,
         "stix1x_source_type": ThreatActor,
         "stix1x_target_type": TTP},
    ("threat-actor", "tool", "uses"):
        {"method": lambda source, target_ref: source.observed_ttps.append(target_ref),
         "reverse": False,
         "stix1x_source_type": ThreatActor,
         "stix1x_target_type": TTP},
}


def get_relationship_adder(type_of_source, type_of_target, type_of_relationship):
    type_tuple = (type_of_source, type_of_target, type_of_relationship)
    if type_tuple in _RELATIONSHIP_MAP:
        return _RELATIONSHIP_MAP[type_tuple]
    else:
        return None


_IDENTITIES = {}


def record_identity(o20, o1x):
    _IDENTITIES[o20["id"]] = [o1x, False]
    _ID_OBJECT_MAPPING[o20["id"]] = o1x


def create_id1x(type_name_1x):
    return "%s:%s-%s" % (_ID_NAMESPACE, type_name_1x, uuid.uuid4())


def convert_id20(id20):
    id_parts = id20.split("--")
    if id_parts[0] in _TYPE_MAP_FROM_2_0_TO_1_x:
        type_name = _TYPE_MAP_FROM_2_0_TO_1_x[id_parts[0]]
    else:
        type_name = id_parts[0]
    return "%s:%s-%s" % (_ID_NAMESPACE, type_name, id_parts[1])


_ID_OBJECT_MAPPING = {}


def record_id_object_mapping(id20, object1x):
    if id20 in _ID_OBJECT_MAPPING:
        print("{} already mapped to an object".format(id20))
    _ID_OBJECT_MAPPING[id20] = object1x


def map_vocabs_to_label(t, vocab_map):
    if vocab_map.get(t, ""):
        return vocab_map[t]
    else:
        return VocabString(t)


def convert_open_vocabs_to_controlled_vocabs(old_vocabs, vocab_mapping, only_one=False, required=True):
    results = []
    if isinstance(old_vocabs, list):
        for t in old_vocabs:
            results.append(map_vocabs_to_label(t, vocab_mapping))
    else:
        results.append(map_vocabs_to_label(old_vocabs, vocab_mapping))
    return results


def convert_to_valid_time(start_time, end_time):
    return ValidTime(DateTimeWithPrecision(start_time),
                     DateTimeWithPrecision(end_time) if end_time else None)


def extract_external_id(external_id, ex_refs):
    for ref in ex_refs:
        if ref["source_name"] == external_id:
            return ref["external_id"]
    return None


def get_type_from_id(id_):
    parts = id_.split("--")
    return parts[0]


def add_missing_property_to_description(obj1x, property_name, property_value):
    if not get_option_value("no_squirrel_gaps"):
        obj1x.add_description(property_name + ": " + text_type(property_value))


def add_missing_list_property_to_description(obj1x, property_name, property_values):
    if not get_option_value("no_squirrel_gaps"):
        obj1x.add_description(property_name + ": " + ", ".join(property_values))


_KILL_CHAINS = {}


def process_kill_chain_phases(phases, obj1x):
    for phase in phases:
        if phase["kill_chain_name"] in _KILL_CHAINS:
            kill_chain_phases = _KILL_CHAINS[phase["kill_chain_name"]]["phases"]
            if not phase["phase_name"] in kill_chain_phases:
                kill_chain_phases.update({phase["phase_name"]: KillChainPhase(
                    phase_id=create_id1x("TTP"),
                    name=phase["phase_name"],
                    ordinality=None)})
                _KILL_CHAINS[phase["kill_chain_name"]]["kill_chain"].add_kill_chain_phase(kill_chain_phases[phase["phase_name"]])
            kcp = kill_chain_phases[phase["phase_name"]]
            if not obj1x.kill_chain_phases:
                obj1x.kill_chain_phases = KillChainPhasesReference()
        else:
            kc = KillChain(id_=create_id1x("TTP"), name=phase["kill_chain_name"])
            _KILL_CHAINS[phase["kill_chain_name"]] = {"kill_chain": kc}
            kcp = KillChainPhase(name=phase["phase_name"], phase_id=create_id1x("TTP"))
            kc.add_kill_chain_phase(kcp)
            _KILL_CHAINS[phase["kill_chain_name"]]["phases"] = {phase["phase_name"]: kcp}
        obj1x.add_kill_chain_phase(KillChainPhaseReference(phase_id=kcp.phase_id,
                                                           name=kcp.name,
                                                           ordinality=None,
                                                           kill_chain_id=_KILL_CHAINS[phase["kill_chain_name"]][
                                                               "kill_chain"].id_,
                                                           kill_chain_name=_KILL_CHAINS[phase["kill_chain_name"]][
                                                               "kill_chain"].name))


def convert_attack_pattern(ap20):
    ap1x = AttackPattern()
    if "name" in ap20:
        ap1x.title = ap20["name"]
    if "description" in ap20:
        ap1x.add_description(ap20["description"])
    if "labels" in ap20:
        for l in ap20["labels"]:
            add_missing_property_to_description(ap1x, "label", l)
    if "external_references" in ap20:
        ap1x.capec_id = extract_external_id("capec", ap20["external_references"])
    ttp = TTP(id_=convert_id20(ap20["id"]),
              timestamp=text_type(ap20["modified"]))
    ttp.behavior = Behavior()
    ttp.behavior.add_attack_pattern(ap1x)
    if "kill_chain_phases" in ap20:
        process_kill_chain_phases(ap20["kill_chain_phases"], ttp)
    if "object_marking_refs" in ap20:
        for m_id in ap20["object_marking_refs"]:
            ms = create_marking_specification(m_id)
            if ms:
                CONTAINER.add_marking(ttp, ms, descendants=True)
    if "granular_markings" in ap20:
        error("Granular Markings present in '%s' are not supported by stix2slider", 604, ap20["id"])
    # if "kill_chain_phases" in ap20:
    #     process_kill_chain_phases(ap20["kill_chain_phases"], ttp)
    record_id_object_mapping(ap20["id"], ttp)
    return ttp


def convert_campaign(c20):
    c1x = Campaign(id_=convert_id20(c20["id"]),
                   timestamp=text_type(c20["modified"]))
    if "name" in c20:
        c1x.title = c20["name"]
    if "description" in c20:
        c1x.add_description(c20["description"])
    names = Names()
    if "aliases" in c20:
        for a in c20["aliases"]:
            names.name.append(VocabString(a))
    if names:
        c1x.names = names
    if "first_seen" in c20:
        add_missing_property_to_description(c1x, "first_seen", text_type(c20["first_seen"]))
    if "last_seen" in c20:
        add_missing_property_to_description(c1x, "last_seen", text_type(c20["last_seen"]))
    if "objective" in c20:
        c1x.intended_effects = [Statement(description=c20["objective"])]
    if "object_marking_refs" in c20:
        for m_id in c20["object_marking_refs"]:
            ms = create_marking_specification(m_id)
            if ms:
                CONTAINER.add_marking(c1x, ms, descendants=True)
    if "granular_markings" in c20:
        error("Granular Markings present in '%s' are not supported by stix2slider", 604, c20["id"])
    record_id_object_mapping(c20["id"], c1x)
    return c1x


def convert_coa(coa20):
    coa1x = CourseOfAction(id_=convert_id20(coa20["id"]),
                           timestamp=text_type(coa20["modified"]))
    if "name" in coa20:
        coa1x.title = coa20["name"]
    if "description" in coa20:
        coa1x.add_description(coa20["description"])
    if "labels" in coa20:
        coa_types = convert_open_vocabs_to_controlled_vocabs(coa20["labels"], COA_LABEL_MAP)
        coa1x.type_ = coa_types[0]
        for l in coa_types[1:]:
            warn("%s in STIX 2.0 has multiple %s, only one is allowed in STIX 1.x. Using first in list - %s omitted",
                 401, "labels", l)
    if "object_marking_refs" in coa20:
        for m_id in coa20["object_marking_refs"]:
            ms = create_marking_specification(m_id)
            if ms:
                CONTAINER.add_marking(coa1x, ms, descendants=True)
    if "granular_markings" in coa20:
        error("Granular Markings present in '%s' are not supported by stix2slider", 604, coa20["id"])
    record_id_object_mapping(coa20["id"], coa1x)
    return coa1x


def add_missing_property_to_free_text_lines(ident1x, property_name, property_value):
    if not get_option_value("no_squirrel_gaps"):
        ident1x.add_free_text_line(property_name + ": " + property_value)


def convert_identity(ident20):
    if ("sectors" in ident20 or
            "contact_information" in ident20 or
            "labels" in ident20 or
            "identity_class" in ident20 or
            "description" in ident20):
        ident1x = CIQIdentity3_0Instance()
        id1x = convert_id20(ident20["id"])
        ident1x.id_ = id1x
        if ident20["identity_class"] != "organization":
            ident1x.name = ident20["name"]
        if "labels" in ident20:
            ident1x.roles = ident20["labels"]
        if ("sectors" in ident20 or
                "contact_information" in ident20 or
                "identity_class" in ident20 or
                "description" in ident20):
            ident1x.specification = STIXCIQIdentity3_0()
            if ident20["identity_class"] == "organization":
                party_name = PartyName()
                party_name.add_organisation_name(text_type(ident20["name"]))
                ident1x.specification.party_name = party_name
            if "sectors" in ident20:
                    first = True
                    for s in ident20["sectors"]:
                        if first:
                            ident1x.specification.organisation_info = \
                                OrganisationInfo(text_type(convert_open_vocabs_to_controlled_vocabs(s, SECTORS_MAP, False)[0]))
                            first = False
                        else:
                            warn("%s in STIX 2.0 has multiple %s, only one is allowed in STIX 1.x. Using first in list - %s omitted",
                                 401,
                                 "Identity", "sectors", s)
            # Identity in 1.x has no description property, use free-text-lines
            if "identity_class" in ident20:
                add_missing_property_to_free_text_lines(ident1x.specification, "identity_class", ident20["identity_class"])
            # Because there is format defined in the specification for this property, it is difficult to
            # determine how to convert the information probably found within it to the CIQ fields, so it will be put
            # in the free_text_lines
            if "contact_information" in ident20:
                add_missing_property_to_free_text_lines(ident1x.specification,
                                                        "contact_information",
                                                        ident20["contact_information"])
            if "description" in ident20:
                add_missing_property_to_free_text_lines(ident1x.specification,
                                                        "description",
                                                        ident20["description"])
    else:
        ident1x = Identity(id_=convert_id20(ident20["id"]),
                           name=ident20["name"])
    if "object_marking_refs" in ident20:
        for m_id in ident20["object_marking_refs"]:
            ms = create_marking_specification(m_id)
            if ms:
                CONTAINER.add_marking(ident1x, ms, descendants=True)
    if "granular_markings" in ident20:
        error("Granular Markings present in '%s' are not supported by stix2slider", 604, ident20["id"])
    return ident1x


def convert_indicator(indicator20):
    indicator1x = Indicator(id_=convert_id20(indicator20["id"]),
                            timestamp=text_type(indicator20["modified"]))
    if "name" in indicator20:
        indicator1x.title = indicator20["name"]
    if "description" in indicator20:
        indicator1x.add_description(indicator20["description"])
    indicator1x.indicator_types = convert_open_vocabs_to_controlled_vocabs(indicator20["labels"], INDICATOR_LABEL_MAP)
    indicator1x.add_valid_time_position(
        convert_to_valid_time(text_type(indicator20["valid_from"]),
                              text_type(indicator20["valid_until"]) if "valid_until" in indicator20 else None))
    indicator1x.add_observable(create_pattern_object(indicator20["pattern"]).toSTIX1x(id20=indicator20["id"]))
    if "kill_chain_phases" in indicator20:
        process_kill_chain_phases(indicator20["kill_chain_phases"], indicator1x)
    if "object_marking_refs" in indicator20:
        for m_id in indicator20["object_marking_refs"]:
            ms = create_marking_specification(m_id)
            if ms:
                CONTAINER.add_marking(indicator1x, ms, descendants=True)
    if "granular_markings" in indicator20:
        error("Granular Markings present in '%s' are not supported by stix2slider", 604, indicator20["id"])
    record_id_object_mapping(indicator20["id"], indicator1x)
    return indicator1x


def convert_malware(malware20):
    malware1x = MalwareInstance()
    if "name" in malware20:
        malware1x.add_name(malware20["name"])
    if "description" in malware20:
        malware1x.add_description(malware20["description"])
    types = convert_open_vocabs_to_controlled_vocabs(malware20["labels"], MALWARE_LABELS_MAP)
    for t in types:
        malware1x.add_type(t)
    ttp = TTP(id_=convert_id20(malware20["id"]),
              timestamp=text_type(malware20["modified"]))
    ttp.behavior = Behavior()
    ttp.behavior.add_malware_instance(malware1x)
    if "kill_chain_phases" in malware20:
        process_kill_chain_phases(malware20["kill_chain_phases"], ttp)
    if "object_marking_refs" in malware20:
        for m_id in malware20["object_marking_refs"]:
            ms = create_marking_specification(m_id)
            if ms:
                CONTAINER.add_marking(ttp, ms, descendants=True)
    if "granular_markings" in malware20:
        error("Granular Markings present in '%s' are not supported by stix2slider", 604, malware20["id"])
    record_id_object_mapping(malware20["id"], ttp)
    return ttp


def convert_observed_data(od20):
    o1x = Observable(id_=convert_id20(od20["id"]))
    if "object_marking_refs" in od20:
        for m_id in od20["object_marking_refs"]:
            ms = create_marking_specification(m_id)
            if ms:
                CONTAINER.add_marking(o1x, ms, descendants=True)
    if "granular_markings" in od20:
        error("Granular Markings present in '%s' are not supported by stix2slider", 604, od20["id"])
    # observable-data has no description
    o1x.object_ = convert_cyber_observables(od20["objects"], od20["id"])
    return o1x


def convert_report(r20):
    r1x = Report(id_=convert_id20(r20["id"]),
                 timestamp=text_type(r20["modified"]))
    r1x.header = Header()
    if "name" in r20:
        r1x.header.title = r20["name"]
    if "description" in r20:
        r1x.header.add_description(r20["description"])
    intents = convert_open_vocabs_to_controlled_vocabs(r20["labels"], REPORT_LABELS_MAP)
    for i in intents:
        r1x.header.add_intent(i)
    if "published" in r20:
        add_missing_property_to_description(r1x.header, "published", r20["published"])
    for ref in r20["object_refs"]:
        ref_type = get_type_from_id(ref)
        if ref_type == "attack-pattern":
            r1x.add_ttp(TTP(idref=ref))
        elif ref_type == "campaign":
            r1x.add_campaign(Campaign(idref=ref))
        elif ref_type == 'course-of-action':
            r1x.add_course_of_action(CourseOfAction(idref=ref))
        elif ref_type == "indicator":
            r1x.add_indicator(Indicator(idref=ref))
        elif ref_type == "observed-data":
            r1x.add_observable(Observable(idref=ref))
        elif ref_type == "malware":
            r1x.add_ttp(TTP(idref=ref))
        elif ref_type == "threat-actor":
            r1x.add_threat_actor(ThreatActor(idref=ref))
        elif ref_type == "vulnerability":
            r1x.add_exploit_target(ExploitTarget(idref=ref))
    if "object_marking_refs" in r20:
        for m_id in r20["object_marking_refs"]:
            ms = create_marking_specification(m_id)
            if ms:
                CONTAINER.add_marking(r1x, ms, descendants=True)
    if "granular_markings" in r20:
        error("Granular Markings present in '%s' are not supported by stix2slider", 604, r20["id"])
    return r1x


def convert_threat_actor(ta20):
    ta1x = ThreatActor(id_=convert_id20(ta20["id"]),
                       timestamp=text_type(ta20["modified"]))
    ta1x.title = ta20["name"]
    types = convert_open_vocabs_to_controlled_vocabs(ta20["labels"], THREAT_ACTOR_LABEL_MAP)
    for t in types:
        ta1x.add_type(t)
    if "description" in ta20:
        ta1x.add_description(ta20["description"])
    if "aliases" in ta20:
        add_missing_list_property_to_description(ta1x, "aliases", ta20["aliases"])
    if "roles" in ta20:
        add_missing_list_property_to_description(ta1x, "roles", ta20["roles"])
    if "goals" in ta20:
        for g in ta20["goals"]:
            ta1x.add_intended_effect(g)
    if "sophistication" in ta20:
        sophistications = convert_open_vocabs_to_controlled_vocabs([ta20["sophistication"]], THREAT_ACTOR_SOPHISTICATION_MAP)
        for s in sophistications:
            ta1x.add_sophistication(s)
    if "resource_level" in ta20:
            add_missing_list_property_to_description(ta1x, "resource_level", ta20["resource_level"])
    all_motivations = []
    if "primary_motivation" in ta20:
        all_motivations = [ta20["primary_motivation"]]
    if "secondary_motivation" in ta20:
        all_motivations.extend(ta20["secondary_motivation"])
    if "personal_motivation" in ta20:
        all_motivations.extend(ta20["personal_motivation"])
    motivations = convert_open_vocabs_to_controlled_vocabs(all_motivations, ATTACK_MOTIVATION_MAP)
    for m in motivations:
        ta1x.add_motivation(m)
    if "object_marking_refs" in ta20:
        for m_id in ta20["object_marking_refs"]:
            ms = create_marking_specification(m_id)
            if ms:
                CONTAINER.add_marking(ta1x, ms, descendants=True)
    if "granular_markings" in ta20:
        error("Granular Markings present in '%s' are not supported by stix2slider", 604, ta20["id"])
    record_id_object_mapping(ta20["id"], ta1x)
    return ta1x


def convert_tool(tool20):
    tool1x = ToolInformation()
    if "name" in tool20:
        tool1x.title = tool20["name"]
    if "description" in tool20:
        tool1x.description = tool20["description"]
    if "tool_version" in tool20:
        tool1x.version = tool20["tool_version"]
    if "labels" in tool20:
        warn("labels not representable in a STIX 1.x ToolInformation.  Found in %s", 502, tool20["id"])
        # bug in python_stix prevents using next line of code
        # tool1x.type_ = convert_open_vocabs_to_controlled_vocabs(tool20["labels"], TOOL_LABELS_MAP)
    ttp = TTP(id_=convert_id20(tool20["id"]),
              timestamp=text_type(tool20["modified"]))
    ttp.resource = Resource(tools=Tools([tool1x]))
    if "kill_chain_phases" in tool20:
        process_kill_chain_phases(tool20["kill_chain_phases"], ttp)
    if "object_marking_refs" in tool20:
        for m_id in tool20["object_marking_refs"]:
            ms = create_marking_specification(m_id)
            if ms:
                CONTAINER.add_marking(ttp, ms, descendants=True)
    if "granular_markings" in tool20:
        error("Granular Markings present in '%s' are not supported by stix2slider", 604, tool20["id"])
    record_id_object_mapping(tool20["id"], ttp)
    return ttp


def convert_vulnerability(v20):
    v1x = Vulnerability()
    if "name" in v20:
        v1x.title = v20["name"]
    if "description" in v20:
        v1x.add_description(v20["description"])
    if "labels" in v20:
        add_missing_list_property_to_description(v1x, "labels", v20["labels"])
    v1x.cve_id = extract_external_id("cve", v20["external_references"])
    et = ExploitTarget(id_=convert_id20(v20["id"]),
                       timestamp=text_type(v20["modified"]))
    et.add_vulnerability(v1x)
    if "kill_chain_phases" in v20:
        process_kill_chain_phases(v20["kill_chain_phases"], et)
    if "object_marking_refs" in v20:
        for m_id in v20["object_marking_refs"]:
            ms = create_marking_specification(m_id)
            if ms:
                CONTAINER.add_marking(et, ms, descendants=True)
    if "granular_markings" in v20:
        error("Granular Markings present in '%s' are not supported by stix2slider", 604, v20["id"])
    record_id_object_mapping(v20["id"], et)
    return et


def process_relationships(rel):
    target_obj = None
    if rel["source_ref"] in _ID_OBJECT_MAPPING:
        source_obj = _ID_OBJECT_MAPPING[rel["source_ref"]]
    else:
        warn("No source object exists for %s to add the relationship %s", 301, rel["source_ref"], rel["id"])
        return
    if rel["target_ref"] in _ID_OBJECT_MAPPING:
        target_obj = _ID_OBJECT_MAPPING[rel["target_ref"]]
    type_of_source = get_type_from_id(rel["source_ref"])
    type_of_target = get_type_from_id(rel["target_ref"])
    type_of_relationship = rel["relationship_type"]
    add_method_info = get_relationship_adder(type_of_source, type_of_target, type_of_relationship)
    if not add_method_info:
        warn("The '%s' relationship of %s between %s and %s is not supported in STIX 1.x",
             501,
             type_of_relationship, rel["id"], type_of_source, type_of_target)
        return
    if add_method_info["reverse"] and target_obj:
        source_obj_class = add_method_info["stix1x_source_type"]
        source_obj_ref_1x = source_obj_class(idref=source_obj.id_)
        add_method_info["method"](target_obj, source_obj_ref_1x)
    else:
        target_obj_class = add_method_info["stix1x_target_type"]
        if target_obj:
            target_obj_idref_1x = target_obj_class(idref=target_obj.id_)
        else:
            target_obj_idref_1x = target_obj_class(idref=convert_id20(rel["target_ref"]))
        if target_obj_class == Identity:
            add_method_info["method"](source_obj, rel["target_ref"], target_obj_idref_1x)
        else:
            add_method_info["method"](source_obj, target_obj_idref_1x)


_INFORMATION_SOURCES = {}


def id_of_type(ref, type):
    return ref.startswith(type)


def create_references_for_vulnerability(obj):
    if obj["id"] in _ID_OBJECT_MAPPING:
        obj1x = _ID_OBJECT_MAPPING[obj["id"]]
        v = obj1x.vulnerabilities[0]
    for er in obj["external_references"]:
        if er["source_name"] != 'cve' and ("url" in er or "external_id" in er):
            if "url" in er:
                v.add_reference("SOURCE: " + er["source_name"] + " - " + er["url"])
            if "external_id" in er:
                v.add_reference("SOURCE: " + er["source_name"] + " - " + er["external_id"])
        if er["source_name"] == 'cve' and "url" in er:
            v.add_reference("SOURCE: " + er["source_name"] + " - " + er["url"])


def get_info_source(ob1x, obj):
    if ob1x.information_source:
        return ob1x.information_source
    else:
        if obj["id"] in _INFORMATION_SOURCES:
            info_source = _INFORMATION_SOURCES[obj["id"]]
            ob1x.information_source = info_source
        else:
            info_source = InformationSource(references=References())
            _INFORMATION_SOURCES[obj["id"]] = info_source
            ob1x.information_source = info_source
        return info_source


def create_references(obj):
    if id_of_type(obj["id"], "identity"):
        warn("Identity has no property to store external-references from %s", 510, obj["id"])
        return
    elif id_of_type(obj["id"], "vulnerability"):
        create_references_for_vulnerability(obj)
        return
    if obj["id"] in _ID_OBJECT_MAPPING:
        ob1x = _ID_OBJECT_MAPPING[obj["id"]]
    else:
        warn("No object %s is found to add the reference to", 307, obj["id"])
        return
    for er in obj["external_references"]:
        # capec and cve handled elsewhere
        if (er["source_name"] != 'capec' and er["source_name"] != 'cve') and ("url" in er or "external_id" in er):
            info_source = get_info_source(ob1x, obj)
            if "url" in er:
                info_source.add_reference("SOURCE: " + er["source_name"] + " - " + er["url"])
            if "external_id" in er:
                info_source.add_reference("SOURCE: " + er["source_name"] + " - " + "EXTERNAL ID: " + er["external_id"])
            if "hashes" in er:
                warn("hashes not representable in a STIX 1.x %s.  Found in %s", 503, "InformationSource", obj["id"])
            if "description" in er:
                info_source.add_description(er["description"])
        elif (er["source_name"] != 'capec' and er["source_name"] != 'cve'):
            warn("Source name %s in external references of %s not handled, yet", 605, er["source_name"], obj["id"])
        if (er["source_name"] == 'capec' or er["source_name"] == 'cve') and "url" in er:
            info_source = get_info_source(ob1x, obj)
            info_source.add_reference("SOURCE: " + er["source_name"] + " - " + er["url"])


def create_information_source(identity20_tuple):
    identity_obj = identity20_tuple[0]
    used_before = identity20_tuple[1]
    if used_before:
        return InformationSource(identity=Identity(idref=identity_obj.id_))
    else:
        identity20_tuple[1] = True
        return InformationSource(identity=identity_obj)


def process_created_by_ref(o):
    if o["id"] in _ID_OBJECT_MAPPING:
        obj1x = _ID_OBJECT_MAPPING[o["id"]]
        if o["created_by_ref"] in _IDENTITIES:
            identity20_tuple = _IDENTITIES[o["created_by_ref"]]
            obj1x.information_source = create_information_source(identity20_tuple)


def indicator_ref(ref):
    return ref.startswith("indicator")


def process_sighting(o):
    if indicator_ref(o["sighting_of_ref"]):
        indicator_of_sighting = _ID_OBJECT_MAPPING[o["sighting_of_ref"]]
        if not indicator_of_sighting:
            warn("%s is not in this bundle.  Referenced from %s", 308, o["sighting_of_ref"], o["id"])
            return
        if not indicator_of_sighting.sightings:
            indicator_of_sighting.sightings = Sightings()
        if "count" in o:
            indicator_of_sighting.sightings.sightings_count = o["count"]
        if "where_sighted_refs" in o:
            for ref in o["where_sighted_refs"]:
                s = Sighting(timestamp=text_type(o["modified"]))
                indicator_of_sighting.sightings.append(s)
                if ref in _IDENTITIES:
                    identity20_tuple = _IDENTITIES[ref]
                    s.source = create_information_source(identity20_tuple)
                if "observed_data_refs" in o:
                    # reference, regardless of whether its in the bundle or not
                    s.related_observables = RelatedObservables()
                    for od_ref in o["observed_data_refs"]:
                        ro = RelatedObservable()
                        s.related_observables.append(ro)
                        ro.item = Observable(idref=convert_id20(od_ref))

        if "first_seen" in o:
            warn("first_seen not representable in a STIX 1.x Sightings.  Found in %s", 503, o["id"])
        if "last_seen" in o:
            warn("last_seen not representable in a STIX 1.x Sightings.  Found in %s", 503, o["id"])
    else:
        warn("Unable to convert STIX 2.0 sighting %s because it doesn't refer to an indicator", 508, o["sighings_of_ref"])


def convert_marking_definition(marking20):
    definition = marking20["definition"]
    marking_spec = MarkingSpecification()
    if marking20["definition_type"] == "statement":
        tou = TermsOfUseMarkingStructure(terms_of_use=definition["statement"])
        tou.id_ = convert_id20(marking20["id"])
        marking_spec.marking_structures.append(tou)
    elif marking20["definition_type"] == "tlp":
        tlp = TLPMarkingStructure(color=definition["tlp"])
        tlp.id_ = convert_id20(marking20["id"])
        marking_spec.marking_structures.append(tlp)
    elif marking20["definition_type"] == "ais":
        identity20_tuple = _IDENTITIES[marking20["created_by_ref"]]
        color = definition["tlp"].upper()

        if definition["is_proprietary"] == "true":
            proprietary = IsProprietary()
            consent = "EVERYONE"
        else:
            proprietary = NotProprietary()
            consent = definition["consent"].upper()

        proprietary.ais_consent = AISConsentType(consent=consent)
        proprietary.tlp_marking = TLPMarkingType(color=color)
        ais_marking = AISMarkingStructure()
        ais_marking.id_ = convert_id20(marking20["id"])

        if isinstance(proprietary, IsProprietary):
            ais_marking.is_proprietary = proprietary
        else:
            ais_marking.not_proprietary = proprietary

        marking_spec.controlled_structure = "//node() | //@*"
        marking_spec.marking_structures.append(ais_marking)
        marking_spec.information_source = create_information_source(identity20_tuple)

        # Remove marking to CIQ identity. Special case for AIS.
        for mark_spec in CONTAINER.get_markings(identity20_tuple[0]):
            mark_struct = mark_spec.marking_structures[0]
            if mark_struct.idref and mark_struct.idref == ais_marking.id_:
                CONTAINER.remove_marking(identity20_tuple[0], mark_spec, True)

    record_id_object_mapping(marking20["id"], marking_spec.marking_structures[0])
    if "object_marking_refs" in marking20:
        for m_id in marking20["object_marking_refs"]:
            ms = create_marking_specification(m_id)
            if ms:
                CONTAINER.add_marking(marking_spec, ms, descendants=True)
    if "granular_markings" in marking20:
        error("Granular Markings present in '%s' are not supported by stix2slider", 604, marking20["id"])
    return marking_spec


def create_marking_specification(id20):
    if id20 in _ID_OBJECT_MAPPING:
        marking1x = _ID_OBJECT_MAPPING[id20]
        if isinstance(marking1x, AISMarkingStructure):
            return  # This is a special case for AIS.

    marking_spec = MarkingSpecification()
    marking_struct = MarkingStructure()
    marking_struct.idref = convert_id20(id20)
    marking_spec.marking_structures.append(marking_struct)
    return marking_spec


def convert_bundle(bundle_obj):
    global _ID_OBJECT_MAPPING
    global _IDENTITIES
    global _VICTIM_TARGET_TTPS
    global _KILL_CHAINS
    global CONTAINER
    _ID_OBJECT_MAPPING = {}
    _IDENTITIES = {}
    _VICTIM_TARGET_TTPS = []
    _KILL_CHAINS = {}

    CONTAINER = stixmarx.new()
    pkg = CONTAINER.package
    pkg.id_ = convert_id20(bundle_obj["id"])

    for identity in (v for v in bundle_obj["objects"] if v["type"] == "identity"):
        debug("Found '%s'", 0, identity["id"])
        i1x = convert_identity(identity)
        record_identity(identity, i1x)

    for marking_definition in (v for v in bundle_obj["objects"] if v["type"] == "marking-definition"):
        debug("Found '%s'", 0, marking_definition["id"])
        m1x = convert_marking_definition(marking_definition)
        if not pkg.stix_header:
            pkg.stix_header = STIXHeader(handling=Marking())
        pkg.stix_header.handling.add_marking(m1x)

    for o in bundle_obj["objects"]:
        if o["type"] == "attack-pattern":
            pkg.add_ttp(convert_attack_pattern(o))
        elif o["type"] == "campaign":
            pkg.add_campaign(convert_campaign(o))
        elif o["type"] == 'course-of-action':
            pkg.add_course_of_action(convert_coa(o))
        elif o["type"] == "indicator":
            pkg.add_indicator(convert_indicator(o))
        elif o["type"] == "intrusion-set":
            error("Cannot convert STIX 2.0 content that contains intrusion-sets", 524)
            return None
        elif o["type"] == "malware":
            pkg.add_ttp(convert_malware(o))
        elif o["type"] == "observed-data":
            pkg.add_observable(convert_observed_data(o))
        elif o["type"] == "report":
            pkg.add_report(convert_report(o))
        elif o["type"] == "threat-actor":
            pkg.add_threat_actor(convert_threat_actor(o))
        elif o["type"] == "tool":
            pkg.add_ttp(convert_tool(o))
        elif o["type"] == "vulnerability":
            pkg.add_exploit_target(convert_vulnerability(o))
    # second passes
    for o in bundle_obj["objects"]:
        if o["type"] == "relationship":
            process_relationships(o)
    for o in bundle_obj["objects"]:
        if "created_by_ref" in o:
            process_created_by_ref(o)
        if "external_references" in o:
            create_references(o)
    for o in bundle_obj["objects"]:
        if o["type"] == "sighting":
            process_sighting(o)
    for k, v in _KILL_CHAINS.items():
        pkg.ttps.kill_chains.append(v["kill_chain"])
    CONTAINER.flush()
    CONTAINER = None
    return pkg
