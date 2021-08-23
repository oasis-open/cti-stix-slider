# external
from cybox.core import Observable
from stix2.pattern_visitor import create_pattern_object
from stix.campaign import AssociatedCampaigns, Campaign, Names
from stix.coa import CourseOfAction, RelatedCOAs
from stix.common.datetimewithprecision import DateTimeWithPrecision
from stix.common.identity import Identity, RelatedIdentities
from stix.common.information_source import InformationSource
from stix.common.kill_chains import (
    KillChain, KillChainPhase, KillChainPhaseReference,
    KillChainPhasesReference
)
from stix.common.references import References
from stix.common.statement import Statement
from stix.common.vocabs import VocabString
from stix.core import STIXHeader
from stix.core.ttps import TTPs
from stix.data_marking import Marking, MarkingSpecification, MarkingStructure
from stix.exploit_target import ExploitTarget
from stix.exploit_target.vulnerability import Vulnerability
from stix.extensions.identity.ciq_identity_3_0 import (
    Address, CIQIdentity3_0Instance, OrganisationInfo, PartyName,
    STIXCIQIdentity3_0
)
from stix.extensions.marking.ais import (
    AISConsentType, AISMarkingStructure, IsProprietary, NotProprietary,
    TLPMarkingType
)
from stix.extensions.marking.terms_of_use_marking import (
    TermsOfUseMarkingStructure
)
from stix.extensions.marking.tlp import TLPMarkingStructure
from stix.extensions.test_mechanism.snort_test_mechanism import (
    SnortTestMechanism
)
from stix.extensions.test_mechanism.yara_test_mechanism import (
    YaraTestMechanism
)
from stix.indicator import Indicator, RelatedIndicators, ValidTime
from stix.indicator.sightings import (
    RelatedObservable, RelatedObservables, Sighting, Sightings
)
from stix.threat_actor import AssociatedActors, ThreatActor
from stix.ttp import TTP, Behavior, Resource
from stix.ttp.attack_pattern import AttackPattern
from stix.ttp.infrastructure import Infrastructure
from stix.ttp.malware_instance import MalwareInstance
from stix.ttp.resource import ToolInformation, Tools
from stix.ttp.victim_targeting import VictimTargeting
import stixmarx

# internal
from stix2slider import common
from stix2slider.common import convert_id2x, create_id1x
from stix2slider.convert_cyber_observables import (
    add_object_refs, add_refs, convert_cyber_observables, convert_sco
)
from stix2slider.options import (
    debug, error, get_option_value, set_option_value, warn
)
from stix2slider.utils import set_default_namespace
from stix2slider.vocab_mappings import (
    ATTACK_MOTIVATION_MAP, COA_LABEL_MAP, INDICATOR_LABEL_MAP,
    INFRASTRUCTURE_LABELS_MAP, MALWARE_LABELS_MAP, REPORT_LABELS_MAP,
    SECTORS_MAP, THREAT_ACTOR_LABEL_MAP, THREAT_ACTOR_SOPHISTICATION_MAP
)

try:  # isort:skip
    from stix.report import Report  # isort:skip
    from stix.report.header import Header  # isort:skip
    _STIX_1_VERSION = "1.2"  # isort:skip
except ImportError:  # isort:skip
    _STIX_1_VERSION = "1.1.1"  # isort:skip


def choose_full_object_or_idref(identity_ref_2x, target_obj_idref_1x):
    identity1x_tuple = _EXPLICIT_OBJECT_USED[identity_ref_2x]
    if identity1x_tuple[1]:
        return target_obj_idref_1x, identity1x_tuple
    else:
        return identity1x_tuple[0], identity1x_tuple


def set_ta_identity(source, target_ref, target_obj_idref_1x):
    target, identity1x_tuple = choose_full_object_or_idref(target_ref, target_obj_idref_1x)
    if source.identity:
        warn("Threat Actor in STIX 2.x has multiple attributed-to relationships, only one is allowed in STIX 1.x. Using first in list - %s omitted",
             401,
             target_ref)
        # Remove marking to CIQ identity if any.
        # If not removed, stixmarx will cause an exception upon serialization
        for mark_spec in CONTAINER.get_markings(target):
            CONTAINER.remove_marking(target, mark_spec, True)
    else:
        source.identity = target
        identity1x_tuple[1] = True


def set_related_identity(source, target_ref, target_obj_idref_1x):
    target, identity1x_tuple = choose_full_object_or_idref(target_ref, target_obj_idref_1x)
    if not source.related_identities:
        source.related_identities = RelatedIdentities()
    source.related_identities.append(target)
    identity1x_tuple[1] = True


def set_associated_actors(source, target_ref, target_obj_idref_1x):
    target, ta1x_tuple = choose_full_object_or_idref(target_ref, target_obj_idref_1x)
    if not source.associated_actors:
        source.associated_actors = AssociatedActors()
    source.associated_actors.append(target)
    ta1x_tuple[1] = True


def set_associated_campaigns(source, target_ref, target_obj_idref_1x):
    target, ta1x_tuple = choose_full_object_or_idref(target_ref, target_obj_idref_1x)
    if not source.associated_campaigns:
        source.associated_campaigns = AssociatedCampaigns()
    source.associated_actors.append(target)
    ta1x_tuple[1] = True


def set_related_coas(source, target_ref, target_obj_idref_1x):
    target, ta1x_tuple = choose_full_object_or_idref(target_ref, target_obj_idref_1x)
    if not source.related_coas:
        source.related_coas = RelatedCOAs()
    source.related_coas.append(target)
    ta1x_tuple[1] = True


def set_related_indicators(source, target_ref, target_obj_idref_1x):
    target, ta1x_tuple = choose_full_object_or_idref(target_ref, target_obj_idref_1x)
    if not source.related_indicators:
        source.related_indicators = RelatedIndicators()
    source.related_indicators.append(target)
    ta1x_tuple[1] = True


def set_related_campaign_ref_for_indicator(source, target_obj_idref_1x):
    # campaign refs are weird
    source.add_related_campaign(Campaign(id_=target_obj_idref_1x.idref))


# TODO: use _VICTIM_TARGET_TTPS
_VICTIM_TARGET_TTPS = []


def create_victim_target_for_threat_actor(source, target_ref, target_obj_ref_1x):
    global _VICTIM_TARGET_TTPS
    target, identity1x_tuple = choose_full_object_or_idref(target_ref, target_obj_ref_1x)
    ttp = TTP()
    ttp.victim_targeting = VictimTargeting()
    ttp.victim_targeting.identity = target
    _VICTIM_TARGET_TTPS.append(ttp)
    source.observed_ttps.append(ttp)
    identity1x_tuple[1] = True


def create_victim_target_for_attack_pattern(ttp, target_ref, target_obj_ref_1x):
    global _VICTIM_TARGET_TTPS
    target, identity1x_tuple = choose_full_object_or_idref(target_ref, target_obj_ref_1x)
    ttp.victim_targeting = VictimTargeting()
    ttp.victim_targeting.identity = target
    _VICTIM_TARGET_TTPS.append(ttp)
    identity1x_tuple[1] = True


def create_exploit_target_to_ttps(ttp, target_ref, target_obj_ref_1x):
    target, vul1x_tuple = choose_full_object_or_idref(target_ref, target_obj_ref_1x)
    ttp.add_exploit_target(target)
    vul1x_tuple[1] = True


# most of the TODOs in this map represent relationships not explicitly called out in STIX 1.x

_RELATIONSHIP_MAP = {
    # TODO: self-reference?
    ("attack-pattern", "malware", "uses"):
        {"method": lambda source, target_ref: source.related_ttps.append(target_ref),
         "reverse": False,
         "stix1x_source_type": TTP,
         "stix1x_target_type": TTP},
    ("attack-pattern", "identity", "targets"):
        {"method": create_victim_target_for_attack_pattern,
         "reverse": False,
         "stix1x_source_type": TTP,
         "stix1x_target_type": Identity},
    ("attack-pattern", "tool", "uses"):
        {"method": lambda source, target_ref: source.related_ttps.append(target_ref),
         "reverse": False,
         "stix1x_source_type": TTP,
         "stix1x_target_type": TTP},
    ("attack-pattern", "vulnerability", "targets"):
        {"method": create_exploit_target_to_ttps,
         "reverse": False,
         "stix1x_source_type": TTP,
         "stix1x_target_type": ExploitTarget},
    ("campaign", "threat-actor", "attributed-to"):
        {"method": lambda source, target_ref: source.associated_campaigns.append(target_ref),
         "reverse": True,
         "stix1x_source_type": Campaign,
         "stix1x_target_type": ThreatActor},
    # TODO: campaign targets identity
    # TODO: campaign targets vulnerability
    ("campaign", "attack-pattern", "uses"):
        {"method": lambda source, target_ref: source.related_ttps.append(target_ref),
         "reverse": False,
         "stix1x_source_type": Campaign,
         "stix1x_target_type": TTP},
    ("campaign", "infrastructure", "compromises"):
        {"method": lambda source, target_ref: source.related_ttps.append(target_ref),
         "reverse": False,
         "stix1x_source_type": Campaign,
         "stix1x_target_type": TTP},
    ("campaign", "malware", "uses"):
        {"method": lambda source, target_ref: source.related_ttps.append(target_ref),
         "reverse": False,
         "stix1x_source_type": Campaign,
         "stix1x_target_type": TTP},
    ("campaign", "tool", "uses"):
        {"method": lambda source, target_ref: source.related_ttps.append(target_ref),
         "reverse": False,
         "stix1x_source_type": Campaign,
         "stix1x_target_type": TTP},
    ("campaign", "infrastructure", "uses"):
        {"method": lambda source, target_ref: source.related_ttps.append(target_ref),
         "reverse": False,
         "stix1x_source_type": Campaign,
         "stix1x_target_type": TTP},
    ("campaign", "indicator", "indicates"):
        {"method": lambda source, target_ref: source.related_indicators.append(target_ref),
         "reverse": True,
         "stix1x_source_type": Campaign,
         "stix1x_target_type": Indicator},
    ("campaign", "campaign", "related-to"):
        {"method": set_associated_campaigns,
         "reverse": False,
         "stix1x_source_type": Campaign,
         "stix1x_target_type": Campaign},
    # TODO: course-of-action mitigates attack-pattern
    # TODO: course-of-action mitigates malware
    # TODO: course-of-action mitigates tools
    ("course-of-action", "vulnerability", "mitigates"):
        {"method": lambda source, target_ref: source.potential_coas.append(target_ref),
         "reverse": True,
         "stix1x_source_type": CourseOfAction,
         "stix1x_target_type": ExploitTarget},
    ("course-of-action", "course-of-action", "related-to"):
        {"method": set_related_coas,
         "reverse": False,
         "stix1x_source_type": CourseOfAction,
         "stix1x_target_type": CourseOfAction},
    # TODO: identity relationships?
    ("identity", "identity", "related-to"):
        {"method": set_related_identity,
         "reverse": False,
         "stix1x_source_type": Identity,
         "stix1x_target_type": Identity},
    ("indicator", "attack_pattern", "indicates"):
        {"method": Indicator.add_indicated_ttp,
         "reverse": False,
         "stix1x_source_type": Indicator,
         "stix1x_target_type": TTP},
    ("indicator", "campaign", "indicates"):
        {"method": set_related_campaign_ref_for_indicator,
         "reverse": False,
         "stix1x_source_type": Indicator,
         "stix1x_target_type": Campaign},
    # ("indicator", "CourseOfAction"): Indicator.suggested_coas,
    ("indicator", "infrastructure", "indicates"):
        {"method": Indicator.add_indicated_ttp,
         "reverse": False,
         "stix1x_source_type": Indicator,
         "stix1x_target_type": TTP},
    ("indicator", "malware", "indicates"):
        {"method": Indicator.add_indicated_ttp,
         "reverse": False,
         "stix1x_source_type": Indicator,
         "stix1x_target_type": TTP},
    ("indicator", "tool", "indicates"):
        {"method": Indicator.add_indicated_ttp,
         "reverse": False,
         "stix1x_source_type": Indicator,
         "stix1x_target_type": TTP},
    # TODO: indicator indicates threat-actor (not in 1x)
    ("indicator", "indicator", "related-to"):
        {"method": set_related_indicators,
         "reverse": False,
         "stix1x_source_type": Indicator,
         "stix1x_target_type": Indicator},
    ("infrastructure", "infrastructure", "communicates-with"):
        {"method": TTP.add_related_ttp,
         "reverse": False,
         "stix1x_source_type": TTP,
         "stix1x_target_type": TTP},
    ("infrastructure", "infrastructure", "consists-of"):
        {"method": TTP.add_related_ttp,
         "reverse": False,
         "stix1x_source_type": TTP,
         "stix1x_target_type": TTP},
    ("infrastructure", "infrastructure", "controls"):
        {"method": TTP.add_related_ttp,
         "reverse": False,
         "stix1x_source_type": TTP,
         "stix1x_target_type": TTP},
    ("infrastructure", "malware", "controls"):
        {"method": TTP.add_related_ttp,
         "reverse": False,
         "stix1x_source_type": TTP,
         "stix1x_target_type": TTP},
    ("infrastructure", "malware", "delivers"):
        {"method": TTP.add_related_ttp,
         "reverse": False,
         "stix1x_source_type": TTP,
         "stix1x_target_type": TTP},
    ("infrastructure", "malware", "hosts"):
        {"method": TTP.add_related_ttp,
         "reverse": False,
         "stix1x_source_type": TTP,
         "stix1x_target_type": TTP},
    ("infrastructure", "tool", "hosts"):
        {"method": TTP.add_related_ttp,
         "reverse": False,
         "stix1x_source_type": TTP,
         "stix1x_target_type": TTP},
    ("infrastructure", "infrastructure", "uses"):
        {"method": TTP.add_related_ttp,
         "reverse": False,
         "stix1x_source_type": TTP,
         "stix1x_target_type": TTP},
    ("malware", "vulnerability", "targets"):
        {"method": create_exploit_target_to_ttps,
         "reverse": False,
         "stix1x_source_type": TTP,
         "stix1x_target_type": ExploitTarget},
    ("malware", "infrastructure", "uses"):
        {"method": TTP.add_related_ttp,
         "reverse": False,
         "stix1x_source_type": TTP,
         "stix1x_target_type": TTP},
    ("malware", "tool", "downloads"):
        {"method": TTP.add_related_ttp,
         "reverse": False,
         "stix1x_source_type": TTP,
         "stix1x_target_type": TTP},
    ("malware", "tool", "drops"):
        {"method": TTP.add_related_ttp,
         "reverse": False,
         "stix1x_source_type": TTP,
         "stix1x_target_type": TTP},
    ("malware", "tool", "uses"):
        {"method": TTP.add_related_ttp,
         "reverse": False,
         "stix1x_source_type": TTP,
         "stix1x_target_type": TTP},
    ("malware", "infrastructure", "beacons-to"):
        {"method": TTP.add_related_ttp,
         "reverse": False,
         "stix1x_source_type": TTP,
         "stix1x_target_type": TTP},
    ("malware", "infrastructure", "exfiltrates-to"):
        {"method": TTP.add_related_ttp,
         "reverse": False,
         "stix1x_source_type": TTP,
         "stix1x_target_type": TTP},
    ("malware", "infrastructure", "targets"):
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
    # TODO: threat-actor impersonates identity (not in 1.x)
    ("threat-actor", "identity", "targets"):
        {"method": create_victim_target_for_threat_actor,
         "reverse": False,
         "stix1x_source_type": ThreatActor,
         "stix1x_target_type": Identity},
    ("threat-actor", "infrastructure", "compromises"):
        {"method": lambda source, target_ref: source.related_ttps.append(target_ref),
         "reverse": False,
         "stix1x_source_type": ThreatActor,
         "stix1x_target_type": TTP},
    ("threat-actor", "infrastructure", "hosts"):
        {"method": lambda source, target_ref: source.related_ttps.append(target_ref),
         "reverse": False,
         "stix1x_source_type": ThreatActor,
         "stix1x_target_type": TTP},
    ("threat-actor", "infrastructure", "owns"):
        {"method": lambda source, target_ref: source.related_ttps.append(target_ref),
         "reverse": False,
         "stix1x_source_type": ThreatActor,
         "stix1x_target_type": TTP},
    # TODO: threat-actor targets vulnerability (not in 1.x)
    ("threat-actor", "infrastructure", "uses"):
        {"method": lambda source, target_ref: source.observed_ttps.append(target_ref),
         "reverse": False,
         "stix1x_source_type": ThreatActor,
         "stix1x_target_type": TTP},
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
    ("threat-actor", "threat-actor", "related-to"):
        {"method": set_associated_actors,
         "reverse": False,
         "stix1x_source_type": ThreatActor,
         "stix1x_target_type": ThreatActor},
    ("tool", "malware", "delivers"):
        {"method": TTP.add_related_ttp,
         "reverse": False,
         "stix1x_source_type": TTP,
         "stix1x_target_type": TTP},
    ("tool", "malware", "drops"):
        {"method": TTP.add_related_ttp,
         "reverse": False,
         "stix1x_source_type": TTP,
         "stix1x_target_type": TTP},
    ("tool", "infrastructure", "targets"):
        {"method": TTP.add_related_ttp,
         "reverse": False,
         "stix1x_source_type": TTP,
         "stix1x_target_type": TTP},
    ("tool", "infrastructure", "uses"):
        {"method": TTP.add_related_ttp,
         "reverse": False,
         "stix1x_source_type": TTP,
         "stix1x_target_type": TTP}
}


def get_relationship_adder(type_of_source, type_of_target, type_of_relationship):
    type_tuple = (type_of_source, type_of_target, type_of_relationship)
    if type_tuple in _RELATIONSHIP_MAP:
        return _RELATIONSHIP_MAP[type_tuple]
    else:
        return None


_ID_OBJECT_MAPPING = {}


_EXPLICIT_OBJECT_USED = {}


def record_id_object_mapping(id2x, object1x, used=True, overwrite=False):
    if id2x in _ID_OBJECT_MAPPING and not overwrite:
        print("{} already mapped to an object".format(id2x))
    _ID_OBJECT_MAPPING[id2x] = object1x
    _EXPLICIT_OBJECT_USED[id2x] = [object1x, used]


def map_vocabs_to_label(t, vocab_map):
    if vocab_map.get(t, ""):
        return vocab_map[t]
    else:
        return VocabString(t)


def convert_open_vocabs_to_controlled_vocabs(old_vocabs, vocab_mapping, required=True):
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


def extract_external_id(external_id, ex_refs, convert_fn=None):
    for ref in ex_refs:
        if external_id == (convert_fn(ref["source_name"]) if convert_fn else ref["source_name"]):
            return ref["external_id"]
    return None


def get_type_from_id(id_):
    parts = id_.split("--")
    return parts[0]


def add_missing_property_to_description(obj1x, property_name, obj2x):
    if not get_option_value("no_squirrel_gaps"):
        if _STIX_1_VERSION == "1.2":
            obj1x.add_description(property_name + ": " + str(obj2x[property_name]))
        else:
            obj1x.description = property_name + ": " + str(obj2x[property_name])
    else:
        warn("%s not representable in a STIX 1.x %s.  Found in %s", 503, property_name, obj1x.__class__.__name__, obj2x["id"])


def add_missing_list_property_to_description(obj1x, property_name, property_values):
    if not get_option_value("no_squirrel_gaps"):
        if _STIX_1_VERSION == "1.2":
            obj1x.add_description(property_name + ": " + ", ".join(property_values))
        else:
            obj1x.description = property_name + ": " + ", ".join(property_values)


def add_missing_properties_to_description(obj1x, obj2x, property_names):
    for prop_name in property_names:
        if prop_name in obj2x:
            if isinstance(obj2x[prop_name], list):
                add_missing_list_property_to_description(obj1x, prop_name, obj2x[prop_name])
            else:
                add_missing_property_to_description(obj1x, prop_name, obj2x)


# use defined LMCO kill chain for STIX 1.x from https://stix.mitre.org/language/version1.2/stix_v1.2_lmco_killchain.xml
_STIX_1_LMCO_KILL_CHAIN = {
    "kill_chain": KillChain(id_="stix:TTP-af3e707f-2fb9-49e5-8c37-14026ca0a5ff",
                            name="LM Cyber Kill Chain"),
    "phases": {
        "Reconnaissance": KillChainPhase(name="Reconnaissance", phase_id="stix:TTP-af1016d6-a744-4ed7-ac91-00fe2272185a"),
        "Weaponization": KillChainPhase(name="Weaponization", phase_id="stix:TTP-445b4827-3cca-42bd-8421-f2e947133c16"),
        "Delivery": KillChainPhase(name="Delivery", phase_id="stix:TTP-79a0e041-9d5f-49bb-ada4-8322622b162d"),
        "Exploitation": KillChainPhase(name="Exploitation", phase_id="stix:TTP-f706e4e7-53d8-44ef-967f-81535c9db7d0"),
        "Installation": KillChainPhase(name="Installation", phase_id="stix:TTP-e1e4e3f7-be3b-4b39-b80a-a593cfd99a4f"),
        "Command and Control": KillChainPhase(name="Command and Control", phase_id="stix:TTP-d6dc32b9-2538-4951-8733-3cb9ef1daae2"),
        "Actions on Objectives": KillChainPhase(name="Actions on Objectives", phase_id="stix:TTP-786ca8f9-2d9a-4213-b38e-399af4a2e5d6")
    }
}

_STIX_2_LMCO_KILL_CHAIN_PHASE_NAMES = {
    "reconnaissance": "Reconnaissance",
    "weaponization": "Weaponization",
    "delivery": "Delivery",
    "exploitation": "Exploitation",
    "installation": "Installation",
    "command-and-control": "Command and Control",
    "actions-on-objectives": "Actions on Objectives"
}


_KILL_CHAINS = {}


def process_kill_chain_phases(phases, obj1x):
    for phase in phases:
        if phase["kill_chain_name"] == "lockheed-martin-cyber-kill-chain":
            if phase["phase_name"] in _STIX_2_LMCO_KILL_CHAIN_PHASE_NAMES:
                kcp = _STIX_1_LMCO_KILL_CHAIN["phases"][_STIX_2_LMCO_KILL_CHAIN_PHASE_NAMES[phase["phase_name"]]]
                if not obj1x.kill_chain_phases:
                    obj1x.kill_chain_phases = KillChainPhasesReference()
                obj1x.add_kill_chain_phase(KillChainPhaseReference(phase_id=kcp.phase_id,
                                                                   name=kcp.name,
                                                                   ordinality=None,
                                                                   kill_chain_id=_STIX_1_LMCO_KILL_CHAIN["kill_chain"].id_,
                                                                   kill_chain_name=_STIX_1_LMCO_KILL_CHAIN["kill_chain"].name))
            else:
                warn("%s is not part of the Lockheed-Martin Kill Chain - see %s", 318, phase["phase_name"], obj1x.id_)
        else:
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


def tlp_marking(m_id):
    return m_id in ["marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",   # white
                    "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",   # green
                    "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",   # amber
                    "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed"]    # red


def create_tlp_marking_specification(m_id):
    marking_spec = MarkingSpecification()
    marking_struct = MarkingStructure()
    if m_id == "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9":
        marking_struct = TLPMarkingStructure(color="WHITE")
    if m_id == "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da":
        marking_struct = TLPMarkingStructure(color="GREEN")
    if m_id == "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82":
        marking_struct = TLPMarkingStructure(color="AMBER")
    if m_id == "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed":
        marking_struct = TLPMarkingStructure(color="RED")
    marking_spec.marking_structures = [marking_struct]
    return marking_spec


def process_markings(o1x, o2x):
    if "object_marking_refs" in o2x:
        for m_id in o2x["object_marking_refs"]:
            if tlp_marking(m_id):
                ms = create_tlp_marking_specification(m_id)
            else:
                ms = create_marking_specification(m_id)
            if ms:
                CONTAINER.add_marking(o1x, ms, descendants=True)
    if "granular_markings" in o2x:
        error("Granular Markings present in '%s' are not supported by stix2slider", 604, o2x["id"])


def convert_attack_pattern(ap2x):
    ap1x = AttackPattern()
    if "extensions" in ap2x:
        warn("Extensions in %s not supported in STIX 1.x", 530, ap2x["id"])
    if "name" in ap2x:
        ap1x.title = ap2x["name"]
    if "description" in ap2x:
        if _STIX_1_VERSION == "1.2":
            ap1x.add_description(ap2x["description"])
        else:
            ap1x.description = ap2x["description"]
    if "external_references" in ap2x:
        ap1x.capec_id = extract_external_id("capec", ap2x["external_references"])
    ttp = TTP(id_=convert_id2x(ap2x["id"]),
              timestamp=str(ap2x["modified"]))
    ttp.behavior = Behavior()
    ttp.behavior.add_attack_pattern(ap1x)
    if "kill_chain_phases" in ap2x:
        process_kill_chain_phases(ap2x["kill_chain_phases"], ttp)
    process_markings(ttp, ap2x)
    # if "kill_chain_phases" in ap2x:
    #     process_kill_chain_phases(ap2x["kill_chain_phases"], ttp)
    add_missing_properties_to_description(ap1x, ap2x, ["labels", "aliases"])
    record_id_object_mapping(ap2x["id"], ttp)
    return ttp


def convert_campaign(c2x):
    c1x = Campaign(id_=convert_id2x(c2x["id"]),
                   timestamp=str(c2x["modified"]))
    if "extensions" in c2x:
        warn("Extensions in %s not supported in STIX 1.x", 530, c2x["id"])
    if "name" in c2x:
        c1x.title = c2x["name"]
    if "description" in c2x:
        if _STIX_1_VERSION == "1.2":
            c1x.add_description(c2x["description"])
        else:
            c1x.description = c2x["description"]
    if "labels" in c2x:
        add_missing_list_property_to_description(c1x, "labels", c2x["labels"])
    names = Names()
    if "aliases" in c2x:
        for a in c2x["aliases"]:
            names.name.append(VocabString(a))
    if names:
        c1x.names = names
    if "objective" in c2x:
        c1x.intended_effects = [Statement(description=c2x["objective"])]
    add_missing_properties_to_description(c1x, c2x, ["first_seen", "last_seen"])
    process_markings(c1x, c2x)
    record_id_object_mapping(c2x["id"], c1x)
    return c1x


def convert_coa(coa2x):
    coa1x = CourseOfAction(id_=convert_id2x(coa2x["id"]),
                           timestamp=str(coa2x["modified"]))
    if "extensions" in coa2x:
        warn("Extensions in %s not supported in STIX 1.x", 530, coa2x["id"])
    if "name" in coa2x:
        coa1x.title = coa2x["name"]
    if "description" in coa2x:
        if _STIX_1_VERSION == "1.2":
            coa1x.add_description(coa2x["description"])
        else:
            coa1x.description = coa2x["description"]
    if "labels" in coa2x:
        coa_types = convert_open_vocabs_to_controlled_vocabs(coa2x["labels"], COA_LABEL_MAP)
        coa1x.type_ = coa_types[0]
        for lab in coa_types[1:]:
            warn("%s in STIX 2.x has multiple %s, only one is allowed in STIX 1.x. Using first in list - %s omitted",
                 401, "labels", lab)
    process_markings(coa1x, coa2x)
    record_id_object_mapping(coa2x["id"], coa1x)
    return coa1x


def add_missing_property_to_free_text_lines(ident1x, property_name, property_value):
    if not get_option_value("no_squirrel_gaps"):
        ident1x.add_free_text_line(property_name + ": " + property_value)


def convert_identity(ident2x):
    if "extensions" in ident2x:
        warn("Extensions in %s not supported in STIX 1.x", 530, ident2x["id"])
    if ("sectors" in ident2x or
            "contact_information" in ident2x or
            "labels" in ident2x or
            "identity_class" in ident2x or
            "description" in ident2x):
        ident1x = CIQIdentity3_0Instance()
        id1x = convert_id2x(ident2x["id"])
        ident1x.id_ = id1x
        if ident2x["identity_class"] != "organization":
            ident1x.name = ident2x["name"]
        if get_option_value("version_of_stix2x") == "2.0":
            if "labels" in ident2x:
                ident1x.roles = ident2x["labels"]
        else:
            if "roles" in ident2x:
                ident1x.roles = ident2x["roles"]
            if "labels" in ident2x:
                add_missing_list_property_to_description(ident1x, "labels", ident2x["labels"])
        if ("sectors" in ident2x or
                "contact_information" in ident2x or
                "identity_class" in ident2x or
                "description" in ident2x):
            ident1x.specification = STIXCIQIdentity3_0()
            if ident2x["identity_class"] == "organization":
                party_name = PartyName()
                party_name.add_organisation_name(str(ident2x["name"]))
                ident1x.specification.party_name = party_name
            if "sectors" in ident2x:
                first = True
                for s in ident2x["sectors"]:
                    if first:
                        ident1x.specification.organisation_info = \
                            OrganisationInfo(str(convert_open_vocabs_to_controlled_vocabs(s, SECTORS_MAP)[0]))
                        first = False
                    else:
                        warn("%s in STIX 2.x has multiple %s, only one is allowed in STIX 1.x. Using first in list - %s omitted",
                             401,
                             "Identity", "sectors", s)
            # Identity in 1.x has no description property, use free-text-lines
            if "identity_class" in ident2x:
                add_missing_property_to_free_text_lines(ident1x.specification, "identity_class", ident2x["identity_class"])
            # Because there is format defined in the specification for this property, it is difficult to
            # determine how to convert the information probably found within it to the CIQ fields, so it will be put
            # in the free_text_lines
            if "contact_information" in ident2x:
                add_missing_property_to_free_text_lines(ident1x.specification,
                                                        "contact_information",
                                                        ident2x["contact_information"])
            if "description" in ident2x:
                add_missing_property_to_free_text_lines(ident1x.specification,
                                                        "description",
                                                        ident2x["description"])
    else:
        ident1x = Identity(id_=convert_id2x(ident2x["id"]),
                           name=ident2x["name"])
    process_markings(ident1x, ident2x)
    return ident1x


def convert_indicator(indicator2x):
    indicator1x = Indicator(id_=convert_id2x(indicator2x["id"]),
                            timestamp=str(indicator2x["modified"]))
    if "extensions" in indicator2x:
        warn("Extensions in %s not supported in STIX 1.x", 530, indicator2x["id"])
    if "name" in indicator2x:
        indicator1x.title = indicator2x["name"]
    if "description" in indicator2x:
        if _STIX_1_VERSION == "1.2":
            indicator1x.add_description(indicator2x["description"])
        else:
            indicator1x.description = indicator2x["description"]

    if get_option_value("version_of_stix2x") == "2.0":
        indicator1x.indicator_types = convert_open_vocabs_to_controlled_vocabs(indicator2x["labels"],
                                                                               INDICATOR_LABEL_MAP)
    else:
        indicator1x.indicator_types = convert_open_vocabs_to_controlled_vocabs(indicator2x["indicator_types"],
                                                                               INDICATOR_LABEL_MAP)
        if "labels" in indicator2x:
            add_missing_list_property_to_description(indicator1x, "labels", indicator2x["labels"])
    indicator1x.add_valid_time_position(
        convert_to_valid_time(str(indicator2x["valid_from"]),
                              str(indicator2x["valid_until"]) if "valid_until" in indicator2x else None))
    if get_option_value("version_of_stix2x") == "2.0" or ("pattern_type" in indicator2x and indicator2x["pattern_type"] == "stix"):
        indicator1x.add_observable(create_pattern_object(indicator2x["pattern"], "Slider", "stix2slider.convert_pattern").toSTIX1x(indicator2x["id"]))
    elif indicator2x["pattern_type"] == "snort":
        tm = SnortTestMechanism()
        tm.rule = indicator2x["pattern"]
        if "pattern_version" in indicator2x:
            tm.version = indicator2x["pattern_version"]
    elif indicator2x["pattern_type"] == "yara":
        tm = YaraTestMechanism()
        tm.rule = indicator2x["pattern"]
        if "pattern_version" in indicator2x:
            tm.version = indicator2x["pattern_version"]
    elif "pattern_type" in indicator2x:
        # not supported
        warn("%s pattern type in %s cannot be represented in STIX 1.x", 524, indicator2x["pattern_type"], indicator2x["id"])
    if "kill_chain_phases" in indicator2x:
        process_kill_chain_phases(indicator2x["kill_chain_phases"], indicator1x)
    process_markings(indicator1x, indicator2x)
    record_id_object_mapping(indicator2x["id"], indicator1x)
    return indicator1x


def convert_infrastructure(infrastructure2x):
    infrastructure1x = Infrastructure()
    if "extensions" in infrastructure2x:
        warn("Extensions in %s not supported in STIX 1.x", 530, infrastructure2x["id"])
    if "name" in infrastructure2x:
        infrastructure1x.title = infrastructure2x["name"]
    if "description" in infrastructure2x:
        if _STIX_1_VERSION == "1.2":
            infrastructure1x.add_description(infrastructure2x["description"])
        else:
            infrastructure1x.description = infrastructure2x["description"]

    if get_option_value("version_of_stix2x") == "2.0":
        types = convert_open_vocabs_to_controlled_vocabs(infrastructure2x["labels"], INFRASTRUCTURE_LABELS_MAP)
    else:
        types = convert_open_vocabs_to_controlled_vocabs(infrastructure2x["infrastructure_types"], INFRASTRUCTURE_LABELS_MAP)
        if "labels" in infrastructure2x:
            add_missing_list_property_to_description(infrastructure1x, "labels", infrastructure2x["labels"])
    for t in types:
        infrastructure1x.add_type(t)
    ttp = TTP(id_=convert_id2x(infrastructure2x["id"]),
              timestamp=str(infrastructure2x["modified"]))
    ttp.resources = Resource()
    ttp.resources.infrastructure = infrastructure1x
    if "kill_chain_phases" in infrastructure2x:
        process_kill_chain_phases(infrastructure2x["kill_chain_phases"], ttp)
    add_missing_properties_to_description(infrastructure1x, infrastructure2x, ["aliases", "first_seen", "last_seen"])
    process_markings(infrastructure1x, infrastructure2x)
    record_id_object_mapping(infrastructure2x["id"], ttp)
    return ttp


def convert_malware(malware2x):
    malware1x = MalwareInstance()
    if "extensions" in malware2x:
        warn("Extensions in %s not supported in STIX 1.x", 530, malware2x["id"])
    if "name" in malware2x:
        malware1x.add_name(malware2x["name"])
    if "description" in malware2x:
        if _STIX_1_VERSION == "1.2":
            malware1x.add_description(malware2x["description"])
        else:
            malware1x.description = malware2x["description"]

    if get_option_value("version_of_stix2x") == "2.0":
        types = convert_open_vocabs_to_controlled_vocabs(malware2x["labels"], MALWARE_LABELS_MAP)
    else:
        types = convert_open_vocabs_to_controlled_vocabs(malware2x["malware_types"], MALWARE_LABELS_MAP)
        if "labels" in malware2x:
            add_missing_list_property_to_description(malware1x, "labels", malware2x["labels"])
    for t in types:
        malware1x.add_type(t)
    ttp = TTP(id_=convert_id2x(malware2x["id"]),
              timestamp=str(malware2x["modified"]))
    ttp.behavior = Behavior()
    ttp.behavior.add_malware_instance(malware1x)
    if "kill_chain_phases" in malware2x:
        process_kill_chain_phases(malware2x["kill_chain_phases"], ttp)
    add_missing_properties_to_description(malware1x, malware2x, ["aliases", "is_family", "first_seen", "last_seen",
                                                                 "operating_system_refs", "architecture_execution_envs",
                                                                 "implementation_languages", "capabilities",
                                                                 "sample_refs"])
    process_markings(malware1x, malware2x)
    record_id_object_mapping(malware2x["id"], ttp)
    return ttp


def convert_observed_data(od2x):
    o1x = Observable(id_=convert_id2x(od2x["id"]))
    if "extensions" in od2x:
        warn("Extensions in %s not supported in STIX 1.x", 530, od2x["id"])
    if "object_marking_refs" in od2x:
        for m_id in od2x["object_marking_refs"]:
            ms = create_marking_specification(m_id)
            if ms:
                CONTAINER.add_marking(o1x, ms, descendants=True)
    if "granular_markings" in od2x:
        error("Granular Markings present in '%s' are not supported by stix2slider", 604, od2x["id"])
    # observable-data has no description
    if "objects" in od2x:  # deprecated in 2.1
        o1x.object_ = convert_cyber_observables(od2x["objects"], od2x["id"])
    return o1x


def convert_report(r2x):
    if _STIX_1_VERSION == "1.2":
        r1x = Report(id_=convert_id2x(r2x["id"]),
                     timestamp=str(r2x["modified"]))
        if "extensions" in r2x:
            warn("Extensions in %s not supported in STIX 1.x", 530, r2x["id"])
        r1x.header = Header()
        if "name" in r2x:
            r1x.header.title = r2x["name"]
        if "description" in r2x:
            r1x.header.add_description(r2x["description"])
        if get_option_value("version_of_stix2x") == "2.0":
            intents = convert_open_vocabs_to_controlled_vocabs(r2x["labels"], REPORT_LABELS_MAP)
        else:
            intents = convert_open_vocabs_to_controlled_vocabs(r2x["report_types"], REPORT_LABELS_MAP)
            # TODO: what if there are labels - there is not description property on reports to put it
        for i in intents:
            r1x.header.add_intent(i)
        if "published" in r2x:
            add_missing_properties_to_description(r1x.header, r2x, ["published"])
        for ref in r2x["object_refs"]:
            ref_type = get_type_from_id(ref)
            ref1x = convert_id2x(ref)
            if ref_type == "attack-pattern":
                r1x.add_ttp(TTP(idref=ref1x))
            elif ref_type == "campaign":
                r1x.add_campaign(Campaign(idref=ref1x))
            elif ref_type == 'course-of-action':
                r1x.add_course_of_action(CourseOfAction(idref=ref1x))
            elif ref_type == "indicator":
                r1x.add_indicator(Indicator(idref=ref1x))
            elif ref_type == "observed-data":
                r1x.add_observable(Observable(idref=ref1x))
            elif ref_type == "malware":
                r1x.add_ttp(TTP(idref=ref1x))
            elif ref_type == "threat-actor":
                r1x.add_threat_actor(ThreatActor(idref=ref1x))
            elif ref_type == "tool":
                r1x.add_ttp(TTP(idref=ref1x))
            elif ref_type == "vulnerability":
                r1x.add_exploit_target(ExploitTarget(idref=ref1x))
            elif ref_type == "identity" or ref_type == "relationship" or ref_type == "location":
                warn("%s in %s cannot be represented explicitly as a member of a STIX 1.x report", 703, ref, r2x["id"])
            elif ref_type == "intrusion-set" or ref_type == "opinion" or ref_type == "note":
                warn("%s in %s cannot be represented in STIX 1.x", 612, ref, r2x["id"])
            else:
                warn("ref type %s in %s is not known", 316, ref_type, r2x["id"])
        process_markings(r1x, r2x)
        record_id_object_mapping(r2x["id"], r1x)
        return r1x
    else:
        return None


def convert_threat_actor(ta2x):
    ta1x = ThreatActor(id_=convert_id2x(ta2x["id"]),
                       timestamp=str(ta2x["modified"]))
    if "extensions" in ta2x:
        warn("Extensions in %s not supported in STIX 1.x", 530, ta2x["id"])
    ta1x.title = ta2x["name"]
    if get_option_value("version_of_stix2x") == "2.0":
        types = convert_open_vocabs_to_controlled_vocabs(ta2x["labels"], THREAT_ACTOR_LABEL_MAP)
    else:
        types = convert_open_vocabs_to_controlled_vocabs(ta2x["threat_actor_types"], THREAT_ACTOR_LABEL_MAP)
        if "labels" in ta2x:
            add_missing_list_property_to_description(ta1x, "labels", ta2x["labels"])
    for t in types:
        ta1x.add_type(t)
    if "description" in ta2x:
        if _STIX_1_VERSION == "1.2":
            ta1x.add_description(ta2x["description"])
        else:
            ta1x.description = ta2x["description"]
    if "goals" in ta2x:
        for g in ta2x["goals"]:
            ta1x.add_intended_effect(g)
    if "sophistication" in ta2x:
        sophistications = convert_open_vocabs_to_controlled_vocabs([ta2x["sophistication"]], THREAT_ACTOR_SOPHISTICATION_MAP)
        for s in sophistications:
            ta1x.add_sophistication(s)
    all_motivations = []
    if "primary_motivation" in ta2x:
        all_motivations = [ta2x["primary_motivation"]]
    if "secondary_motivation" in ta2x:
        all_motivations.extend(ta2x["secondary_motivation"])
    if "personal_motivation" in ta2x:
        all_motivations.extend(ta2x["personal_motivation"])
    motivations = convert_open_vocabs_to_controlled_vocabs(all_motivations, ATTACK_MOTIVATION_MAP)
    for m in motivations:
        ta1x.add_motivation(m)
    add_missing_properties_to_description(ta1x, ta2x, ["resource_level", "last_seen", "first_seen", "roles", "aliases"])
    process_markings(ta1x, ta2x)
    record_id_object_mapping(ta2x["id"], ta1x)
    return ta1x


def convert_tool(tool2x):
    tool1x = ToolInformation()
    if "extensions" in tool2x:
        warn("Extensions in %s not supported in STIX 1.x", 530, tool2x["id"])
    if "name" in tool2x:
        tool1x.title = tool2x["name"]
    if "description" in tool2x:
        tool1x.description = tool2x["description"]
    if "tool_version" in tool2x:
        tool1x.version = tool2x["tool_version"]
    if "labels" in tool2x:
        warn("labels not representable in a STIX 1.x ToolInformation.  Found in %s", 502, tool2x["id"])
        # bug in python_stix prevents using next line of code
        # tool1x.type_ = convert_open_vocabs_to_controlled_vocabs(tool2x["labels"], TOOL_LABELS_MAP)
    ttp = TTP(id_=convert_id2x(tool2x["id"]),
              timestamp=str(tool2x["modified"]))
    if not ttp.resources:
        ttp.resources = Resource()
    if not ttp.resources.tools:
        ttp.resources.tools = Tools()
    ttp.resources.tools.append(tool1x)
    if "kill_chain_phases" in tool2x:
        process_kill_chain_phases(tool2x["kill_chain_phases"], ttp)
    process_markings(tool1x, tool2x)
    record_id_object_mapping(tool2x["id"], ttp)
    return ttp


def convert_vulnerability(v2x):
    v1x = Vulnerability()
    if "extensions" in v2x:
        warn("Extensions in %s not supported in STIX 1.x", 530, v2x["id"])
    if "name" in v2x:
        v1x.title = v2x["name"]
    if "description" in v2x:
        if _STIX_1_VERSION == "1.2":
            v1x.add_description(v2x["description"])
        else:
            v1x.description = v2x["description"]
    if "labels" in v2x:
        add_missing_list_property_to_description(v1x, "labels", v2x["labels"])
    v1x.cve_id = extract_external_id("cve", v2x["external_references"])
    et = ExploitTarget(id_=convert_id2x(v2x["id"]),
                       timestamp=str(v2x["modified"]))
    et.add_vulnerability(v1x)
    if "kill_chain_phases" in v2x:
        process_kill_chain_phases(v2x["kill_chain_phases"], et)
    process_markings(v1x, v2x)
    record_id_object_mapping(v2x["id"], et)
    return et


def create_free_text_address(location_obj):
    free_text = ""
    if "description" in location_obj:
        free_text = free_text + location_obj["description"] + "\n"
    if "latitutde" in location_obj and "longitude" in location_obj:
        free_text = free_text + "(" + location_obj["latitutde"] + ", " + location_obj["longitude"] + ")\n"
    if "street_address" in location_obj:
        free_text = free_text + location_obj["street_address"] + "\n"
    if "city" in location_obj:
        free_text = free_text + location_obj["city"]
    if "region" in location_obj:
        free_text = free_text + (", " if "city" in location_obj else "") + location_obj["region"]
    if "postal_code" in location_obj:
        free_text = free_text + " " + location_obj["postal_code"]
    if free_text == "":
        return None
    else:
        return free_text


def create_address_object_from_location(location_obj):
    address = Address()
    address.country = location_obj["country"]
    address.administrative_area = location_obj["administrative_area"]
    address.free_text_address = create_free_text_address(location_obj)
    return address


def enhance_identity(identity_object):
    ciq_object = CIQIdentity3_0Instance()
    ciq_object.specification = STIXCIQIdentity3_0()
    ciq_object.specification.party_name = identity_object.name
    return ciq_object


def add_location_to_identity(source_1x_obj, target_obj):
    if isinstance(source_1x_obj, ThreatActor):
        # add an identity to the threat actor, if necessary
        if source_1x_obj.identity is None:
            source_1x_obj.identity = CIQIdentity3_0Instance()
        source_1x_obj = source_1x_obj.identity
    if isinstance(source_1x_obj, Identity):
        if not isinstance(source_1x_obj, CIQIdentity3_0Instance):
            source_1x_obj = enhance_identity(source_1x_obj)
        record_id_object_mapping(source_1x_obj.id_, source_1x_obj, used=False, overwrite=True)
        source_1x_obj.specification.add_address(create_address_object_from_location(target_obj))
    else:
        warn("Relationship between %s and location is not supported in STIX 1.x", 527, source_1x_obj.id_)


def process_location_reference(rel):
    if rel["source_ref"] and rel["target_ref"]:
        if rel["source_ref"] in _ID_OBJECT_MAPPING:
            source_1x_obj = _ID_OBJECT_MAPPING[rel["source_ref"]]  # 1.x object
        else:
            warn("No %s object exists for %s in relationship %s", 315, "source_ref", rel["source_ref"], rel["id"])
            return
        if rel["target_ref"] in _LOCATIONS:
            target_obj = _LOCATIONS[rel["target_ref"]]  # 2.x object
        else:
            warn("No %s object exists for %s in relationship %s", 315, "target_ref", rel["target_ref"], rel["id"])
            return
        add_location_to_identity(source_1x_obj, target_obj)
    else:
        warn("Cannot convert %s because it doesn't contain both a source_ref and a target_ref", 314, rel["id"])


def process_relationships(rel):
    target_obj = None
    if rel.relationship_type == "located-at":
        process_location_reference(rel)
        return
    if rel["source_ref"] in _ID_OBJECT_MAPPING:
        source_obj = _ID_OBJECT_MAPPING[rel["source_ref"]]
    else:
        warn("No source object exists for %s. Dropping the relationship %s", 301, rel["source_ref"], rel["id"])
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
    if not add_method_info["method"]:
        # handled elsewhere
        return
    source_obj_class = add_method_info["stix1x_source_type"]
    target_obj_class = add_method_info["stix1x_target_type"]
    if add_method_info["reverse"] and target_obj:
        source_obj_ref_1x = source_obj_class(idref=source_obj.id_)
        add_method_info["method"](target_obj, source_obj_ref_1x)
    else:
        if target_obj:
            target_obj_idref_1x = target_obj_class(idref=target_obj.id_)
        else:
            target_obj_idref_1x = target_obj_class(idref=convert_id2x(rel["target_ref"]))
        # type_of_source == type_of_target implies its a self-referencing related-to relationship
        if target_obj_class == Identity or target_obj_class == ExploitTarget or type_of_source == type_of_target:
            add_method_info["method"](source_obj, rel["target_ref"], target_obj_idref_1x)
        else:
            add_method_info["method"](source_obj, target_obj_idref_1x)


_INFORMATION_SOURCES = {}


def id_of_type(ref, type):
    return ref.startswith(type)


def create_references_for_vulnerability(obj1x, obj2x):
    # assume only ine
    v = obj1x.vulnerabilities[0]
    not_urls = []
    for er in obj2x["external_references"]:
        # cve and osvdb handled elsewhere
        if "url" in er:
            v.add_reference(er["url"])
        else:
            not_urls.append(er)
    return not_urls


def get_info_source(ob1x, obj):
    if hasattr(ob1x, "information_source") and ob1x.information_source:
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
    if obj["id"] in _ID_OBJECT_MAPPING:
        ob1x = _ID_OBJECT_MAPPING[obj["id"]]
    else:
        warn("No object has been created for %s to add to the external references", 307, obj["id"])
        return
    if id_of_type(obj["id"], "vulnerability"):
        er_for_info_source = create_references_for_vulnerability(ob1x, obj)
    else:
        er_for_info_source = obj["external_references"]
    if er_for_info_source:
        ref_texts = []
        info_source = None
        for er in er_for_info_source:
            # capec and cve handled elsewhere
            if "url" in er:
                if obj["type"] == "indicator":
                    desc = "SOURCE: " + er["source_name"] + " - " + er["url"]
                    if _STIX_1_VERSION == "1.2":
                        ob1x.add_description(desc)
                    else:
                        ob1x.description = ob1x.description + "\n" + desc
                else:
                    if not info_source:
                        info_source = get_info_source(ob1x, obj)
                    info_source.add_reference(er["url"])
            if "external_id" in er and er["source_name"] != "capec":
                ref_texts.append("SOURCE: " + er["source_name"] + " - " + "EXTERNAL ID: " + er["external_id"])
            if "hashes" in er:
                warn("hashes not representable in a STIX 1.x %s.  Found in %s", 503, "InformationSource", obj["id"])
            if "description" in er:
                if hasattr(ob1x, "description"):
                    if _STIX_1_VERSION == "1.2":
                        ob1x.add_description(er["description"])
                    else:
                        ob1x.description = ob1x.description + "\n" + er["description"]
                else:
                    warn("%s does not support descriptions, so the external reference has been dropped", 532, obj["id"])
        if ref_texts != []:
            for rt in ref_texts:
                if _STIX_1_VERSION == "1.2":
                    ob1x.add_description(rt)
                else:
                    ob1x.description = ob1x.description + " " + rt


def create_information_source(identity2x_tuple):
    identity_obj = identity2x_tuple[0]
    used_before = identity2x_tuple[1]
    if used_before:
        return InformationSource(identity=Identity(idref=identity_obj.id_))
    else:
        identity2x_tuple[1] = True
        return InformationSource(identity=identity_obj)


def process_created_by_ref(o):
    if o["id"] in _ID_OBJECT_MAPPING:
        obj1x = _ID_OBJECT_MAPPING[o["id"]]
        if hasattr(obj1x, "information_source"):
            if o["created_by_ref"] in _EXPLICIT_OBJECT_USED:
                identity2x_tuple = _EXPLICIT_OBJECT_USED[o["created_by_ref"]]
                obj1x.information_source = create_information_source(identity2x_tuple)


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
                s = Sighting(timestamp=str(o["modified"]), description=[])
                if "description" in o:
                    if _STIX_1_VERSION == "1.2":
                        s.add_description(o["description"])
                    else:
                        s.description = o["description"]
                indicator_of_sighting.sightings.append(s)
                if ref in _EXPLICIT_OBJECT_USED:
                    identity2x_tuple = _EXPLICIT_OBJECT_USED[ref]
                    s.source = create_information_source(identity2x_tuple)
                if "observed_data_refs" in o:
                    # reference, regardless of whether its in the bundle or not
                    s.related_observables = RelatedObservables()
                    for od_ref in o["observed_data_refs"]:
                        ro = RelatedObservable()
                        s.related_observables.append(ro)
                        ro.item = Observable(idref=convert_id2x(od_ref))
        add_missing_properties_to_description(s, o, ["first_seen", "last_seen"])
    else:
        warn("Unable to convert STIX 2.x sighting %s because it doesn't refer to an indicator", 508, o["sighting_of_ref"])


def convert_marking_definition(marking2x):
    definition = marking2x["definition"]
    marking_spec = MarkingSpecification()
    if marking2x["definition_type"] == "statement":
        tou = TermsOfUseMarkingStructure(terms_of_use=definition["statement"])
        tou.id_ = convert_id2x(marking2x["id"])
        marking_spec.marking_structures.append(tou)
    elif marking2x["definition_type"] == "tlp":
        tlp = TLPMarkingStructure(color=definition["tlp"])
        tlp.id_ = convert_id2x(marking2x["id"])
        marking_spec.marking_structures.append(tlp)
    elif marking2x["definition_type"] == "ais":
        identity2x_tuple = _EXPLICIT_OBJECT_USED[marking2x["created_by_ref"]]
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
        ais_marking.id_ = convert_id2x(marking2x["id"])

        if isinstance(proprietary, IsProprietary):
            ais_marking.is_proprietary = proprietary
        else:
            ais_marking.not_proprietary = proprietary

        marking_spec.controlled_structure = "//node() | //@*"
        marking_spec.marking_structures.append(ais_marking)
        marking_spec.information_source = create_information_source(identity2x_tuple)

        # Remove marking to CIQ identity. Special case for AIS.
        for mark_spec in CONTAINER.get_markings(identity2x_tuple[0]):
            mark_struct = mark_spec.marking_structures[0]
            if mark_struct.idref and mark_struct.idref == ais_marking.id_:
                CONTAINER.remove_marking(identity2x_tuple[0], mark_spec, True)

    record_id_object_mapping(marking2x["id"], marking_spec.marking_structures[0])
    if "object_marking_refs" in marking2x:
        for m_id in marking2x["object_marking_refs"]:
            ms = create_marking_specification(m_id)
            if ms:
                CONTAINER.add_marking(marking_spec, ms, descendants=True)
    if "granular_markings" in marking2x:
        error("Granular Markings present in '%s' are not supported by stix2slider", 604, marking2x["id"])
    return marking_spec


def create_marking_specification(id2x):
    if id2x in _ID_OBJECT_MAPPING:
        marking1x = _ID_OBJECT_MAPPING[id2x]
        if isinstance(marking1x, AISMarkingStructure):
            return  # This is a special case for AIS.

    marking_spec = MarkingSpecification()
    marking_struct = MarkingStructure()
    marking_struct.idref = convert_id2x(id2x)
    marking_spec.marking_structures.append(marking_struct)
    return marking_spec


_LOCATIONS = {}


def is_extension_type(obj, type_):
    if "extensions" in obj:
        extensions = obj["extensions"].items()
        if len(extensions) == 1:
            k, v = list(extensions)[0]
            if v["extension_type"] == type_:
                return True
        else:
            warn("Multiple extensions in %s are not handled, yet", 613, obj["id"])
    else:
        return False


def sco_type(type_name):
    return type_name in {"artifact", "autonomous-system", "directory", "domain-name", "email-addr",
                         "email-message", "file", "ipv4-addr", "ipv6-addr", "mac-addr", "mutex",
                         "network-traffic", "process", "software", "url", "user-account",
                         "windows-registry-key", "x509-certificate"}


def convert_bundle(bundle_obj):
    global _ID_OBJECT_MAPPING
    global _EXPLICIT_OBJECT_USED
    global _VICTIM_TARGET_TTPS
    global _KILL_CHAINS
    global CONTAINER
    global STIX1X_OBS_GLOBAL
    _ID_OBJECT_MAPPING = {}
    _EXPLICIT_OBJECT_USED = {}
    _VICTIM_TARGET_TTPS = []
    _KILL_CHAINS = {}
    STIX1X_OBS_GLOBAL = {}
    stix2x_objs = {}
    stix1x_obs_list = {}

    if "spec_version" in bundle_obj:
        set_option_value("version_of_stix2x", "2.0")
    else:
        set_option_value("version_of_stix2x", "2.1")

    if get_option_value("use_namespace"):
        option_value = get_option_value("use_namespace").split(" ")
        common._ID_NAMESPACE = option_value[0]
        set_default_namespace(*option_value)

    CONTAINER = stixmarx.new()
    pkg = CONTAINER.package
    pkg.id_ = convert_id2x(bundle_obj["id"])

    for identity in (v for v in bundle_obj["objects"] if v["type"] == "identity"):
        debug("Found '%s'", 0, identity["id"])
        i1x = convert_identity(identity)
        record_id_object_mapping(identity["id"], i1x, used=False)

    for marking_definition in (v for v in bundle_obj["objects"] if v["type"] == "marking-definition"):
        debug("Found '%s'", 0, marking_definition["id"])
        m1x = convert_marking_definition(marking_definition)
        if not pkg.stix_header:
            pkg.stix_header = STIXHeader(handling=Marking())
        pkg.stix_header.handling.add_marking(m1x)

    for o in bundle_obj["objects"]:
        # map all 2.x objects to their 2.x ids
        stix2x_objs[o["id"]] = o
        if o["type"] == "attack-pattern":
            pkg.add_ttp(convert_attack_pattern(o))
        elif o["type"] == "campaign":
            pkg.add_campaign(convert_campaign(o))
        elif o["type"] == 'course-of-action':
            pkg.add_course_of_action(convert_coa(o))
        elif o["type"] == "extension-definition":
            warn("Ignoring %s, because %ss cannot be represented in STIX 1.x", 528, o["id"], "extension-definition")
        elif o["type"] == "grouping":
            warn("Ignoring %s, because %ss cannot be represented in STIX 1.x", 528, o["id"], "grouping")
        elif o["type"] == "indicator":
            pkg.add_indicator(convert_indicator(o))
        elif o["type"] == "infrastructure":
            pkg.add_ttp(convert_infrastructure(o))
        elif o["type"] == "intrusion-set":
            warn("Ignoring %s, because %ss cannot be represented in STIX 1.x", 528, o["id"], "intrusion-set")
        elif o["type"] == "location":
            _LOCATIONS[o["id"]] = o
            # TODO: anything about the markings on the location that we should remember?
        elif o["type"] == "language-content":
            warn("Ignoring %s, because %ss cannot be represented in STIX 1.x", 528, o["id"], "language-content")
        elif o["type"] == "malware":
            pkg.add_ttp(convert_malware(o))
        elif o["type"] == "malware-analysis":
            warn("Ignoring %s, because a %s object cannot be represented in STIX 1.x", 528, o["id"], "malware-analysis")
        elif o["type"] == "note":
            warn("Ignoring %s, because a %s object cannot be represented in STIX 1.x", 528, o["id"], "note")
        elif o["type"] == "observed-data":
            obs1x = convert_observed_data(o)
            pkg.add_observable(obs1x)
            stix1x_obs_list[o["id"]] = obs1x
        elif o["type"] == "opinion":
            warn("Ignoring %s, because a %s object cannot be represented in STIX 1.x", 528, o["id"], "opinion")
        elif o["type"] == "report":
            if _STIX_1_VERSION == "1.2":
                pkg.add_report(convert_report(o))
            else:
                warn("Ignoring %s, because a %s object cannot be represented in STIX 1.1.1", 509, o["id"], "report")
        elif o["type"] == "threat-actor":
            pkg.add_threat_actor(convert_threat_actor(o))
        elif o["type"] == "tool":
            pkg.add_ttp(convert_tool(o))
        elif o["type"] == "vulnerability":
            pkg.add_exploit_target(convert_vulnerability(o))
        elif sco_type(o["type"]):
            pkg.add_observable(convert_sco(o))
        elif is_extension_type(o, "new-sco"):
            convert_sco(o)
        elif is_extension_type(o, "new-sdo") or is_extension_type(o, "new-sro"):
            warn("Ignoring %s, because only new-sco extensions are supported", 533, o["id"])
        elif o["id"].startswith("x-"):
            warn("Ignoring %s, because (deprecated) custom objects are not supported", 534, o["id"])

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
    if get_option_value("version_of_stix2x") == "2.1":
        for o in bundle_obj["objects"]:
            if sco_type(o["type"]):
                # add STIX 1.x embedded properties
                add_refs(o, pkg)
        objects_inline = dict()
        for o in bundle_obj["objects"]:
            if o["type"] == "observed-data":
                # add related objects
                add_object_refs(o, stix2x_objs, stix1x_obs_list, objects_inline, pkg)
    # the LMCO Kill Chain is not included here.  It is defined outside of the STIX content.
    for k, v in _KILL_CHAINS.items():
        if not pkg.ttps:
            pkg.ttps = TTPs()
        pkg.ttps.add_kill_chain(v["kill_chain"])
    CONTAINER.flush()
    CONTAINER = None
    return pkg
