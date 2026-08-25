"""Tests for backend/intelligence/entities.py: entity creation, stable/deterministic
IDs, relationship creation, and ThreatGraph's basic operations.
"""

from backend.intelligence.entities import (
    Entity,
    Relationship,
    ThreatGraph,
    indicator_id,
    mitigation_id,
    slugify,
    source_id,
    technique_id,
    threat_id,
)


def test_slugify_is_deterministic():
    assert slugify("Web Application Firewall (WAF)") == slugify("Web Application Firewall (WAF)")


def test_slugify_lowercases_and_replaces_non_alphanumerics():
    assert slugify("Web Application Firewall (WAF)") == "web_application_firewall_waf"


def test_slugify_strips_leading_trailing_underscores():
    assert slugify("  --Rate Limiting!!--  ") == "rate_limiting"


def test_slugify_caps_length():
    assert len(slugify("x" * 500)) <= 60


def test_threat_id_is_deterministic_and_namespaced():
    assert threat_id("ddos_attack") == "threat:ddos_attack"
    assert threat_id("ddos_attack") == threat_id("ddos_attack")


def test_technique_id_normalizes_case():
    assert technique_id("t1498") == "mitre:T1498"
    assert technique_id("T1498") == "mitre:T1498"


def test_indicator_and_mitigation_ids_are_slug_based_and_stable():
    assert indicator_id("Extremely high traffic volume") == indicator_id("Extremely high traffic volume")
    assert mitigation_id("Rate limiting") == "mitigation:rate_limiting"


def test_source_id_uses_filename_verbatim():
    assert source_id("ddos_attack.txt") == "source:ddos_attack.txt"


def test_ids_are_never_randomly_generated_same_input_same_output():
    # Regenerating an entity from the same text 100 times must always produce the
    # same ID -- this is the property the whole graph's idempotent ingestion and
    # deterministic MITRE/source attribution depend on.
    results = {indicator_id("unusual outbound traffic") for _ in range(100)}
    assert len(results) == 1


def test_entity_construction():
    entity = Entity(id="threat:ddos_attack", type="threat", name="DDoS Attack")
    assert entity.id == "threat:ddos_attack"
    assert entity.type == "threat"
    assert entity.name == "DDoS Attack"


def test_relationship_carries_reference():
    rel = Relationship(source_id="threat:ddos_attack", relation="USES", target_id="mitre:T1498", reference="ddos_attack.txt")
    assert rel.reference == "ddos_attack.txt"
    assert rel.relation == "USES"


def test_threat_graph_add_entity_is_idempotent():
    graph = ThreatGraph()
    entity = Entity(id="threat:ddos_attack", type="threat", name="DDoS Attack")
    graph.add_entity(entity)
    graph.add_entity(entity)
    assert len(graph.entities) == 1


def test_threat_graph_add_relationship_deduplicates():
    graph = ThreatGraph()
    rel = Relationship(source_id="threat:ddos_attack", relation="USES", target_id="mitre:T1498", reference="ddos_attack.txt")
    graph.add_relationship(rel)
    graph.add_relationship(rel)
    assert len(graph.relationships) == 1


def test_relations_from_filters_by_source():
    graph = ThreatGraph()
    a = Relationship(source_id="threat:ddos_attack", relation="USES", target_id="mitre:T1498")
    b = Relationship(source_id="threat:phishing", relation="USES", target_id="mitre:T1566")
    graph.add_relationship(a)
    graph.add_relationship(b)
    assert graph.relations_from("threat:ddos_attack") == [a]


def test_threat_graph_round_trips_through_json():
    graph = ThreatGraph()
    graph.add_entity(Entity(id="threat:ddos_attack", type="threat", name="DDoS Attack"))
    graph.add_relationship(Relationship(source_id="threat:ddos_attack", relation="USES", target_id="mitre:T1498"))

    restored = ThreatGraph.model_validate_json(graph.model_dump_json())
    assert restored == graph
