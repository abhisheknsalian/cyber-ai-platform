from backend.rag.retrieval import retrieve_relevant


def test_phishing_query_retrieves_phishing_documents():
    results = retrieve_relevant("Explain phishing attacks and mitigation")
    assert results
    assert results[0][0].metadata["threat_type"] == "phishing"


def test_ransomware_query_retrieves_ransomware_documents():
    results = retrieve_relevant("Explain ransomware attacks")
    assert results
    assert results[0][0].metadata["threat_type"] == "ransomware"


def test_ddos_query_retrieves_ddos_documents():
    results = retrieve_relevant("How can DDoS attacks be mitigated?")
    assert results
    assert results[0][0].metadata["threat_type"] == "ddos_attack"


def test_sql_injection_query_retrieves_sql_injection_documents():
    results = retrieve_relevant("What are SQL injection indicators?")
    assert results
    assert results[0][0].metadata["threat_type"] == "sql_injection"


def test_unrelated_query_returns_no_relevant_chunks():
    """An off-topic query should not be treated as supported threat intelligence just
    because some document is the mathematically nearest neighbor in embedding space.
    """
    results = retrieve_relevant("What is the capital of France?")
    assert results == []
