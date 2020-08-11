from leapp.libraries.common import isccfg
from leapp.libraries.actor import model
from leapp.models import BindFacts


def model_paths(model):
    paths = list()
    for m in model.dnssec_lookaside:
        paths.append(m.path)
    return paths


def test_simple(path):
    mockcfg = isccfg.MockConfig("""
options {
    listen-on port 53 { 127.0.0.1; };
    listen-on-v6 port 53 { ::1; };
    directory       "/var/named";
    allow-query     { localhost; };
    recursion yes;

    dnssec-validation yes;
};

zone "." IN {
    type hint;
    file "named.ca";
};
""", '/etc/named.conf')
    facts = model.get_facts(mockcfg)
    assert isinstance(facts, BindFacts)
    assert facts.dnssec_lookaside is None


def test_dnssec_lookaside(path):
    mockcfg = isccfg.MockConfig("""
options {
    listen-on port 53 { 127.0.0.1; };
    listen-on-v6 port 53 { ::1; };
    directory       "/var/named";
    allow-query     { localhost; };
    recursion yes;

    dnssec-validation yes;
        dnssec-lookaside auto;
};

zone "." IN {
    type hint;
    file "named.ca";
};
""", '/etc/named.conf')
    facts = model.get_facts(mockcfg)
    assert isinstance(facts, BindFacts)
    assert '/etc/named.conf' in model_paths(facts.dnssec_lookaside)
