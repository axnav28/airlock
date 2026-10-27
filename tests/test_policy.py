from airlock.models import Sensitivity
from airlock.policy import PolicyEngine
from airlock.provenance import trusted, untrusted, derive

def test_untrusted_recipient_denied():
    d = PolicyEngine().check("email.send", {"to": untrusted("bad@evil.test", "email#3"), "body": trusted("hi", "user")}, approved_root=".")
    assert not d.allowed and d.policy_id == "EMAIL_RECIPIENT_AUTH"

def test_secret_search_denied():
    d = PolicyEngine().check("web.search", {"query": trusted("fake", "file:secret", Sensitivity.SECRET)}, approved_root=".")
    assert not d.allowed and d.policy_id == "SEARCH_SECRET_EGRESS"

def test_authorized_benign_send_allowed():
    destination = trusted("friend@example.test", "user", authorization={"subject":"user", "scope":"email.send", "destination":"friend@example.test"})
    body = trusted("Dinner at 7", "user")
    assert PolicyEngine().check("email.send", {"to": destination, "body": body}, approved_root=".").allowed
