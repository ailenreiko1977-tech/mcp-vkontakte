import pytest
from starlette.testclient import TestClient
from vk_mcp.app import create_app
from test_security import cookie


@pytest.mark.parametrize("origin",[None,"null","https://attacker.invalid"])
def test_account_form_still_rejects_untrusted_origin(settings,store,origin):
    sid=store.new_session("alice")
    csrf=store.session(sid)["csrf"]
    with TestClient(create_app(settings,store=store),base_url=settings.public_url) as client:
        client.cookies.set("vk_session",cookie(settings,sid))
        page=client.get("/account")
        assert page.headers["referrer-policy"]=="strict-origin"
        headers={} if origin is None else {"Origin":origin}
        r=client.post("/account",headers=headers,data={"csrf":csrf,"alias":"check","kind":"group","token":"fake-token"})
        assert r.status_code==400
        assert store.connections("alice")==[]


def test_referrer_policy_allows_normal_https_form_and_keeps_csrf(settings,store):
    sid=store.new_session("alice")
    csrf=store.session(sid)["csrf"]
    with TestClient(create_app(settings,store=store),base_url=settings.public_url) as client:
        client.cookies.set("vk_session",cookie(settings,sid))
        assert client.get("/account").headers["referrer-policy"]=="strict-origin"
        data={"alias":"check","kind":"group","token":"fake-token"}
        assert client.post("/account",headers={"Origin":settings.public_url},data=data).status_code==400
        r=client.post("/account",headers={"Origin":settings.public_url},data=data|{"csrf":csrf})
        assert r.status_code==200
        assert store.connections("alice")==[{"alias":"check","kind":"group"}]
