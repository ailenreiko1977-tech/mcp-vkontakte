import asyncio
import json
import time
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from starlette.testclient import TestClient
from itsdangerous import TimestampSigner
from base64 import b64encode
from mcp.server.auth.provider import AccessToken

from vk_mcp.auth import Verifier
from vk_mcp.app import create_app
from vk_mcp.catalog import Catalog, PolicyError
from vk_mcp.service import Service
from vk_mcp.vk import VKClient, VKError


def seed(store):
    store.put_connection("alice","group","group","test-alice-secret")
    store.put_connection("bob","group","group","test-bob-secret")


def test_tenant_tokens_encrypted_and_not_shared(store):
    seed(store)
    assert store.connection("alice","group")["token"]=="test-alice-secret"
    assert store.connection("bob","group")["token"]=="test-bob-secret"
    assert b"test-alice-secret" not in store.path.read_bytes()
    assert "token" not in store.connections("alice")[0]
    with pytest.raises(PolicyError): store.connection("mallory","group")


def test_action_belongs_to_creator_and_exact_payload(store):
    action_id,digest=store.prepare("alice",{"method":"wall.post","params":{"message":"first"}})
    with pytest.raises(PolicyError): store.action("bob",action_id)
    with pytest.raises(PolicyError): store.claim("alice",action_id,"wrong")
    assert store.claim("alice",action_id,digest)["params"]["message"]=="first"
    with pytest.raises(PolicyError): store.claim("alice",action_id,digest)


def test_concurrent_confirmation_is_single_attempt(store):
    action_id,digest=store.prepare("alice",{"method":"wall.post"})
    def claim():
        try: store.claim("alice",action_id,digest); return 1
        except PolicyError: return 0
    with ThreadPoolExecutor(max_workers=8) as pool:
        assert sum(pool.map(lambda _:claim(),range(8)))==1


def test_expired_action_cannot_execute(store):
    action_id,digest=store.prepare("alice",{})
    with store.connect() as db: db.execute("UPDATE actions SET expires=0 WHERE id=?",(action_id,))
    with pytest.raises(PolicyError): store.claim("alice",action_id,digest)


@pytest.mark.parametrize("method,params,write",[
    ("wall.post",{"message":"hi"},False),
    ("wall.get",{},True),
    ("execute",{"code":"return API.wall.post({});"},False),
    ("wall.get",{"access_token":"replacement"},False),
    ("wall.get",{"v":"5.1"},False),
    ("wall.get",{"count":1000000},False),
    ("wall.get",{"count":True},False),
    ("groups.getCallbackConfirmationCode",{"group_id":1},False),
    ("utils.getShortLink",{"url":"https://example.test"},False),
    ("ads.createAds",{},True),
])
def test_policy_denies_bypass(method,params,write):
    with pytest.raises(PolicyError): Catalog().validate(method,params,write=write)


async def test_read_uses_only_correct_tenant_and_fixed_api(store):
    seed(store)
    observed=[]
    def handler(request):
        from urllib.parse import parse_qs
        body=parse_qs(request.content.decode())
        observed.append((str(request.url),body))
        return httpx.Response(200,json={"response":{"items":[],"access_token":body["access_token"][0]}})
    vk=VKClient(store,httpx.MockTransport(handler))
    entry=Catalog().validate("wall.get",{"owner_id":-1})
    for who in ("alice","bob"):
        result=await vk.call(who,"group",{**entry,"token_types":["group"]},{"owner_id":-1})
        assert result["data"]["access_token"]=="[redacted]"
    assert observed[0][0]=="https://api.vk.com/method/wall.get"
    assert observed[0][1]["access_token"]==["test-alice-secret"]
    assert observed[1][1]["access_token"]==["test-bob-secret"]
    assert observed[0][1]["v"]==["5.199"]


async def test_vk_error_never_echoes_request_token(store):
    seed(store)
    def handler(req):
        return httpx.Response(200,json={"error":{"error_code":5,"error_msg":"test-alice-secret","request_params":[{"key":"access_token","value":"test-alice-secret"}]}})
    client=VKClient(store,httpx.MockTransport(handler))
    with pytest.raises(VKError) as error:
        await client.call("alice","group",{"method":"wall.post","token_types":["group"]},{},write=True)
    assert "test-alice-secret" not in str(error.value)


async def test_redirects_not_followed_and_changes_not_retried(store):
    seed(store)
    calls=[]
    def handler(req):
        calls.append(str(req.url))
        return httpx.Response(302,headers={"Location":"https://attacker.invalid"})
    client=VKClient(store,httpx.MockTransport(handler))
    with pytest.raises(VKError): await client.call("alice","group",{"method":"wall.post","token_types":["group"]},{},write=True)
    assert calls==["https://api.vk.com/method/wall.post"]


async def test_read_rate_limit_retries_but_write_does_not(store):
    seed(store)
    calls=[]
    async def no_sleep(_): pass
    def handler(req):
        calls.append(1)
        return httpx.Response(200,json={"error":{"error_code":6}})
    client=VKClient(store,httpx.MockTransport(handler),no_sleep)
    for write,expected in ((False,3),(True,1)):
        calls.clear()
        with pytest.raises(VKError): await client.call("alice","group",{"method":"wall.post","token_types":["group"]},{},write=write)
        assert len(calls)==expected


async def test_replaced_connection_invalidates_pending_action(settings,store):
    seed(store)
    service=Service(settings,store)
    pending=service.prepare("alice","group","wall.post",{"message":"hello"})
    value=store.action("alice",pending["action_id"])
    store.put_connection("alice","group","group","replaced-secret")
    with pytest.raises(PolicyError): await service.approve("alice",value["id"],value["digest"])
    assert store.action("alice",value["id"])["state"]=="failed_or_unknown"


async def test_jwt_rejects_wrong_issuer_audience_scope_expiry(settings):
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    verifier=Verifier(settings)
    verifier.keys=SimpleNamespace(get_signing_key_from_jwt=lambda _:SimpleNamespace(key=key.public_key()))
    claims={"iss":settings.issuer,"aud":settings.resource,"sub":"alice","iat":int(time.time()),"exp":int(time.time())+600,"scope":"vk-mcp","azp":"client"}
    assert (await verifier.verify_token(jwt.encode(claims,key,algorithm="RS256"))).subject
    for change in ({"iss":"https://attacker.invalid"},{"aud":"another-server"},{"scope":"openid"},{"exp":1},{"sub":""}):
        assert await verifier.verify_token(jwt.encode(claims|change,key,algorithm="RS256")) is None
    assert await verifier.verify_token("alice") is None
    assert await verifier.verify_token(jwt.encode(claims,"hmac-key-that-is-long-enough-for-HS256",algorithm="HS256")) is None


def cookie(settings,sid):
    value=b64encode(json.dumps({"sid":sid}).encode())
    return TimestampSigner(settings.cookie_secret).sign(value).decode()


def test_browser_csrf_and_owner_isolation(settings,store):
    seed(store)
    app=create_app(settings,store=store)
    sid=store.new_session("alice")
    with TestClient(app,base_url=settings.public_url) as client:
        client.cookies.set("vk_session",cookie(settings,sid))
        assert client.get("/account").status_code==200
        response=client.post("/account",data={"alias":"leak","kind":"group","token":"secret"},headers={"Origin":settings.public_url})
        assert response.status_code==400
        assert not any(r["alias"]=="leak" for r in store.connections("alice"))
        csrf=store.session(sid)["csrf"]
        response=client.post("/account",data={"csrf":csrf,"alias":"leak","kind":"group","token":"secret"},headers={"Origin":"https://attacker.invalid"})
        assert response.status_code==400
        other,digest=store.prepare("bob",{"method":"wall.post","alias":"group","params":{},"revision":"x"})
        assert client.get("/actions/"+other).status_code==400
        assert client.get("/health").headers["x-frame-options"]=="DENY"


def test_body_limit_and_host_validation(settings,store):
    app=create_app(settings,store=store)
    with TestClient(app,base_url=settings.public_url) as client:
        assert client.post("/mcp",content=b"x"*1_048_577).status_code==413
        assert client.get("/health",headers={"Host":"attacker.invalid"}).status_code==400


def test_mcp_protocol_authentication_and_tools(settings,store):
    class FakeVerifier:
        async def verify_token(self,token):
            if token!="alice-access": return None
            return AccessToken(token=token,client_id="test",scopes=[settings.scope],subject="alice",resource=settings.resource,expires_at=int(time.time())+60)
    app=create_app(settings,store=store,verifier=FakeVerifier())
    with TestClient(app,base_url=settings.public_url) as client:
        headers={"Accept":"application/json, text/event-stream","Content-Type":"application/json"}
        init={"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}
        denied=client.post("/mcp",json=init,headers=headers)
        assert denied.status_code==401
        assert "resource_metadata" in denied.headers["www-authenticate"]
        metadata=client.get("/.well-known/oauth-protected-resource/mcp").json()
        assert metadata["resource"]==settings.resource
        headers["Authorization"]="Bearer alice-access"
        result=client.post("/mcp",json=init,headers=headers)
        assert result.status_code==200, result.text
        assert result.json()["result"]["serverInfo"]["name"]=="mcp-vkontakte"
        tools=client.post("/mcp",json={"jsonrpc":"2.0","id":2,"method":"tools/list"},headers=headers).json()["result"]["tools"]
        names={t["name"] for t in tools}
        assert names=={"search_methods","describe_method","list_connections","call_read","prepare_action","action_status","community_snapshot","compare_communities"}
        assert not any("execute" in name or "confirm" in name for name in names)
        result=client.post("/mcp",json={"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"search_methods","arguments":{"query":"wall.get"}}},headers=headers).json()
        assert not result["result"].get("isError"), result
