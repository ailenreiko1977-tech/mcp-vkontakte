import asyncio
import json
import time
from urllib.parse import parse_qs
import httpx
import pytest
from mcp.server.auth.provider import AccessToken
from starlette.testclient import TestClient

from vk_mcp.app import create_app
from vk_mcp.catalog import Catalog, PolicyError
from vk_mcp.service import Service
from vk_mcp.vk import VKClient
from test_security import cookie


def test_human_approval_executes_exact_request_once(settings,store):
    store.put_connection("alice","own-community","group","fake-group-token")
    calls=[]
    def handler(request):
        calls.append(parse_qs(request.content.decode()))
        return httpx.Response(200,json={"response":{"post_id":7}})
    service=Service(settings,store,VKClient(store,httpx.MockTransport(handler)))
    pending=service.prepare("alice","own-community","wall.post",{"owner_id":-123,"message":"Approved text"})
    assert calls==[]
    action=store.action("alice",pending["action_id"])
    sid=store.new_session("alice")
    csrf=store.session(sid)["csrf"]
    app=create_app(settings,store=store,service=service)
    with TestClient(app,base_url=settings.public_url) as client:
        client.cookies.set("vk_session",cookie(settings,sid))
        url="/actions/"+pending["action_id"]
        page=client.get(url)
        assert page.status_code==200 and "Approved text" in page.text
        assert "fake-group-token" not in page.text
        assert calls==[]
        form={"csrf":csrf,"digest":action["digest"],"approve":"yes"}
        response=client.post(url,data=form,headers={"Origin":settings.public_url})
        assert response.status_code==200
        assert len(calls)==1
        assert calls[0]["message"]==["Approved text"]
        assert calls[0]["owner_id"]==["-123"]
        assert client.post(url,data=form,headers={"Origin":settings.public_url}).status_code==400
        assert len(calls)==1
        assert store.action("alice",action["id"])["state"]=="completed"


def test_mcp_requests_cannot_reuse_another_users_identity(settings,store):
    store.put_connection("alice","alice-only","user","fake-alice")
    store.put_connection("bob","bob-only","user","fake-bob")
    class Verifier:
        async def verify_token(self,token):
            if token not in ("alice","bob"): return None
            return AccessToken(token=token,client_id="test",scopes=[settings.scope],subject=token,resource=settings.resource,expires_at=int(time.time())+60)
    with TestClient(create_app(settings,store=store,verifier=Verifier()),base_url=settings.public_url) as client:
        for who in ("alice","bob","alice"):
            result=client.post("/mcp",headers={"Accept":"application/json, text/event-stream","Authorization":"Bearer "+who},
                json={"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_connections","arguments":{}}}).json()
            text=json.dumps(result)
            assert who+"-only" in text
            assert ("bob" if who=="alice" else "alice")+"-only" not in text


async def test_snapshot_uses_one_window_and_reports_partial_coverage(settings,store):
    store.put_connection("alice","public","service","fake-service")
    requests=[]
    def handler(request):
        requests.append(str(request.url))
        if str(request.url).endswith("groups.getById"):
            return httpx.Response(200,json={"response":{"groups":[{"id":123,"name":"Forest","members_count":100}]}})
        return httpx.Response(200,json={"response":{"count":500,"items":[{"id":i,"owner_id":-123,"date":100,"text":"Post","likes":{"count":i}} for i in range(100)]}})
    service=Service(settings,store,VKClient(store,httpx.MockTransport(handler)))
    sample=await service.snapshot("alice","public",123,50,150,max_pages=1)
    assert len(sample["posts"])==100
    assert sample["coverage"].startswith("partial")
    assert len(requests)==2


def test_generated_catalog_schemas_are_valid():
    from jsonschema import Draft202012Validator
    catalog=Catalog()
    assert len(catalog.methods)==434
    for entry in catalog.methods.values():
        Draft202012Validator.check_schema(entry["schema"])
        assert not {"access_token","v","sig","client_secret"}.intersection(entry["schema"]["properties"])


def test_service_key_cannot_prepare_changes(settings,store):
    store.put_connection("alice","public","service","fake-service")
    with pytest.raises(PolicyError): Service(settings,store).prepare("alice","public","wall.post",{"message":"no"})


def test_rate_limit_and_logout(store):
    store.rate_limit("alice",1)
    with pytest.raises(PolicyError): store.rate_limit("alice",1)
    sid=store.new_session("alice")
    assert store.session(sid)
    store.logout(sid)
    assert store.session(sid) is None
