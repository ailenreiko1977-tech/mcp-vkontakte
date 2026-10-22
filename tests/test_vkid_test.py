from dataclasses import replace
from urllib.parse import parse_qs, urlsplit

import httpx
from starlette.testclient import TestClient

from vk_mcp.app import create_app
from test_security import cookie


def test_disabled_by_default(settings, store):
    with TestClient(create_app(settings, store=store), base_url=settings.public_url) as client:
        assert client.get('/vkid-test').status_code == 404


def test_owner_csrf_and_callback_binding(settings, store):
    settings = replace(settings, vkid_test_app_id=123, vkid_test_owner='alice')
    sid = store.new_session('alice')
    other = store.new_session('alice')
    with TestClient(create_app(settings, store=store), base_url=settings.public_url) as client:
        assert client.get('/vkid-test').status_code == 403
        client.cookies.clear()
        client.cookies.set('vk_session', cookie(settings, store.new_session('bob')))
        assert client.get('/vkid-test').status_code == 403
        client.cookies.clear()
        client.cookies.set('vk_session', cookie(settings, sid))
        assert client.post('/vkid-test', data={'csrf': store.session(sid)['csrf']}).status_code == 400
        assert client.post('/vkid-test', headers={'Origin': settings.public_url}).status_code == 400
        r = client.post('/vkid-test', data={'csrf': store.session(sid)['csrf']}, headers={'Origin': settings.public_url}, follow_redirects=False)
        q = parse_qs(urlsplit(r.headers['location']).query)
        assert q['scope'] == ['groups']
        assert q['code_challenge_method'] == ['S256'] and len(q['code_challenge'][0]) == 43
        client.cookies.clear()
        client.cookies.set('vk_session', cookie(settings, other))
        assert client.get('/vkid-test/callback', params={'state': q['state'][0]}).status_code == 400
        client.cookies.clear()
        client.cookies.set('vk_session', cookie(settings, sid))
        url = '/vkid-test/callback?' + 'state='+q['state'][0]+'&error=access_denied'
        r = client.get(url)
        assert 'access_denied' in r.text
        assert client.get(url).status_code == 400
        assert store.connections('alice') == []


def test_exchange_refresh_and_no_secrets_or_connection_changes(settings, store, monkeypatch):
    settings = replace(settings, vkid_test_app_id=123, vkid_test_owner='alice')
    sid = store.new_session('alice')
    store.put_connection('alice', 'existing', 'group', 'existing-token')
    calls = []
    real_client = httpx.AsyncClient

    def respond(request):
        calls.append(str(request.url))
        data = parse_qs(request.content.decode())
        if request.url.host == 'id.vk.com':
            if data['grant_type'] == ['authorization_code']:
                assert len(data['code_verifier'][0]) >= 43
                assert data['device_id'] == ['device-test']
                return httpx.Response(200, json={'access_token': 'secret-first', 'refresh_token': 'secret-renew', 'state': data['state'][0]})
            assert data['refresh_token'] == ['secret-renew']
            return httpx.Response(200, json={'access_token': 'secret-second', 'state': data['state'][0]})
        assert request.url.host == 'api.vk.com'
        if data['access_token'] == ['secret-first']:
            return httpx.Response(200, json={'response': {'count': 2}})
        return httpx.Response(200, json={'error': {'error_code': 15, 'error_msg': 'secret-second', 'request_params': data}})

    monkeypatch.setattr('vk_mcp.vkid_test.httpx.AsyncClient', lambda **kwargs: real_client(transport=httpx.MockTransport(respond), **kwargs))
    with TestClient(create_app(settings, store=store), base_url=settings.public_url) as client:
        client.cookies.set('vk_session', cookie(settings, sid))
        r = client.post('/vkid-test', headers={'Origin': settings.public_url}, data={'csrf': store.session(sid)['csrf']}, follow_redirects=False)
        state = parse_qs(urlsplit(r.headers['location']).query)['state'][0]
        r = client.get('/vkid-test/callback', params={'state': state, 'code': 'code-test', 'device_id': 'device-test'})
        assert 'search_before_refresh' in r.text and 'search_after_refresh' in r.text
        assert 'vk_error_code' in r.text and '15' in r.text
        assert 'secret-first' not in r.text and 'secret-second' not in r.text and 'secret-renew' not in r.text
        assert len(calls) == 4
        assert all('secret-' not in url for url in calls)
        assert store.connections('alice') == [{'alias': 'existing', 'kind': 'group'}]
