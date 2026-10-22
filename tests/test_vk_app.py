from dataclasses import replace
from hashlib import sha256
from html.parser import HTMLParser
from starlette.testclient import TestClient
from vk_mcp.app import create_app


def test_bridge_page_enabled_only_with_explicit_app_id(settings,store):
    with TestClient(create_app(settings,store=store),base_url=settings.public_url) as client:
        response=client.get('/vk-app')
        assert response.status_code==404
        assert response.headers['x-frame-options']=='DENY'


def test_only_probe_page_can_be_framed_by_vk(settings,store):
    settings=replace(settings,vk_app_id=54845887)
    with TestClient(create_app(settings,store=store),base_url=settings.public_url) as client:
        response=client.get('/vk-app')
        assert response.status_code==200
        assert 'x-frame-options' not in response.headers
        csp=response.headers['content-security-policy']
        assert 'frame-ancestors https://vk.com https://vk.ru' in csp
        assert "connect-src 'none'" in csp
        assert "script-src 'self'" in csp
        assert "form-action 'none'" in csp
        assert client.get('/account',follow_redirects=False).headers['x-frame-options']=='DENY'
        assert client.get('/health').headers['x-frame-options']=='DENY'
        assert client.post('/vk-app',data={'token':'not-a-real-token'}).status_code in (404,405)


def test_app_identifier_and_bundled_assets(settings,store):
    class Main(HTMLParser):
        app_id=None
        def handle_starttag(self,tag,attrs):
            if tag=='main': self.app_id=dict(attrs).get('data-app-id')
    with TestClient(create_app(replace(settings,vk_app_id=54845887),store=store),base_url=settings.public_url) as client:
        parser=Main(); parser.feed(client.get('/vk-app').text)
        assert parser.app_id=='54845887'
        sdk=client.get('/vk-app/assets/bridge.js')
        assert sdk.status_code==200
        assert sha256(sdk.content).hexdigest()=='0cdf89612cf18f12d5f39be5e5ea0aad6d1760ddb3964f31effb251d679d8178'
        js=client.get('/vk-app/assets/check.js').text
        assert "scope: 'groups'" in js
        assert 'localStorage' not in js and 'sessionStorage' not in js
        assert 'fetch(' not in js and 'console.' not in js
