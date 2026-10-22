"""Opt-in owner-only VK ID diagnostic. Credentials live only during one callback."""
import base64
import hashlib
import html
import json
import re
import secrets
import time
from urllib.parse import urlencode

import httpx
from starlette.responses import RedirectResponse
from starlette.routing import Route


def routes(settings, store, browser_session, guard, page):
    if not settings.vkid_test_app_id or not settings.vkid_test_owner:
        return []
    pending = {}
    results = {}
    root = "/vkid-test"
    redirect = settings.public_url + root + "/callback"

    def authorized(request):
        session = browser_session(request)
        if session and secrets.compare_digest(session["owner"], settings.vkid_test_owner):
            return session
        return None

    def prune():
        now = time.time()
        for mapping in (pending, results):
            for key in list(mapping):
                if mapping[key]["expires"] < now:
                    del mapping[key]

    def error_code(body):
        # Never display provider descriptions or request parameters: they may echo secrets.
        value = str(body.get("error", "invalid_response"))
        return value if re.fullmatch(r"[a-zA-Z0-9_]{1,64}", value) else "provider_error"

    async def token_request(client, data):
        state = secrets.token_urlsafe(32)
        response = await client.post("https://id.vk.com/oauth2/auth", data={
            "client_id": str(settings.vkid_test_app_id), "redirect_uri": redirect,
            "state": state, **data,
        })
        body = response.json()
        if not isinstance(body, dict):
            return None, "invalid_response"
        if response.status_code != 200 or "error" in body:
            return None, error_code(body)
        if not isinstance(body.get("state"), str) or not secrets.compare_digest(body["state"], state):
            return None, "state_mismatch"
        token = body.get("access_token")
        if not isinstance(token, str) or not 1 <= len(token) <= 8192:
            return None, "missing_access_token"
        return body, None

    async def search(client, token):
        response = await client.post("https://api.vk.com/method/groups.search", data={
            "access_token": token, "v": "5.199", "q": "нейрокино", "count": "3",
        })
        if response.status_code != 200:
            return {"ok": False, "http_status": response.status_code}
        body = response.json()
        if isinstance(body, dict) and isinstance(body.get("error"), dict):
            code = body["error"].get("error_code")
            return {"ok": False, "vk_error_code": code if type(code) is int else None}
        value = body.get("response") if isinstance(body, dict) else None
        if isinstance(value, dict) and type(value.get("count")) is int:
            return {"ok": True, "matches": value["count"]}
        return {"ok": False, "error": "invalid_response"}

    async def index(request):
        prune()
        session = authorized(request)
        if not session:
            return page("Проверка VK ID", "<p>Сначала <a href='/account'>войти в кабинет</a> под учётной записью владельца, затем вернуться по этому адресу.</p>", 403)
        if request.method == "POST":
            await guard(request, session)
            if len(pending) >= 3:
                return page("Проверка VK ID", "<p>Проверка уже начата. Заверши её или повтори через 10 минут.</p>", 429)
            state = secrets.token_urlsafe(32)
            verifier = secrets.token_urlsafe(48)
            challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
            pending[state] = {"expires": time.time()+600, "sid": request.session["sid"], "verifier": verifier}
            return RedirectResponse("https://id.vk.com/authorize?"+urlencode({
                "response_type": "code", "client_id": settings.vkid_test_app_id,
                "redirect_uri": redirect, "scope": "groups", "state": state,
                "code_challenge": challenge, "code_challenge_method": "S256",
            }), status_code=303)
        body = ("<p>Разовая проверка: вход через VK ID с разрешением «Сообщества», поиск с VPS, "
                "обновление ключа и повторный поиск. Ничего в VK не публикуется.</p>"
                "<p>Тестовые ключи обрабатываются на сервере только во время проверки, "
                "не сохраняются как подключения и не выводятся на страницу. Твои действующие подключения не меняются.</p>")
        result = results.get(request.session["sid"])
        if result:
            body += "<h2>Результат</h2><pre>"+html.escape(json.dumps(result["value"], ensure_ascii=False, indent=2))+"</pre>"
            body += "<p>Успешное обновление в этом тесте не гарантирует бессрочный доступ или работу после отзыва разрешения.</p>"
        body += "<form method='post'><input type='hidden' name='csrf' value='"+html.escape(session["csrf"], quote=True)+"'><button>Войти через VK ID и выполнить тест</button></form>"
        return page("Проверка VK ID", body)

    async def callback(request):
        prune()
        session = authorized(request)
        state = request.query_params.get("state", "")
        item = pending.get(state)
        if not session or not item or not secrets.compare_digest(item["sid"], request.session["sid"]):
            return page("Проверка VK ID", "<p>Проверка истекла или открыта в другом браузере. Вернись на страницу теста и начни заново.</p>", 400)
        del pending[state]
        result = {}
        try:
            if "error" in request.query_params:
                result = {"stage": "authorization", "error": error_code(request.query_params)}
            else:
                code = request.query_params.get("code", "")
                device = request.query_params.get("device_id", "")
                if not code or not device or len(code) > 8192 or len(device) > 1024:
                    result = {"stage": "authorization", "error": "missing_code_or_device"}
                else:
                    async with httpx.AsyncClient(timeout=20, trust_env=False, follow_redirects=False) as client:
                        tokens, error = await token_request(client, {
                            "grant_type": "authorization_code", "code": code,
                            "device_id": device, "code_verifier": item["verifier"],
                        })
                        if error:
                            result = {"stage": "code_exchange", "error": error}
                        else:
                            result["search_before_refresh"] = await search(client, tokens["access_token"])
                            result["refresh_token_received"] = isinstance(tokens.get("refresh_token"), str) and bool(tokens["refresh_token"])
                            if result["refresh_token_received"]:
                                refreshed, error = await token_request(client, {
                                    "grant_type": "refresh_token", "refresh_token": tokens["refresh_token"], "device_id": device,
                                })
                                result["refresh"] = {"ok": error is None}
                                if error:
                                    result["refresh"]["error"] = error
                                else:
                                    result["search_after_refresh"] = await search(client, refreshed["access_token"])
                                refreshed = None
                        tokens = None
        except Exception:
            # httpx errors and provider bodies must never appear in logs or HTML.
            result = {"stage": "network_or_provider_response", "error": "test_incomplete"}
        results[request.session["sid"]] = {"expires": time.time()+600, "value": result}
        return RedirectResponse(root, status_code=303)

    return [Route(root, index, methods=["GET", "POST"]), Route(root+"/callback", callback)]
