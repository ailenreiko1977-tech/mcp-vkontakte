"""Browser-only VK Bridge access probe. Never accepts or stores tokens on the server."""
from pathlib import Path
from starlette.responses import HTMLResponse, Response
from starlette.routing import Route

WEB=Path(__file__).with_name("web")

def routes(settings):
    async def index(request):
        if not settings.vk_app_id:
            return HTMLResponse("VK mini app access check is not configured",status_code=404)
        return HTMLResponse("""<!doctype html><html lang="ru"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Проверка поиска сообществ VK</title>
<style>body{font:18px/1.55 system-ui;max-width:760px;margin:32px auto;padding:0 20px;background:#f6f8f5;color:#18312a}button{font:inherit;padding:12px 18px;margin:10px 0;cursor:pointer}button:disabled{cursor:default;opacity:.5}#status{padding:16px;background:white;border-radius:12px}small{display:block;margin:14px 0}li{margin:10px 0}</style>
<main id="probe" data-app-id='"""+str(settings.vk_app_id)+"""'>
<h1>Проверка поиска сообществ VK</h1>
<p>Эта страница проверяет, разрешает ли VK нашему приложению искать сообщества от твоего имени.</p>
<p>По кнопке VK запросит разрешение «Сообщества». Затем будет выполнен один поиск по слову «нейрокино». Этот тест ничего не публикует и не меняет в VK.</p>
<p id="status" role="status">Открой приложение внутри ВКонтакте, чтобы начать.</p>
<button id="authorize" type="button" disabled>Разрешить доступ и проверить поиск</button>
<ul id="results"></ul>
<button id="copy" type="button" disabled>Скопировать проверенный ключ</button>
<small>Ключ остаётся в памяти этой страницы. Мы не отправляем его на наш сервер и не сохраняем в браузере. После обновления страницы он исчезнет. Копирование выполняется только по твоему нажатию.</small>
<p>Если поиск пройдёт, добавь ключ в кабинете как новое подключение <strong>vk_user</strong> с типом «Пользовательский токен API». Затем отдельно проверим, работает ли он с VPS. Успех проверки внутри VK этого ещё не гарантирует.</p>
<p><a href="/account" target="_blank" rel="noopener noreferrer">Открыть мой кабинет</a></p>
</main>
<script src="/vk-app/assets/bridge.js" defer></script><script src="/vk-app/assets/check.js" defer></script></html>""")

    async def bridge(request):
        return Response(WEB.joinpath("vk-bridge-2.15.0.min.js").read_bytes(),media_type="application/javascript")

    async def check(request):
        return Response(WEB.joinpath("vk-access-check.js").read_bytes(),media_type="application/javascript")

    return [Route("/vk-app",index),Route("/vk-app/assets/bridge.js",bridge),Route("/vk-app/assets/check.js",check)]
