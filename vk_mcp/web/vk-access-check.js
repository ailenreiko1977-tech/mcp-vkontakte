/* The token lives only in this closure. Never log it, render it or persist it. */
(() => {
  'use strict';
  const appId = Number(document.getElementById('probe').dataset.appId);
  const status = document.getElementById('status');
  const authorize = document.getElementById('authorize');
  const copy = document.getElementById('copy');
  const results = document.getElementById('results');
  let token = null;
  let verified = false;
  let busy = false;
  const codeOf = (error) => {
    const value = error?.error_data?.error_code ?? error?.error_code;
    return /^\d{1,6}$/.test(String(value)) ? String(value) : 'не указан';
  };

  async function init() {
    if (window.parent === window || !window.vkBridge || !Number.isSafeInteger(appId) || appId <= 0) {
      status.textContent = 'Открой эту страницу через мини-приложение ВКонтакте. В обычной вкладке запрос пользовательского ключа недоступен.';
      return;
    }
    try {
      await window.vkBridge.send('VKWebAppInit');
      status.textContent = 'Приложение открыто в VK. Нажми кнопку, если согласна запросить разрешение «Сообщества» и проверить поиск.';
      authorize.disabled = false;
    } catch (error) {
      status.textContent = 'VK не подтвердил запуск приложения. Код: ' + codeOf(error) + '. Проверь адрес размещения приложения.';
    }
  }

  authorize.addEventListener('click', async () => {
    if (busy) return;
    busy = true;
    authorize.disabled = true;
    copy.disabled = true;
    token = null;
    verified = false;
    results.replaceChildren();
    let phase = 'получение пользовательского ключа';
    try {
      status.textContent = 'Ожидаем решение VK и твоё подтверждение разрешений.';
      const auth = await window.vkBridge.send('VKWebAppGetAuthToken', {app_id: appId, scope: 'groups'});
      if (typeof auth.access_token !== 'string' || !auth.access_token) throw new Error('No token');
      token = auth.access_token;
      phase = 'поиск сообществ';
      status.textContent = 'Ключ получен. Проверяем, разрешён ли поиск.';
      const answer = await window.vkBridge.send('VKWebAppCallAPIMethod', {
        method: 'groups.search', params: {access_token: token, v: '5.199', q: 'нейрокино', count: 3}
      });
      if (answer.error) throw answer.error;
      const data = answer.response;
      if (!data || !Array.isArray(data.items) || !Number.isFinite(data.count)) throw new Error('Unexpected result');
      for (const group of data.items) {
        const item = document.createElement('li');
        item.textContent = typeof group.name === 'string' ? group.name : 'Сообщество';
        results.appendChild(item);
      }
      verified = true;
      copy.disabled = false;
      status.textContent = 'Поиск внутри VK работает. Найдено сообществ: ' + data.count + '. Теперь можно скопировать ключ в свой кабинет для проверки с VPS.';
    } catch (error) {
      token = null;
      status.textContent = 'Проверка не пройдена. Этап: ' + phase + '. Код VK: ' + codeOf(error) + '. Дополнительный доступ пока не подтверждён; ключ не сохранён. Покажи этот результат для дальнейшей диагностики.';
    } finally {
      busy = false;
      authorize.disabled = false;
    }
  });

  copy.addEventListener('click', async () => {
    if (!verified || !token) return;
    try {
      await navigator.clipboard.writeText(token);
      status.textContent = 'Ключ скопирован. Вставь его только в защищённое поле своего кабинета. В чат отправлять не нужно.';
    } catch (error) {
      status.textContent = 'Браузер не разрешил копирование. Ключ не был отправлен на сервер. Сообщи об этом, не присылай сам ключ.';
    }
  });
  window.addEventListener('pagehide', () => { token = null; verified = false; });
  void init();
})();
