# Rafix License Server (Simple, без базы данных, без подпапок)

Промокоды/ключи хранятся прямо в файле `licenses.json`. Supabase не нужен.
Все файлы лежат в корне репозитория — без вложенных папок, чтобы не было
проблем при загрузке через веб-интерфейс GitHub.

## Эндпоинты

- `GET /` — проверка, что сервер жив.
- `POST /api/license/check` — body `{ "code": "ABC123" }`.
- `POST /api/license/register` — body `{ "code": "ABC123", "expires_at": "2026-12-31" }`.
  Требует заголовок `x-admin-secret`.

## Переменные окружения на Render

Нужна только одна:
- `ADMIN_SECRET` — любая длинная случайная строка (можно сгенерировать кнопкой Generate на Render).

## Важно про бесплатный план Render

На бесплатном тарифе файловая система сервиса не сохраняется постоянно — при
передеплое или долгом простое `licenses.json` может сброситься к значениям
из репозитория. Чтобы добавить новый код — редактируй `licenses.json` прямо
на GitHub и коммить изменения, Render сам передеплоит сервис.

## Деплой на Render

Root Directory: оставь пустым.
Build command: `npm install`
Start command: `npm start`

Environment Variables: только `ADMIN_SECRET`.
