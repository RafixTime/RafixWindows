RAFIX SERVER v2 — установка (все файлы в КОРНЕ репозитория, без папок)

Файлы для GitHub (репозиторий RafixTime/RafixWindows): server.js, package.json, admin.js, .gitignore, этот README.
Старые license.js, licenses.json и старый server.js можно удалить / заменить.

1) БАЗА ДАННЫХ (бесплатно): создай проект на neon.tech (или supabase.com) и скопируй строку подключения
   Postgres вида  postgresql://user:pass@host/db?sslmode=require
   Таблицы создаются автоматически при первом запуске.

2) RENDER -> сервис -> Environment. Добавь переменные из файла SECRETS_PRIVATE.txt:
   ADMIN_SECRET, TOKEN_PRIVATE_KEY, APP_MASTER_KEY, DATABASE_URL
   (старый ADMIN_SECRET замени на новый!). Необязательно: MAX_DEVICES (по умолчанию 2 устройства на аккаунт).
   Build Command: npm install     Start Command: npm start
   !!! APP_MASTER_KEY и TOKEN_PRIVATE_KEY не менять после запуска: иначе сохранённые приложения не расшифруются,
       а все токены станут недействительными. Сохрани SECRETS_PRIVATE.txt в надёжном месте.

3) ЗАГРУЗИ ПРИЛОЖЕНИЯ на сервер (на своём компьютере, нужен Node.js 18+):
   set ADMIN_SECRET=<твой ADMIN_SECRET>
   node admin.js upload RafixLauncher PLUS build\RafixLauncher.jar
   node admin.js upload RafixMusic PLUS build\RafixMusic.jar
   (jar берутся из папки build после Install.bat / build.bat. Их НЕ распространяй.)

4) ПРОМОКОДЫ:
   node admin.js codes PLUS MONTH 10      -> 10 кодов Premium+ на месяц
   node admin.js codes PREMIUM YEAR 3     -> 3 кода Premium на год
   Сроки: HOUR DAY WEEK MONTH YEAR FOREVER. В базе хранятся только хэши, код виден один раз — сохрани его.
   node admin.js grant ник PLUS MONTH     -> выдать подписку напрямую (NONE — забрать)
   node admin.js ban ник | unban ник | resetdevices ник

Как это защищает:
 - аккаунты, пароли (scrypt), подписки и коды — только в БД на сервере;
 - приложения хранятся в БД зашифрованными (AES-256-GCM) и отдаются ТОЛЬКО при действующей подписке
   (проверка по БД), каждый раз с новым ключом; в RafixWindows.exe их нет и на диск они не пишутся;
 - токен сессии подписан Ed25519; подделать подписку в клиенте нельзя;
 - лимит попыток входа, привязка к устройству, коды гасятся атомарно на сервере.
Без интернета: вход по уже сохранённой сессии работает, но активация промокода и запуск Premium+ приложений — нет.
Старые промокоды (codes.dat) больше не работают — сгенерируй новые командой выше.
