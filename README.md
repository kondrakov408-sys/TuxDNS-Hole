# TuxDNS-Hole 🐧🛡️

**TuxDNS-Hole** — быстрый, легковесный и бескомпромиссно приватный локальный DNS-sinkhole демон на Go 1.22+ для Linux.

Разработан как минималистичная замена тяжеловесным решениям (Pi-hole, Blocky, AdGuard Home) без веб-интерфейсов и лишних зависимостей. Перехватывает DNS-запросы на `127.0.0.1:53`, блокирует телеметрию, трекеры и рекламу по спискам хостов (возвращая `0.0.0.0` / `::` или `NXDOMAIN`), а легитимные запросы перенаправляет в зашифрованные DoH (DNS-over-HTTPS) или стандартные upstream-резолверы.

---

## ⚡ Ключевые возможности

- **Высокая производительность:** Параллельная non-blocking обработка UDP и TCP на горутинах (`github.com/miekg/dns`).
- **Domain Trie & Hash Indexing:** Мгновенный поиск $O(1)$ по точным доменам и эффективное сопоставление wildcard-доменов (`*.telemetry.google.com`) через суффиксное дерево меток (Trie).
- **Поддержка Hosts-форматов:** Потоковый парсер стандартных `hosts`-файлов (`0.0.0.0 ad.com`, `127.0.0.1 ad.com`), AdBlock-списков и простых списков доменов.
- **DoH (DNS-over-HTTPS) & UDP Upstreams:** Встроенная поддержка RFC 8484 DoH через HTTP/2 с пулом соединений (Quad9, Cloudflare, Mullvad) + балансировка Round-Robin, Failover и Parallel.
- **In-Memory LRU Кэш:** Умный кэш с динамическим пересчетом DNS TTL ответов и защитой от кэширования ошибок.
- **OpSec & Zero-Log:** В режиме по умолчанию **никакие клиентские запросы и метаданные не пишутся на диск**. В debug-режиме факт блокировки выводится в stdout через структурированный `log/slog`.
- **Hot-Reload без простоя:** Автоматическое фоновое обновление списков по таймеру и мгновенная перезагрузка правил на лету по сигналу `SIGHUP` (через атомарный указатель `atomic.Pointer`).
- **Rootless безопасность:** Hardened systemd-юнит с `AmbientCapabilities=CAP_NET_BIND_SERVICE` для работы на порту 53 от непривилегированного пользователя.

---

## 📁 Структура проекта

```text
tuxdns-hole/
├── cmd/
│   └── tuxdnshole/
│       └── main.go              # Точка входа, обработка сигналов, CLI-флаги
├── internal/
│   ├── config/
│   │   └── config.go            # Конфигурация и валидация YAML
│   ├── dns/
│   │   ├── server.go            # Двойной слушатель UDP/TCP
│   │   ├── handler.go           # Маршрутизация запросов и Sinkhole-логика
│   │   ├── cache.go             # In-Memory LRU кэш с динамическим TTL
│   │   └── cache_test.go        # Тесты кэша
│   ├── filter/
│   │   ├── engine.go            # Фильтр-движок с DomainTrie и атомарными снимками
│   │   ├── loader.go            # Потоковый парсер hosts и HTTP-загрузчик
│   │   └── engine_test.go       # Тесты правил и wildcard
│   └── upstream/
│       ├── doh.go               # RFC 8484 DoH клиент (HTTP/2)
│       └── forwarder.go         # Пул апстримов (DoH/UDP) с балансировкой и failover
├── configs/
│   └── config.example.yaml      # Полный пример конфигурационного файла
├── systemd/
│   └── tuxdnshole.service       # Hardened systemd unit
├── Makefile                     # Сборка, тесты, установка
├── go.mod
└── README.md
```

---

## 🚀 Быстрый старт

### 1. Требования
- Linux (x86_64, aarch64, armv7)
- Go 1.22+
- `make`

### 2. Сборка
```bash
git clone https://github.com/tuxdns/tuxdnshole.git
cd tuxdnshole
make build
```
Бинарный файл будет скомпилирован в `bin/tuxdnshole`.

### 3. Запуск тестов
```bash
make test
```

### 4. Тестовый запуск на нестандартном порту
Для проверки без прав суперпользователя:
1. Отредактируйте `configs/config.example.yaml`:
   ```yaml
   server:
     listen_addr: "127.0.0.1:1053"
   ```
2. Запустите:
   ```bash
   make run
   ```
3. В другом терминале проверьте резолвинг через `dig`:
   ```bash
   # Проверка блокировки
   dig @127.0.0.1 -p 1053 telemetry.google.com A
   # Должен вернуть 0.0.0.0

   # Проверка легитимного домена
   dig @127.0.0.1 -p 1053 example.com A
   # Должен вернуть реальный IP через DoH upstream
   ```

---

## 🛠️ Установка в систему (Systemd)

### 1. Установка бинарника и конфигурации
```bash
sudo make install
```
- Бинарник устанавливается в `/usr/local/bin/tuxdnshole`.
- Конфигурация размещается в `/etc/tuxdnshole/config.yaml`.

### 2. Установка и запуск службы systemd
```bash
sudo make service
```

Проверка статуса службы:
```bash
systemctl status tuxdnshole
```

---

## ⚙️ Настройка coexistence с `systemd-resolved`

Если на вашей системе порт `53` занят `systemd-resolved`, освободите его:

1. Отредактируйте `/etc/systemd/resolved.conf`:
   ```ini
   [Resolve]
   DNSStubListener=no
   ```
2. Перезапустите `systemd-resolved`:
   ```bash
   sudo systemctl restart systemd-resolved
   ```
3. Укажите `127.0.0.1` в `/etc/resolv.conf`:
   ```bash
   nameserver 127.0.0.1
   options edns0 trust-ad
   ```

---

## 🔄 Сигналы и управление на лету

- **Перезагрузить списки фильтрации без остановки сервера (`SIGHUP`):**
  ```bash
  sudo systemctl reload tuxdnshole
  # или напрямую:
  sudo killall -HUP tuxdnshole
  ```
- **Проверить синтаксис конфига:**
  ```bash
  tuxdnshole -config /etc/tuxdnshole/config.yaml -test-config
  ```

---

## 📄 Лицензия

MIT License.
