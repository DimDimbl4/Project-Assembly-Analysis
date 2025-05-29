# 🛠️ Get-ProjectAssemblyAnalysis.py

[![Python Version](https://img.shields.io/badge/python-3.6%2B-blue)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

---

## 📄 Описание

Скрипт для анализа использования файлов во время сборки программного обеспечения. Помогает выявить:

* Неиспользуемые исходные файлы
* Неиспользуемые бинарные файлы
* Другие типы файлов, которые можно удалить

Поддерживает несколько режимов работы:

1. Мониторинг файловых операций во время сборки
2. Анализ логов мониторинга
3. Классификация файлов по типам
4. Экспорт результатов в различных форматах

---

## ⚙️ Установка и требования

### Требования

* Python 3.6 и выше
* Зависимости:

```bash
pip install python-magic
```
* Для работы в Linux необходимо установить:

```bash
sudo apt install libmagic1
```

### Дополнительные инструменты (по платформе)

* **Windows:** Process Monitor (ProcMon)
* **Linux:** inotifywait, strace или auditd

---

## 🔧 Конфигурация

Скрипт использует JSON-файл конфигурации. Пример `config.json`:

```json
{
    "source_exts": [".c", ".cpp", ".h", ".py"],
    "binary_exts": [".exe", ".dll", ".so"],
    "source_keywords": ["#include", "def ", "class "],
    "procmon_filters": [
        "Operation is ReadFile",
        "Operation is WriteFile",
        "Operation is CreateFile"
    ],
    "ignore_patterns": [".git/*", "*.tmp", "__pycache__/*"]
}
```

---

## 🚀 Использование

### Основные команды

* Запуск мониторинга:

```bash
python Get-ProjectAssemblyAnalysis.py --target-dir /path/to/project --start-monitor
```

* Остановка мониторинга:

```bash
python Get-ProjectAssemblyAnalysis.py --stop-monitor
```

* Анализ логов:

```bash
python Get-ProjectAssemblyAnalysis.py --target-dir /path/to/project --log-file monitor.log
```

---

### Параметры

#### Общие

* `--target-dir` — директория проекта (обязательный параметр)
* `--config` — путь к конфигу (JSON)
* `--platform` — платформа (windows/linux), определяется автоматически
* `--verbose` — подробный вывод логов

#### Мониторинг

* `--start-monitor` — запустить мониторинг
* `--stop-monitor` — остановить мониторинг
* `--monitor-output` — файл для логов мониторинга
* `--linux-tool` — инструмент мониторинга для Linux (inotifywait/strace/auditd)
* `--auto-auditd` — автоматическая настройка auditd (требуются sudo-права)

#### Анализ

* `--log-file` — файл с логами для анализа
* `--output` — файл для результатов
* `--export-format` — формат вывода: `text` (по умолчанию), `json`, `csv`
* `--smart-classify` — расширенная классификация по содержимому файлов

---

## 📚 Примеры использования

### Windows — мониторинг и анализ

```bash
python Get-ProjectAssemblyAnalysis.py --target-dir C:\my_project --start-monitor --monitor-output build_monitor.pml
```

Выполнить сборку, затем:

```bash
python Get-ProjectAssemblyAnalysis.py --stop-monitor
```

Анализ:

```bash
python Get-ProjectAssemblyAnalysis.py --target-dir C:\my_project --log-file build_monitor.pml --output unused_files.json --export-format json
```

### Linux — мониторинг с inotifywait

```bash
python Get-ProjectAssemblyAnalysis.py --target-dir /home/user/project --start-monitor --linux-tool inotifywait --monitor-output build.log
```

После сборки:

```bash
python Get-ProjectAssemblyAnalysis.py --target-dir /home/user/project --log-file build.log --smart-classify --output report.txt
```

### Использование пользовательской конфигурации

```bash
python Get-ProjectAssemblyAnalysis.py --target-dir /path/to/project --config my_config.json --log-file build.log --output results.csv --export-format csv
```

---

## 📊 Интерпретация результатов

Файлы классифицируются на:

1. **source** — исходники (код, скрипты)
2. **binary** — бинарники (исполняемые файлы, библиотеки)
3. **other** — прочие файлы (документы, изображения и др.)
4. **ignored** — файлы, соответствующие паттернам игнорирования

---

## 🔍 Особенности

* **Классификация:**

  * Базовая — по расширениям (быстрее)
  * Расширенная (`--smart-classify`) — анализ содержимого (точнее)

* **Мониторинг:**

  * Windows: ProcMon
  * Linux: inotifywait / strace / auditd (надежность и нагрузка разные)

* **Форматы экспорта:** text, json, csv

---

## 💡 Советы

* Используйте `--smart-classify` для финального анализа крупных проектов
* На Linux для точности лучше auditd + `--auto-auditd`
* Для CI/CD лучше экспортировать в JSON или CSV
* Настраивайте конфиг под ваш проект (расширения, игнорирование)

---

## ⚠️ Обработка ошибок и безопасность

* Логи ошибок пишутся в `file_analyzer.log` (по умолчанию)
* `--verbose` выводит ошибки в консоль
* При использовании auditd и sudo — проверяйте доверие к скрипту и безопасность конфигурации

---

## 📞 Контакты и лицензия

Авторы:

Макаров Дмитрий — [GitHub](https://github.com/DimDimbl4)

Валентик Даниил

Анастасия Семянникова

Лицензия: MIT — смотрите файл LICENSE

---

> Скрипт поможет оптимизировать структуру проекта, выявить и удалить неиспользуемые файлы для облегчения поддержки и сборки.

---
