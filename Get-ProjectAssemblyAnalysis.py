#!/usr/bin/env python3
# ============================== ИМПОРТЫ ==================================
import argparse
import csv
import json
import os
import platform
import re
import subprocess
import sys
import signal
from abc import ABC, abstractmethod
from collections import defaultdict
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import (Dict, List, Set, Optional, Literal, TypedDict, Union,
                    DefaultDict)
import mimetypes
import magic
import logging
import fnmatch
from enum import Enum, auto
import io
import time

# ============================== ТИПЫ ДАННЫХ ==================================
FileType = Literal["source", "binary", "other", "ignored"]
FileClassification = Dict[FileType, List[str]]

class PlatformType(Enum):
    WINDOWS = auto()
    LINUX = auto()

class MonitoringToolType(Enum):
    PROCMON = auto()
    INOTIFYWAIT = auto()
    STRACE = auto()
    AUDITD = auto()

class AnalysisResults(TypedDict):
    source: List[str]
    binary: List[str]
    other: List[str]
    ignored: List[str]

# ============================== КОНФИГУРАЦИЯ ================================
class Config:
    DEFAULT_CONFIG = {
        "source_exts": ['.c', '.cpp', '.h', '.hpp', '.py', '.java', '.cs', 
                       '.js', '.go', '.rs', '.swift', '.m', '.sh'],
        "binary_exts": ['.exe', '.dll', '.so', '.a', '.lib', '.dylib', 
                       '.bin', '.elf'],
        "source_keywords": [
            "#include", "import ", "def ", "class ", "function ",
            "main(", "int main", "public ", "private "
        ],
        "ignore_patterns": [
            '.git/*', '*.swp', '*.bak', '*.tmp', '*.o', '*.obj',
            '__pycache__/*', '*.pyc', '*.pyo', '*.pyd',
            'node_modules/*', '*.log', '*.tlog'
        ]
    }

    def __init__(self, config_path: Optional[str] = None):
        self.config = self.DEFAULT_CONFIG.copy()
        if config_path and os.path.exists(config_path):
            self._load_config(config_path)

    def _load_config(self, config_path: str):
        try:
            with open(config_path) as f:
                user_config = json.load(f)
                self.config.update(user_config)
        except Exception as e:
            logging.warning(f"Failed to load config: {e}. Using defaults")

    @property
    def SOURCE_EXTS(self) -> Set[str]:
        return set(self.config["source_exts"])

    @property
    def BINARY_EXTS(self) -> Set[str]:
        return set(self.config["binary_exts"])

    @property
    def SOURCE_KEYWORDS(self) -> Set[bytes]:
        return {kw.encode('utf-8') for kw in self.config["source_keywords"]}

    @property
    def IGNORE_PATTERNS(self) -> Set[str]:
        return set(self.config["ignore_patterns"])

# ============================== ЛОГГИНГ =====================================
def setup_logging(verbose: bool = False, log_file: str = "file_analyzer.log"):
    level = logging.DEBUG if verbose else logging.INFO
    handlers = [logging.StreamHandler()]
    
    if log_file:
        file_handler = RotatingFileHandler(
            log_file, maxBytes=1_000_000, backupCount=3
        )
        handlers.append(file_handler)
    
    logging.basicConfig(
        format='%(asctime)s - %(levelname)s - %(message)s',
        level=level,
        handlers=handlers
    )

# ============================== КЛАССИФИКАЦИЯ ФАЙЛОВ ========================
class FileClassifier:
    def __init__(self, config: Config):
        self.config = config

    def should_ignore(self, filepath: str) -> bool:
        """Проверка, нужно ли игнорировать файл"""
        rel_path = os.path.relpath(filepath)
        return any(
            fnmatch.fnmatch(rel_path, pattern)
            for pattern in self.config.IGNORE_PATTERNS
        )

    def classify_by_extension(self, filepath: str) -> FileType:
        """Классификация только по расширению"""
        if self.should_ignore(filepath):
            return "ignored"
            
        ext = os.path.splitext(filepath)[1].lower()
        if ext in self.config.SOURCE_EXTS:
            return "source"
        if ext in self.config.BINARY_EXTS:
            return "binary"
        return "other"

    def classify_by_content(self, filepath: str) -> FileType:
        """Улучшенная классификация с анализом содержимого"""
        if self.should_ignore(filepath):
            return "ignored"
            
        try:
            with open(filepath, 'rb') as f:
                header = f.read(1024)
                
                # Проверка бинарных сигнатур
                if self._is_binary(header):
                    return "binary"
                
                # Проверка исходников по ключевым словам
                if self._is_source(header):
                    return "source"
                
                # Проверка MIME-типа
                mime = magic.from_file(filepath, mime=True)
                if mime.startswith('text/') or 'script' in mime:
                    return "source"
                if mime in ('application/x-executable', 'application/x-sharedlib'):
                    return "binary"

        except Exception as e:
            logging.warning(f"Error classifying {filepath}: {str(e)}")
        
        return self.classify_by_extension(filepath)

    def _is_binary(self, header: bytes) -> bool:
        """Определяет бинарные файлы по сигнатурам"""
        binary_signatures = [
            b'\x7fELF',  # ELF
            b'MZ',       # PE (Windows)
            b'\xfe\xed\xfa\xce',  # Mach-O
            b'\xcf\xfa\xed\xfe'   # Mach-O (64-bit)
        ]
        return any(header.startswith(sig) for sig in binary_signatures)

    def _is_source(self, header: bytes) -> bool:
        """Определяет исходные файлы по ключевым словам"""
        try:
            text_sample = header.decode('utf-8', errors='ignore').lower()
            return any(
                keyword.decode('utf-8').lower() in text_sample
                for keyword in self.config.SOURCE_KEYWORDS
            )
        except UnicodeDecodeError:
            return False

# ============================== МОНИТОРИНГ ==================================
class MonitoringTool(ABC):
    def __init__(self, config: Config):
        self.config = config
        self.process: Optional[subprocess.Popen] = None
        self.log_file: Optional[io.TextIOWrapper] = None

    @abstractmethod
    def start(self, target_dir: str, output_file: str) -> None:
        pass

    @abstractmethod
    def stop(self) -> None:
        pass

    def is_running(self) -> bool:
        return self.process is not None and self.process.poll() is None

class ProcMonTool(MonitoringTool):
    def __init__(self, config: Config, procmon_config: Optional[str] = None):
        super().__init__(config)
        self.procmon_config = procmon_config
        self.lock_file_path = "procmon.lock"
        self._process_info = {}  # Будем хранить информацию о процессе

    def start(self, target_dir: str, output_file: str) -> None:
        try:
            # Сохраняем информацию о процессе для последующей остановки
            self._process_info = {
                'output_file': output_file,
                'target_dir': target_dir,
                'start_time': time.time()
            }

            # Создаем lock-файл с полной информацией
            with open(self.lock_file_path, 'w') as lock_file:
                json.dump({
                    'pid': os.getpid(),
                    'process_info': self._process_info,
                    'procmon_config': self.procmon_config
                }, lock_file)

            cmd = [
                "procmon.exe",
                "/AcceptEula",
                "/Quiet",
                "/Minimized",
                "/BackingFile", output_file,
            ]
            
            if self.procmon_config:
                cmd.extend(["/LoadConfig", self.procmon_config])
            
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP
            )
            
            # Обновляем информацию о PID Procmon
            self._process_info['procmon_pid'] = self.process.pid
            self._update_lock_file()
            
            logging.info(f"ProcMon started with PID {self.process.pid}")
        except Exception as e:
            self._cleanup_resources()
            raise

    def _update_lock_file(self):
        """Обновляет lock-файл текущей информацией о процессе"""
        if os.path.exists(self.lock_file_path):
            with open(self.lock_file_path, 'w') as lock_file:
                json.dump({
                    'pid': os.getpid(),
                    'procmon_pid': self._process_info.get('procmon_pid'),
                    'process_info': self._process_info,
                    'procmon_config': self.procmon_config
                }, lock_file)

    def _cleanup_resources(self):
        """Очищает ресурсы при ошибках"""
        if os.path.exists(self.lock_file_path):
            os.remove(self.lock_file_path)
        self._process_info = {}
        self.process = None

    def stop(self) -> None:
        if not os.path.exists(self.lock_file_path):
            logging.warning("No active Procmon monitoring session found")
            return

        try:
            # Загружаем информацию из lock-файла
            with open(self.lock_file_path) as f:
                lock_data = json.load(f)
                self._process_info = lock_data.get('process_info', {})
                procmon_pid = lock_data.get('procmon_pid')

            # 1. Штатное завершение
            try:
                subprocess.run(
                    ["procmon.exe", "/Terminate"],
                    timeout=30,
                    check=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE
                )
            except subprocess.TimeoutExpired:
                logging.warning("/Terminate timed out")
            except Exception as e:
                logging.warning(f"/Terminate failed: {e}")

            # 2. Принудительное завершение через taskkill если Procmon еще работает
            if self._is_procmon_running(procmon_pid):
                try:
                    subprocess.run(
                        ["taskkill", "/F", "/PID", str(procmon_pid), "/T"],
                        timeout=10,
                        check=True,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.PIPE
                    )
                    logging.info(f"Successfully killed Procmon process {procmon_pid}")
                except Exception as e:
                    logging.error(f"Failed to kill Procmon process: {e}")

            # 3. Очистка
            self._cleanup_resources()
            logging.info("Procmon monitoring stopped")
        except Exception as e:
            logging.error(f"Error stopping Procmon: {e}")
            raise

    def _is_procmon_running(self, pid: Optional[int] = None) -> bool:
        """Проверяет, работает ли Procmon"""
        try:
            result = subprocess.run(
                ["tasklist", "/FI", "IMAGENAME eq procmon.exe"],
                capture_output=True,
                text=True,
                timeout=3
            )
            if pid:
                return f"procmon.exe {pid}" in result.stdout
            return "procmon.exe" in result.stdout
        except Exception as e:
            logging.warning(f"Failed to check Procmon status: {e}")
            return False

class InotifyTool(MonitoringTool):
    def start(self, target_dir: str, output_file: str) -> None:
        try:
            self.log_file = open(output_file, 'wb')
            self.process = subprocess.Popen(
                [
                    "inotifywait",
                    "-m",  # monitor continuously
                    "-r",  # recursive
                    "-q",  # quiet mode
                    "--format", "%w%f",  # output format
                    target_dir
                ],
                stdout=self.log_file,
                stderr=subprocess.STDOUT,
                preexec_fn=os.setsid,
                close_fds=True
            )
            logging.info(f"inotifywait started. Logging to {output_file}")
        except Exception as e:
            if self.log_file:
                self.log_file.close()
            logging.error(f"Failed to start inotifywait: {e}")
            raise

    def stop(self) -> None:
        if self.is_running() and self.process:
            os.killpg(os.getpgid(self.process.pid), signal.SIGTERM)
            self.process.wait()
        if self.log_file:
            self.log_file.close()

class StraceTool(MonitoringTool):
    def start(self, target_dir: str, output_file: str) -> None:
        try:
            self.log_file = open(output_file, 'wb')
            self.process = subprocess.Popen(
                [
                    "strace",
                    "-f",  # follow forks
                    "-e", "trace=file",  # monitor file operations
                    "make"  # default build command
                ],
                stdout=self.log_file,
                stderr=subprocess.STDOUT,
                preexec_fn=os.setsid,
                close_fds=True,
                cwd=target_dir
            )
            logging.info(f"strace started. Logging to {output_file}")
        except Exception as e:
            if self.log_file:
                self.log_file.close()
            logging.error(f"Failed to start strace: {e}")
            raise

    def stop(self) -> None:
        if self.is_running() and self.process:
            os.killpg(os.getpgid(self.process.pid), signal.SIGTERM)
            self.process.wait()
        if self.log_file:
            self.log_file.close()

class AuditdTool(MonitoringTool):
    def start(self, target_dir: str, output_file: str) -> None:
        try:
            subprocess.run([
                "sudo", "auditctl",
                "-w", target_dir,
                "-p", "rwxa",
                "-k", "build_monitor"
            ], check=True)
            logging.info(f"auditd rules added for {target_dir}")
            logging.info(f"Logs will be written to {output_file}")
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to configure auditd: {e}")
            raise

    def stop(self) -> None:
        try:
            subprocess.run([
                "sudo", "auditctl",
                "-D", "-k", "build_monitor"
            ], check=True)
            logging.info("auditd rules removed")
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to remove auditd rules: {e}")

class MonitoringManager:
    def __init__(self, config: Config, procmon_config: Optional[str] = None):
        self.config = config
        self.tool: Optional[MonitoringTool] = None
        self.procmon_config = procmon_config
        self._current_tool_type: Optional[MonitoringToolType] = None

    def start_monitoring(
        self,
        platform_type: PlatformType,
        tool_type: MonitoringToolType,
        target_dir: str,
        output_file: str
    ) -> None:
        # Останавливаем предыдущий мониторинг если был
        if self.tool:
            self.stop_monitoring()

        tool_classes = {
            (PlatformType.WINDOWS, MonitoringToolType.PROCMON): lambda c: ProcMonTool(c, self.procmon_config),
            (PlatformType.LINUX, MonitoringToolType.INOTIFYWAIT): InotifyTool,
            (PlatformType.LINUX, MonitoringToolType.STRACE): StraceTool,
            (PlatformType.LINUX, MonitoringToolType.AUDITD): AuditdTool
        }
        
        tool_class = tool_classes.get((platform_type, tool_type))
        if not tool_class:
            raise ValueError(f"Unsupported tool {tool_type} for platform {platform_type}")
        
        self.tool = tool_class(self.config)
        self._current_tool_type = tool_type
        self.tool.start(target_dir, output_file)

    def stop_monitoring(self) -> None:
        if not self.tool:
            # Попробуем остановить Procmon по lock-файлу если это Windows
            if platform.system() == "Windows":
                if self._stop_procmon_by_lock():
                    return  # Выходим если остановили по lock-файлу
            else:
                logging.warning("No active monitoring tool to stop")
            return

        try:
            self.tool.stop()
        except Exception as e:
            logging.error(f"Error stopping monitoring tool: {e}")
        finally:
            self.tool = None
            self._current_tool_type = None

    def _stop_procmon_by_lock(self):
        """Специальная обработка для остановки Procmon по lock-файлу"""
        lock_file = "procmon.lock"
        if os.path.exists(lock_file):
            try:
                with open(lock_file) as f:
                    data = json.load(f)
                if data.get('procmon_pid'):
                    logging.info(f"Found orphaned Procmon process {data['procmon_pid']}, attempting to stop...")
                    temp_tool = ProcMonTool(self.config, data.get('procmon_config'))
                    
                    temp_tool.stop()
                    
                    # Выходим после успешной обработки
                    return True
            except Exception as e:
                logging.error(f"Error reading lock file: {e}")
                try:
                    os.remove(lock_file)
                except Exception as e:
                    logging.warning(f"Failed to remove corrupted lock file: {e}")
        
        logging.warning("No active monitoring to stop")
        return False

    def is_monitoring_active(self) -> bool:
        if self.tool and self.tool.is_running():
            return True
        
        # Специальная проверка для Procmon на Windows
        if platform.system() == "Windows":
            lock_file = "procmon.lock"
            if os.path.exists(lock_file):
                try:
                    with open(lock_file) as f:
                        data = json.load(f)
                        if data.get('procmon_pid'):
                            return True
                except:
                    pass
        return False

# ============================== АНАЛИЗ ЛОГОВ ================================
class LogParser:
    def __init__(self, config: Config, target_dir: str):
        self.config = config
        self.target_dir = os.path.normpath(target_dir).lower()

    def _is_file_in_target_dir(self, filepath: str) -> bool:
        """Проверяет, находится ли файл в целевой директории"""
        try:
            filepath = os.path.normpath(filepath).lower()
            return filepath.startswith(self.target_dir)
        except Exception:
            return False

    def _convert_pml_to_csv(self, pml_file: str, csv_file: str) -> None:
        """Конвертирует бинарный лог ProcMon (PML) в CSV"""
        try:
            subprocess.run([
                "procmon.exe",
                "/Quiet",
                "/Minimized",
                "/OpenLog", pml_file,
                "/SaveAs", csv_file
            ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            logging.info(f"Успешно конвертировал {pml_file} в {csv_file}")
        except subprocess.CalledProcessError as e:
            logging.error(f"Ошибка конвертации PML в CSV: {e}")
            raise
        except Exception as e:
            logging.error(f"Неожиданная ошибка при конвертации: {e}")
            raise

    def parse_procmon_log(self, log_path: str) -> Set[str]:
        """Парсит лог ProcMon (PML или CSV)"""
        used_files = set()
        
        # Если файл в формате PML, конвертируем в CSV
        if log_path.lower().endswith('.pml'):
            csv_path = os.path.splitext(log_path)[0] + '.csv'
            try:
                self._convert_pml_to_csv(log_path, csv_path)
                log_path = csv_path
            except Exception as e:
                logging.error(f"Не удалось конвертировать PML в CSV, анализ невозможен: {e}")
                return used_files
        
        try:
            with open(log_path, 'r', encoding='utf-8-sig') as f:
                # Читаем первые 2 строки для определения формата
                first_line = f.readline()
                second_line = f.readline()
                f.seek(0)
                
                # Проверяем наличие заголовков CSV
                if 'Process Name' in first_line and 'Operation' in first_line:
                    reader = csv.DictReader(f)
                    for row in reader:
                        if (row.get('Result') == 'SUCCESS' and 
                            row.get('Operation') in ('ReadFile', 'WriteFile', 'CreateFile') and
                            'Path' in row and 
                            self._is_file_in_target_dir(row['Path'])):
                            path = os.path.normpath(row['Path']).lower()
                            used_files.add(path)
                else:
                    logging.error("Неподдерживаемый формат файла. Ожидается CSV или PML.")
        except Exception as e:
            logging.error(f"Ошибка парсинга лога ProcMon: {e}")
        
        return used_files

    def parse_inotifywait_log(self, log_path: str) -> Set[str]:
        used_files = set()
        try:
            with open(log_path, 'r', encoding='utf-8') as f:
                for line in f:
                    path = line.strip()
                    if path and self._is_file_in_target_dir(path):
                        full_path = os.path.normpath(path).lower()
                        used_files.add(full_path)
        except Exception as e:
            logging.error(f"inotifywait log parsing failed: {e}")
        return used_files

    def parse_strace_log(self, log_path: str) -> Set[str]:
        used_files = set()
        # Строки strace могут выглядеть как:
        #   open("/path/file", O_RDONLY) = 3
        #   openat(AT_FDCWD, "/path/file", O_RDONLY) = 3
        # Регулярное выражение ниже извлекает путь из подобных вызовов,
        # учитывая опциональное "at" и возможные дополнительные параметры.
        open_re = re.compile(r'open(?:at)?\(.*?"([^"]+)"')
        try:
            with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    if 'ENOENT' not in line:
                        match = open_re.search(line)
                        if match:
                            path = os.path.normpath(match.group(1)).lower()
                            if self._is_file_in_target_dir(path):
                                used_files.add(path)
        except Exception as e:
            logging.error(f"strace log parsing failed: {e}")
        return used_files

    def parse_auditd_log(self, log_path: str) -> Set[str]:
        used_files = set()
        path_re = re.compile(r'name="([^"]+)"')
        try:
            with open(log_path, 'r', encoding='utf-8') as f:
                for line in f:
                    if 'type=PATH' in line and 'item=0' in line:
                        match = path_re.search(line)
                        if match:
                            path = os.path.normpath(match.group(1)).lower()
                            if self._is_file_in_target_dir(path):
                                used_files.add(path)
        except Exception as e:
            logging.error(f"auditd log parsing failed: {e}")
        return used_files

# ============================== ЭКСПОРТ РЕЗУЛЬТАТОВ ========================
class ResultExporter:
    @staticmethod
    def export_to_json(results: AnalysisResults, output_file: str) -> None:
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            logging.info(f"Results exported to JSON: {output_file}")
        except Exception as e:
            logging.error(f"Failed to export to JSON: {e}")
            raise

    @staticmethod
    def export_to_csv(results: AnalysisResults, output_file: str) -> None:
        try:
            with open(output_file, 'w', encoding='utf-8', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Type', 'File'])
                for file_type, files in results.items():
                    for file in files:
                        writer.writerow([file_type, file])
            logging.info(f"Results exported to CSV: {output_file}")
        except Exception as e:
            logging.error(f"Failed to export to CSV: {e}")
            raise

    @staticmethod
    def export_to_text(results: AnalysisResults, output_file: Optional[str] = None) -> None:
        output = []
        for file_type in ["source", "binary", "other", "ignored"]:
            if results.get(file_type):
                output.append(f"\n=== {file_type.upper()} ({len(results[file_type])}) ===")
                output.extend(results[file_type])

        result_text = "\n".join(output)
        
        if output_file:
            try:
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(result_text)
                logging.info(f"Results exported to text file: {output_file}")
            except Exception as e:
                logging.error(f"Failed to export to text file: {e}")
                raise
        else:
            print(result_text)

# ============================== ОСНОВНАЯ ЛОГИКА ============================
class FileUsageAnalyzer:
    def __init__(self, config: Optional[Config] = None, procmon_config: Optional[str] = None):
        self.config = config or Config()
        self.classifier = FileClassifier(self.config)
        self.monitoring_manager = MonitoringManager(self.config, procmon_config)

    def analyze_unused_files(
        self,
        target_dir: str,
        log_file: str,
        tool_type: MonitoringToolType,
        smart_classify: bool = False
    ) -> AnalysisResults:
        logging.info(f"Starting analysis of {target_dir} using {tool_type} log: {log_file}")
        
        # Инициализируем парсер с целевой директорией
        log_parser = LogParser(self.config, target_dir)
        
        # Парсинг лога
        parser_methods = {
            MonitoringToolType.PROCMON: log_parser.parse_procmon_log,
            MonitoringToolType.INOTIFYWAIT: log_parser.parse_inotifywait_log,
            MonitoringToolType.STRACE: log_parser.parse_strace_log,
            MonitoringToolType.AUDITD: log_parser.parse_auditd_log
        }
        
        used_files = parser_methods[tool_type](log_file)
        logging.info(f"Found {len(used_files)} used files in log")

        # Сбор всех файлов в целевой директории
        all_files = set()
        for root, _, files in os.walk(target_dir):
            for file in files:
                full_path = os.path.normpath(os.path.join(root, file)).lower()
                all_files.add(full_path)

        logging.info(f"Found {len(all_files)} files in target directory")

        # Классификация неиспользованных файлов
        unused_files = all_files - used_files
        classified: DefaultDict[str, List[str]] = defaultdict(list)
        
        classify_func = (
            self.classifier.classify_by_content 
            if smart_classify 
            else self.classifier.classify_by_extension
        )
        
        for file in unused_files:
            file_type = classify_func(file)
            classified[file_type].append(file)

        # Сортировка результатов
        for file_type in classified:
            classified[file_type].sort(key=lambda x: os.path.splitext(x)[1])

        logging.info(
            f"Analysis completed. Unused files by type: "
            f"{ {k: len(v) for k, v in classified.items()} }"
        )
        
        return {
            "source": classified.get("source", []),
            "binary": classified.get("binary", []),
            "other": classified.get("other", []),
            "ignored": classified.get("ignored", [])
        }

# ============================== CLI ИНТЕРФЕЙС ==============================
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="File Usage Analyzer for Build Processes",
        formatter_class=argparse.RawTextHelpFormatter
    )

    # Основные параметры
    parser.add_argument(
        "--target-dir",
        required=True,
        help="Directory with source files to analyze"
    )
    parser.add_argument(
        "--config",
        help="Path to custom config file (JSON format)"
    )
    parser.add_argument(
        "--platform",
        choices=["windows", "linux"],
        default="windows" if platform.system() == "Windows" else "linux",
        help="Target platform (auto-detected)"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging"
    )

    # Параметры мониторинга
    monitor_group = parser.add_argument_group("Monitoring options")
    monitor_group.add_argument(
        "--start-monitor",
        action="store_true",
        help="Start file monitoring"
    )
    monitor_group.add_argument(
        "--stop-monitor",
        action="store_true",
        help="Stop file monitoring"
    )
    monitor_group.add_argument(
        "--monitor-output",
        help="Path for monitoring log"
    )
    monitor_group.add_argument(
        "--linux-tool",
        choices=["inotifywait", "strace", "auditd"],
        default="inotifywait",
        help="Linux monitoring tool (default: inotifywait)"
    )
    monitor_group.add_argument(
        "--auto-auditd",
        action="store_true",
        help="Auto-configure auditd (requires sudo)"
    )
    monitor_group.add_argument(
        "--config-procmon",
        help="Path to ProcMon configuration file (PMC)"
    )

    # Параметры анализа
    analysis_group = parser.add_argument_group("Analysis options")
    analysis_group.add_argument(
        "--log-file",
        help="Existing log file to analyze"
    )
    analysis_group.add_argument(
        "--output",
        help="File to save results"
    )
    analysis_group.add_argument(
        "--export-format",
        choices=["text", "json", "csv"],
        default="text",
        help="Format for results export (default: text)"
    )
    analysis_group.add_argument(
        "--smart-classify",
        action="store_true",
        help="Use advanced file classification (slower but more accurate)"
    )

    return parser.parse_args()

def main():
    args = parse_args()
    setup_logging(args.verbose)
    
    try:
        config = Config(args.config) if args.config else Config()
        analyzer = FileUsageAnalyzer(config, args.config_procmon)
        
        platform_type = (
            PlatformType.WINDOWS 
            if args.platform == "windows" 
            else PlatformType.LINUX
        )

        # Режим мониторинга
        if args.start_monitor:
            tool_type = {
                "windows": MonitoringToolType.PROCMON,
                "inotifywait": MonitoringToolType.INOTIFYWAIT,
                "strace": MonitoringToolType.STRACE,
                "auditd": MonitoringToolType.AUDITD
            }.get(args.linux_tool if platform_type == PlatformType.LINUX else "windows")
            
            output_file = args.monitor_output or {
                MonitoringToolType.PROCMON: "procmon_log.pml",
                MonitoringToolType.INOTIFYWAIT: "inotifywait.log",
                MonitoringToolType.STRACE: "strace.log",
                MonitoringToolType.AUDITD: "/var/log/audit/audit.log"
            }[tool_type]
            
            analyzer.monitoring_manager.start_monitoring(
                platform_type,
                tool_type,
                args.target_dir,
                output_file
            )
            return

        # Остановка мониторинга
        if args.stop_monitor:
            analyzer.monitoring_manager.stop_monitoring()
            return

        # Режим анализа
        if args.log_file:
            tool_type = {
                "windows": MonitoringToolType.PROCMON,
                "inotifywait": MonitoringToolType.INOTIFYWAIT,
                "strace": MonitoringToolType.STRACE,
                "auditd": MonitoringToolType.AUDITD
            }.get(args.linux_tool if platform_type == PlatformType.LINUX else "windows")
            
            results = analyzer.analyze_unused_files(
                target_dir=args.target_dir,
                log_file=args.log_file,
                tool_type=tool_type,
                smart_classify=args.smart_classify
            )

            # Экспорт результатов
            if args.output:
                export_methods = {
                    "json": ResultExporter.export_to_json,
                    "csv": ResultExporter.export_to_csv,
                    "text": ResultExporter.export_to_text
                }
                export_methods[args.export_format](results, args.output)
            else:
                ResultExporter.export_to_text(results)

            # Статистика
            logging.info("\n=== SUMMARY ===")
            total_files = sum(len(files) for files in results.values())
            unused_files = sum(len(files) for files in results.values() if files)
            logging.info(f"Total files in directory: {total_files}")
            logging.info(f"Unused files detected: {unused_files}")
            for file_type, files in results.items():
                logging.info(f"- {file_type}: {len(files)}")
        else:
            logging.error("No action specified. Use --help for usage information.")
            sys.exit(1)

    except Exception as e:
        logging.error(f"Error: {str(e)}", exc_info=args.verbose)
        sys.exit(1)

if __name__ == "__main__":
    mimetypes.init()
    try:
        main()
    except KeyboardInterrupt:
        logging.info("\nScript interrupted by user")
        sys.exit(0)
