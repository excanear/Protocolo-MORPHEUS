"""
Sistema de logging estilizado para o Protocolo Morpheus.
"""

import logging
import sys
from datetime import datetime
from typing import Optional
from enum import Enum
from colorama import init, Fore, Back, Style

# Inicializa colorama para Windows
init(autoreset=True)


class LogLevel(Enum):
    """Níveis de log com cores associadas."""
    DEBUG = (Fore.CYAN, "DBG")
    INFO = (Fore.GREEN, "INF")
    WARNING = (Fore.YELLOW, "WRN")
    ERROR = (Fore.RED, "ERR")
    CRITICAL = (Fore.RED + Style.BRIGHT, "CRT")
    SUCCESS = (Fore.GREEN + Style.BRIGHT, "OK ")
    SCAN = (Fore.MAGENTA, "SCN")
    FOUND = (Fore.CYAN + Style.BRIGHT, "FND")
    ALERT = (Fore.YELLOW + Style.BRIGHT, "ALT")


class MorpheusLogger:
    """Logger personalizado com interface estilizada."""
    
    BANNER = r"""
    ╔══════════════════════════════════════════════════════════════════════════════╗
    ║                                                                              ║
    ║   ███╗   ███╗ ██████╗ ██████╗ ██████╗ ██╗  ██╗███████╗██╗   ██╗███████╗     ║
    ║   ████╗ ████║██╔═══██╗██╔══██╗██╔══██╗██║  ██║██╔════╝██║   ██║██╔════╝     ║
    ║   ██╔████╔██║██║   ██║██████╔╝██████╔╝███████║█████╗  ██║   ██║███████╗     ║
    ║   ██║╚██╔╝██║██║   ██║██╔══██╗██╔═══╝ ██╔══██║██╔══╝  ██║   ██║╚════██║     ║
    ║   ██║ ╚═╝ ██║╚██████╔╝██║  ██║██║     ██║  ██║███████╗╚██████╔╝███████║     ║
    ║   ╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚══════╝     ║
    ║                                                                              ║
    ║                    P R O T O C O L O   M O R P H E U S                       ║
    ║                Framework de Inteligência de Fontes Abertas                   ║
    ║                              [ v1.0.0 ]                                      ║
    ╚══════════════════════════════════════════════════════════════════════════════╝
    """
    
    def __init__(self, name: str = "morpheus", verbose: bool = True, debug: bool = False):
        self.name = name
        self.verbose = verbose
        self.debug_mode = debug
        self._setup_file_logger()
    
    def _setup_file_logger(self):
        """Configura logger para arquivo."""
        self.file_logger = logging.getLogger(f"{self.name}_file")
        self.file_logger.setLevel(logging.DEBUG)
        
        # Handler para arquivo
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        handler = logging.FileHandler(f"morpheus_{timestamp}.log", encoding="utf-8")
        handler.setFormatter(logging.Formatter(
            "%(asctime)s | %(levelname)-8s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        ))
        self.file_logger.addHandler(handler)
    
    def _format_message(self, level: LogLevel, message: str, module: Optional[str] = None) -> str:
        """Formata mensagem com cores e timestamp."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        color, tag = level.value
        
        module_str = f"[{module}]" if module else ""
        
        return f"{Fore.WHITE}[{timestamp}]{Style.RESET_ALL} {color}[{tag}]{Style.RESET_ALL} {Fore.BLUE}{module_str}{Style.RESET_ALL} {message}"
    
    def print_banner(self):
        """Exibe o banner do Morpheus."""
        print(Fore.CYAN + self.BANNER + Style.RESET_ALL)
    
    def log(self, level: LogLevel, message: str, module: Optional[str] = None):
        """Log genérico."""
        formatted = self._format_message(level, message, module)
        print(formatted)
        self.file_logger.info(f"[{module or 'CORE'}] {message}")
    
    def info(self, message: str, module: Optional[str] = None):
        """Log de informação."""
        if self.verbose:
            self.log(LogLevel.INFO, message, module)
    
    def debug(self, message: str, module: Optional[str] = None):
        """Log de debug."""
        if self.debug_mode:
            self.log(LogLevel.DEBUG, message, module)
    
    def warning(self, message: str, module: Optional[str] = None):
        """Log de aviso."""
        self.log(LogLevel.WARNING, message, module)
    
    def error(self, message: str, module: Optional[str] = None):
        """Log de erro."""
        self.log(LogLevel.ERROR, message, module)
    
    def critical(self, message: str, module: Optional[str] = None):
        """Log crítico."""
        self.log(LogLevel.CRITICAL, message, module)
    
    def success(self, message: str, module: Optional[str] = None):
        """Log de sucesso."""
        self.log(LogLevel.SUCCESS, message, module)
    
    def scan(self, message: str, module: Optional[str] = None):
        """Log de scan em progresso."""
        self.log(LogLevel.SCAN, message, module)
    
    def found(self, message: str, module: Optional[str] = None):
        """Log de item encontrado."""
        self.log(LogLevel.FOUND, message, module)
    
    def alert(self, message: str, module: Optional[str] = None):
        """Log de alerta importante."""
        self.log(LogLevel.ALERT, message, module)
    
    def section(self, title: str):
        """Imprime divisor de seção."""
        width = 80
        print()
        print(Fore.CYAN + "═" * width + Style.RESET_ALL)
        print(Fore.CYAN + Style.BRIGHT + f"  ◆ {title.upper()}" + Style.RESET_ALL)
        print(Fore.CYAN + "═" * width + Style.RESET_ALL)
        print()
    
    def subsection(self, title: str):
        """Imprime divisor de subseção."""
        print(Fore.BLUE + f"\n  ▸ {title}" + Style.RESET_ALL)
        print(Fore.BLUE + "  " + "─" * 60 + Style.RESET_ALL)
    
    def result(self, key: str, value: str, indent: int = 2):
        """Imprime resultado formatado."""
        spaces = " " * indent
        print(f"{spaces}{Fore.WHITE}├─ {Fore.YELLOW}{key}: {Fore.GREEN}{value}{Style.RESET_ALL}")
    
    def list_item(self, item: str, found: bool = True, indent: int = 4):
        """Imprime item de lista."""
        spaces = " " * indent
        icon = "✓" if found else "✗"
        color = Fore.GREEN if found else Fore.RED
        print(f"{spaces}{color}{icon} {item}{Style.RESET_ALL}")
    
    def progress(self, current: int, total: int, prefix: str = ""):
        """Exibe barra de progresso."""
        percent = current / total * 100
        bar_length = 40
        filled = int(bar_length * current / total)
        bar = "█" * filled + "░" * (bar_length - filled)
        
        sys.stdout.write(f"\r  {prefix} [{Fore.CYAN}{bar}{Style.RESET_ALL}] {percent:.1f}% ({current}/{total})")
        sys.stdout.flush()
        
        if current == total:
            print()
    
    def table(self, headers: list, rows: list):
        """Imprime tabela formatada."""
        if not rows:
            return
        
        # Calcula largura das colunas
        widths = [len(h) for h in headers]
        for row in rows:
            for i, cell in enumerate(row):
                widths[i] = max(widths[i], len(str(cell)))
        
        # Header
        header_line = " │ ".join(h.ljust(widths[i]) for i, h in enumerate(headers))
        separator = "─┼─".join("─" * w for w in widths)
        
        print(f"  {Fore.CYAN}{header_line}{Style.RESET_ALL}")
        print(f"  {Fore.BLUE}{separator}{Style.RESET_ALL}")
        
        # Rows
        for row in rows:
            row_line = " │ ".join(str(cell).ljust(widths[i]) for i, cell in enumerate(row))
            print(f"  {row_line}")
