#!/usr/bin/env python3
"""
Color output utilities for jsosint
"""

class Colors:
    """ANSI color codes for terminal output"""
    
    # Regular colors
    BLACK = '\033[0;30m'
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[0;33m'
    BLUE = '\033[0;34m'
    MAGENTA = '\033[0;35m'
    CYAN = '\033[0;36m'
    WHITE = '\033[0;37m'
    
    # Bold colors
    BOLD_BLACK = '\033[1;30m'
    BOLD_RED = '\033[1;31m'
    BOLD_GREEN = '\033[1;32m'
    BOLD_YELLOW = '\033[1;33m'
    BOLD_BLUE = '\033[1;34m'
    BOLD_MAGENTA = '\033[1;35m'
    BOLD_CYAN = '\033[1;36m'
    BOLD_WHITE = '\033[1;37m'
    
    # Underline colors
    UNDERLINE_BLACK = '\033[4;30m'
    UNDERLINE_RED = '\033[4;31m'
    UNDERLINE_GREEN = '\033[4;32m'
    UNDERLINE_YELLOW = '\033[4;33m'
    UNDERLINE_BLUE = '\033[4;34m'
    UNDERLINE_MAGENTA = '\033[4;35m'
    UNDERLINE_CYAN = '\033[4;36m'
    UNDERLINE_WHITE = '\033[4;37m'
    
    # Background colors
    BACKGROUND_BLACK = '\033[40m'
    BACKGROUND_RED = '\033[41m'
    BACKGROUND_GREEN = '\033[42m'
    BACKGROUND_YELLOW = '\033[43m'
    BACKGROUND_BLUE = '\033[44m'
    BACKGROUND_MAGENTA = '\033[45m'
    BACKGROUND_CYAN = '\033[46m'
    BACKGROUND_WHITE = '\033[47m'
    
    # High intensity
    INTENSE_BLACK = '\033[0;90m'
    INTENSE_RED = '\033[0;91m'
    INTENSE_GREEN = '\033[0;92m'
    INTENSE_YELLOW = '\033[0;93m'
    INTENSE_BLUE = '\033[0;94m'
    INTENSE_MAGENTA = '\033[0;95m'
    INTENSE_CYAN = '\033[0;96m'
    INTENSE_WHITE = '\033[0;97m'
    
    # Bold high intensity
    BOLD_INTENSE_BLACK = '\033[1;90m'
    BOLD_INTENSE_RED = '\033[1;91m'
    BOLD_INTENSE_GREEN = '\033[1;92m'
    BOLD_INTENSE_YELLOW = '\033[1;93m'
    BOLD_INTENSE_BLUE = '\033[1;94m'
    BOLD_INTENSE_MAGENTA = '\033[1;95m'
    BOLD_INTENSE_CYAN = '\033[1;96m'
    BOLD_INTENSE_WHITE = '\033[1;97m'
    
    # Reset
    RESET = '\033[0m'
    
    # Aliases for common uses
    INFO = CYAN
    SUCCESS = GREEN
    WARNING = YELLOW
    ERROR = RED
    TITLE = BOLD_CYAN
    HIGHLIGHT = BOLD_WHITE
    
    @staticmethod
    def colorize(text, color):
        """Wrap text in color codes"""
        return f"{color}{text}{Colors.RESET}"
    
    @staticmethod
    def print_info(text):
        """Print info message"""
        print(f"{Colors.INFO}[*]{Colors.RESET} {text}")
    
    @staticmethod
    def print_success(text):
        """Print success message"""
        print(f"{Colors.SUCCESS}[+]{Colors.RESET} {text}")
    
    @staticmethod
    def print_warning(text):
        """Print warning message"""
        print(f"{Colors.WARNING}[!]{Colors.RESET} {text}")
    
    @staticmethod
    def print_error(text):
        """Print error message"""
        print(f"{Colors.ERROR}[-]{Colors.RESET} {text}")
    
    @staticmethod
    def print_title(text):
        """Print title"""
        print(f"\n{Colors.TITLE}{text}{Colors.RESET}")
        print(f"{Colors.TITLE}{'=' * len(text)}{Colors.RESET}")
    
    @staticmethod
    def print_table(headers, rows):
        """Print a table with colored headers"""
        # Calculate column widths
        col_widths = []
        for i in range(len(headers)):
            max_len = len(str(headers[i]))
            for row in rows:
                if i < len(row):
                    max_len = max(max_len, len(str(row[i])))
            col_widths.append(max_len + 2)  # Add padding
        
        # Print headers
        header_str = ""
        for i, header in enumerate(headers):
            header_str += Colors.BOLD_CYAN + str(header).ljust(col_widths[i]) + Colors.RESET
        print(header_str)
        
        # Print separator
        separator = "-" * (sum(col_widths) + len(headers) - 1)
        print(Colors.INTENSE_BLACK + separator + Colors.RESET)
        
        # Print rows
        for row in rows:
            row_str = ""
            for i, cell in enumerate(row):
                if i < len(row):
                    row_str += str(cell).ljust(col_widths[i])
            print(row_str)