# ANSI color codes
RESET = "\033[0m"
BOLD = "\033[1m"

COLORS = {
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "blue": "\033[34m",
    "magenta": "\033[35m",
    "cyan": "\033[36m",
    "white": "\033[37m",
    "gray": "\033[90m",
}

def color(text, color="white", bold=False):
    style = BOLD if bold else ""
    return f"{style}{COLORS[color]}{text}{RESET}"
