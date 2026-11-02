"""PhishLens: plain-English verdicts for pasted email headers and URLs.

All analysis is lexical and in memory. PhishLens never opens a mailbox,
never sends mail, never fetches a URL, and never stores what it analyzes.
"""

from .headers import analyze_headers
from .urls import analyze_text, analyze_url

__all__ = ["analyze_headers", "analyze_url", "analyze_text"]
__version__ = "1.0.0"
