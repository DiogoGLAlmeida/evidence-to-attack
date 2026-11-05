# Single text normalization used everywhere

# Stored by ingestion next to the raw text

import re
import unicodedata

_WHITESPACE = re.compile(r"\s+")

def normalize(text: str) -> str:
    """ 
    Return a canonical form of "text" for matching quotes
    
    - NFKC folds alike forms (full-width letter, ligatures) in to plain ones
    - Invisible format characters (zero-width spaces, BOM, soft hyphens) are removed
    - Every run of whitespaces becomes a singles space and the ends are trimmed
    
    A quote must match the evidence as written
    
    """
    text = unicodedata.normalize("NFKC", text)
    text = "".join(ch for ch in text if unicodedata.category(ch) != "Cf")
    return _WHITESPACE.sub(" ", text).strip()