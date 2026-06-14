# -*- coding: utf-8 -*-
"""
CTPPO v2.0 - Data Cleaner
=========================

Comprehensive text and data cleaning for CVE descriptions.

Cleaning Pipeline:
1. HTML decoding and tag removal
2. URL extraction and normalization
3. CVE/CWE reference extraction
4. Version number normalization
5. Text normalization (case, whitespace)
6. Tokenization and lemmatization
7. Noise removal

Author: Ruthvik (Fixed by Claude)
Date: January 2026
"""

import re
import html
import unicodedata
import logging
from typing import List, Dict, Any, Optional, Tuple, Set
from dataclasses import dataclass, field

import nltk
from nltk.tokenize import word_tokenize
from nltk.stem import WordNetLemmatizer
from nltk.corpus import stopwords

# Ensure NLTK resources are available
def _ensure_nltk_resources():
    """Download required NLTK resources if not present."""
    resources = [
        ('tokenizers/punkt', 'punkt'),
        ('tokenizers/punkt_tab', 'punkt_tab'),
        ('corpora/stopwords', 'stopwords'),
        ('corpora/wordnet', 'wordnet')
    ]
    for path, name in resources:
        try:
            nltk.data.find(path)
        except LookupError:
            nltk.download(name, quiet=True)

_ensure_nltk_resources()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class CleanedText:
    """
    Result of text cleaning with extracted metadata.
    
    Keeps both the cleaned text and extracted information
    that can be useful for feature engineering.
    """
    # Cleaned text ready for model input
    cleaned_text: str
    
    # Original text for reference
    original_text: str
    
    # Extracted metadata
    extracted_urls: List[str] = field(default_factory=list)
    extracted_cves: List[str] = field(default_factory=list)
    extracted_cwes: List[str] = field(default_factory=list)
    extracted_versions: List[str] = field(default_factory=list)
    
    # Text statistics
    original_length: int = 0
    cleaned_length: int = 0
    word_count: int = 0
    
    # Detected patterns
    has_code_snippet: bool = False
    has_exploit_mention: bool = False
    has_patch_mention: bool = False


class TextCleaner:
    """
    Comprehensive text cleaner for CVE descriptions.
    
    Performs multiple cleaning stages while preserving
    meaningful information and extracting useful metadata.
    """
    
    # Compiled regex patterns for efficiency
    PATTERNS = {
        # URLs
        'url': re.compile(
            r'https?://[^\s<>"\')\]]+|www\.[^\s<>"\')\]]+',
            re.IGNORECASE
        ),
        # Email addresses
        'email': re.compile(r'\b[\w.-]+@[\w.-]+\.\w+\b'),
        # CVE IDs
        'cve': re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE),
        # CWE IDs  
        'cwe': re.compile(r'CWE-\d+', re.IGNORECASE),
        # Version numbers
        'version': re.compile(
            r'\b[vV]?\d+(?:\.\d+)+(?:[-._][a-zA-Z0-9]+)*\b'
        ),
        # File paths
        'filepath': re.compile(
            r'(?:/[a-zA-Z0-9_.-]+)+(?:\.[a-zA-Z0-9]+)?'
        ),
        # IP addresses
        'ip': re.compile(
            r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ),
        # Hex values
        'hex': re.compile(r'\b0x[a-fA-F0-9]+\b'),
        # HTML tags
        'html_tag': re.compile(r'<[^>]+>'),
        # HTML entities
        'html_entity': re.compile(r'&[a-zA-Z]+;|&#\d+;|&#x[a-fA-F0-9]+;'),
        # Multiple spaces
        'multi_space': re.compile(r'\s+'),
        # Code blocks
        'code_block': re.compile(r'```[\s\S]*?```|`[^`]+`'),
        # Special characters (keep alphanumeric, spaces, basic punctuation)
        'special_chars': re.compile(r'[^\w\s.,;:!?()-]'),
    }
    
    # Security-related keywords to preserve/detect
    SECURITY_KEYWORDS = {
        'exploit', 'vulnerability', 'attack', 'malicious', 'injection',
        'overflow', 'bypass', 'escalation', 'privilege', 'remote',
        'arbitrary', 'execution', 'denial', 'service', 'buffer',
        'heap', 'stack', 'memory', 'corruption', 'disclosure',
        'authentication', 'authorization', 'traversal', 'xss',
        'csrf', 'ssrf', 'sqli', 'rce', 'lfi', 'rfi', 'dos', 'ddos'
    }
    
    # Exploit-related patterns
    EXPLOIT_PATTERNS = [
        r'proof.?of.?concept', r'poc', r'exploit.?available',
        r'actively.?exploit', r'in.?the.?wild', r'weaponized'
    ]
    
    # Patch-related patterns
    PATCH_PATTERNS = [
        r'patch', r'fix', r'update', r'upgrade', r'remediat',
        r'mitigat', r'workaround', r'addressed'
    ]
    
    def __init__(
        self,
        lowercase: bool = True,
        remove_stopwords: bool = False,
        lemmatize: bool = True,
        min_word_length: int = 2,
        max_word_length: int = 50
    ):
        """
        Initialize the text cleaner.
        
        Args:
            lowercase: Convert text to lowercase
            remove_stopwords: Remove common stopwords
            lemmatize: Apply lemmatization
            min_word_length: Minimum word length to keep
            max_word_length: Maximum word length to keep
        """
        self.lowercase = lowercase
        self.remove_stopwords = remove_stopwords
        self.lemmatize = lemmatize
        self.min_word_length = min_word_length
        self.max_word_length = max_word_length
        
        # Initialize NLTK components
        self.lemmatizer = WordNetLemmatizer()
        self.stop_words = set(stopwords.words('english'))
        
        # Compile exploit/patch patterns
        self.exploit_regex = re.compile(
            '|'.join(self.EXPLOIT_PATTERNS),
            re.IGNORECASE
        )
        self.patch_regex = re.compile(
            '|'.join(self.PATCH_PATTERNS),
            re.IGNORECASE
        )
    
    def _decode_html(self, text: str) -> str:
        """Decode HTML entities."""
        # First pass: named entities
        text = html.unescape(text)
        # Second pass: any remaining numeric entities
        text = self.PATTERNS['html_entity'].sub(
            lambda m: html.unescape(m.group(0)),
            text
        )
        return text
    
    def _remove_html_tags(self, text: str) -> str:
        """Remove HTML tags."""
        return self.PATTERNS['html_tag'].sub(' ', text)
    
    def _extract_urls(self, text: str) -> Tuple[str, List[str]]:
        """Extract and remove URLs."""
        urls = self.PATTERNS['url'].findall(text)
        cleaned = self.PATTERNS['url'].sub(' [URL] ', text)
        return cleaned, urls
    
    def _extract_emails(self, text: str) -> str:
        """Remove email addresses."""
        return self.PATTERNS['email'].sub(' [EMAIL] ', text)
    
    def _extract_cves(self, text: str) -> Tuple[str, List[str]]:
        """Extract CVE references."""
        cves = self.PATTERNS['cve'].findall(text)
        cleaned = self.PATTERNS['cve'].sub(' [CVE_REF] ', text)
        return cleaned, [cve.upper() for cve in cves]
    
    def _extract_cwes(self, text: str) -> Tuple[str, List[str]]:
        """Extract CWE references."""
        cwes = self.PATTERNS['cwe'].findall(text)
        cleaned = self.PATTERNS['cwe'].sub(' [CWE_REF] ', text)
        return cleaned, [cwe.upper() for cwe in cwes]
    
    def _extract_versions(self, text: str) -> Tuple[str, List[str]]:
        """Extract version numbers."""
        versions = self.PATTERNS['version'].findall(text)
        cleaned = self.PATTERNS['version'].sub(' [VERSION] ', text)
        return cleaned, versions
    
    def _normalize_whitespace(self, text: str) -> str:
        """Normalize whitespace."""
        return self.PATTERNS['multi_space'].sub(' ', text).strip()
    
    def _detect_code_snippets(self, text: str) -> bool:
        """Detect if text contains code snippets."""
        indicators = [
            self.PATTERNS['code_block'].search(text),
            '```' in text,
            '()' in text and '{' in text,
            '=>' in text,
            '==' in text
        ]
        return any(indicators)
    
    def _detect_exploit_mention(self, text: str) -> bool:
        """Detect exploit-related mentions."""
        return bool(self.exploit_regex.search(text))
    
    def _detect_patch_mention(self, text: str) -> bool:
        """Detect patch-related mentions."""
        return bool(self.patch_regex.search(text))
    
    def _tokenize_and_process(self, text: str) -> Tuple[str, int]:
        """Tokenize and optionally lemmatize/filter."""
        try:
            tokens = word_tokenize(text)
        except Exception:
            # Fallback to simple split
            tokens = text.split()
        
        processed_tokens = []
        
        for token in tokens:
            # Length filter
            if len(token) < self.min_word_length or len(token) > self.max_word_length:
                continue
            
            # Skip pure numbers (but keep alphanumeric)
            if token.isdigit():
                continue
            
            # Optional stopword removal
            if self.remove_stopwords and token.lower() in self.stop_words:
                continue
            
            # Optional lemmatization
            if self.lemmatize:
                token = self.lemmatizer.lemmatize(token.lower())
            elif self.lowercase:
                token = token.lower()
            
            processed_tokens.append(token)
        
        return ' '.join(processed_tokens), len(processed_tokens)
    
    def clean(self, text: str) -> CleanedText:
        """
        Clean text through the full pipeline.
        
        Args:
            text: Raw text to clean
            
        Returns:
            CleanedText object with cleaned text and metadata
        """
        if not text or not isinstance(text, str):
            return CleanedText(
                cleaned_text="",
                original_text=str(text) if text else "",
                original_length=0,
                cleaned_length=0,
                word_count=0
            )
        
        original_text = text
        original_length = len(text)
        
        # Detect patterns before cleaning
        has_code = self._detect_code_snippets(text)
        has_exploit = self._detect_exploit_mention(text)
        has_patch = self._detect_patch_mention(text)
        
        # Stage 1: HTML handling
        text = self._decode_html(text)
        text = self._remove_html_tags(text)
        
        # Stage 2: Extract and normalize special elements
        text, urls = self._extract_urls(text)
        text = self._extract_emails(text)
        text, cves = self._extract_cves(text)
        text, cwes = self._extract_cwes(text)
        text, versions = self._extract_versions(text)
        
        # Stage 3: Remove file paths and IPs
        text = self.PATTERNS['filepath'].sub(' [PATH] ', text)
        text = self.PATTERNS['ip'].sub(' [IP] ', text)
        text = self.PATTERNS['hex'].sub(' [HEX] ', text)
        
        # Stage 4: Remove special characters
        text = self.PATTERNS['special_chars'].sub(' ', text)
        
        # Stage 5: Normalize whitespace
        text = self._normalize_whitespace(text)
        
        # Stage 6: Tokenize and process
        text, word_count = self._tokenize_and_process(text)
        
        return CleanedText(
            cleaned_text=text,
            original_text=original_text,
            extracted_urls=urls,
            extracted_cves=cves,
            extracted_cwes=cwes,
            extracted_versions=versions,
            original_length=original_length,
            cleaned_length=len(text),
            word_count=word_count,
            has_code_snippet=has_code,
            has_exploit_mention=has_exploit,
            has_patch_mention=has_patch
        )
    
    def clean_batch(self, texts: List[str]) -> List[CleanedText]:
        """Clean multiple texts."""
        return [self.clean(text) for text in texts]


class CVECleaner:
    """
    High-level cleaner for CVE records.
    
    Combines text cleaning with record-level processing.
    """
    
    def __init__(self, text_cleaner: Optional[TextCleaner] = None):
        """
        Initialize CVE cleaner.
        
        Args:
            text_cleaner: TextCleaner instance (creates default if None)
        """
        self.text_cleaner = text_cleaner or TextCleaner()
    
    def clean_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """
        Clean a CVE record.
        
        Args:
            record: CVE record dictionary
            
        Returns:
            Cleaned record with additional metadata
        """
        # Make a copy to avoid modifying original
        cleaned = record.copy()
        
        # Clean description
        if 'description' in cleaned:
            result = self.text_cleaner.clean(cleaned['description'])
            cleaned['cleaned_description'] = result.cleaned_text
            cleaned['text_metadata'] = {
                'extracted_urls': result.extracted_urls,
                'extracted_cves': result.extracted_cves,
                'extracted_cwes': result.extracted_cwes,
                'extracted_versions': result.extracted_versions,
                'original_length': result.original_length,
                'cleaned_length': result.cleaned_length,
                'word_count': result.word_count,
                'has_code_snippet': result.has_code_snippet,
                'has_exploit_mention': result.has_exploit_mention,
                'has_patch_mention': result.has_patch_mention
            }
        
        return cleaned
    
    def clean_records(self, records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Clean multiple CVE records."""
        return [self.clean_record(r) for r in records]


# Example usage
if __name__ == "__main__":
    # Test text cleaning
    cleaner = TextCleaner()
    
    test_texts = [
        """A vulnerability in <script>alert('xss')</script> the OpenSSL library 
        v1.1.1k allows remote attackers to execute arbitrary code via a crafted 
        request. See CVE-2021-3449 and CWE-787 for more details. 
        Patch available at https://openssl.org/news/secadv/20210325.txt""",
        
        """Buffer overflow in libpng before 1.6.37 allows denial of service 
        (application crash) or possibly have unspecified other impact via 
        a crafted PNG file.""",
        
        """SQL injection vulnerability in the admin panel (admin.php?id=123) 
        allows attackers to bypass authentication. Proof of concept available. 
        Contact security@example.com for details."""
    ]
    
    print("Text Cleaning Results:\n")
    for i, text in enumerate(test_texts):
        result = cleaner.clean(text)
        print(f"Example {i+1}:")
        print(f"  Original ({result.original_length} chars): {text[:80]}...")
        print(f"  Cleaned ({result.cleaned_length} chars): {result.cleaned_text[:80]}...")
        print(f"  Word count: {result.word_count}")
        print(f"  Extracted URLs: {result.extracted_urls}")
        print(f"  Extracted CVEs: {result.extracted_cves}")
        print(f"  Has exploit mention: {result.has_exploit_mention}")
        print(f"  Has patch mention: {result.has_patch_mention}")
        print()
