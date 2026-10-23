import math
import re
from collections import Counter

import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin


                                                                             
                                                                 
                                                                              
                                                                             
_TOKEN_GROUPS = (
                                        
    (
        'exec', 'eval', 'compile', '__import__', 'importlib', 'pickle.loads',
        'marshal.loads', 'subprocess', 'os.system', 'os.popen', 'shutil.rmtree',
        'rm -rf', 'chmod 000', 'dd if=/dev/', 'shred', 'format-volume',
        'Remove-Item', 'Invoke-Expression',
    ),
                                           
    (
        'password', 'secret', 'token', 'api_key', 'private_key', 'id_rsa',
        'id_ed25519', '.aws/credentials', '.aws/config', '.ssh/', 'shadow',
        '.netrc', '.env', 'proc/environ', 'keychain', 'USERPROFILE',
    ),
                                    
    (
        'requests.post', 'requests.get', 'urllib.request', 'curl', 'wget',
        'nc ', 'socket.connect', 'socket.create_connection', 'sendmail',
        'rsync', 'scp', 'fetch(', 'XMLHttpRequest', 'smtplib', 'ftplib',
    ),
                           
    (
        'open(', 'read_text', 'read_bytes', 'readlines', 'Path(', 'cat ',
        '/etc/', '/proc/', 'Get-Content', 'fs.readFile', 'readFileSync',
    ),
                                            
    (
        'crontab', '/etc/cron', 'authorized_keys', 'sudoers', 'bashrc',
        '.profile', '.zshrc', 'LaunchAgents', 'LaunchDaemons', 'schtasks',
        'systemctl enable', 'update-rc.d', 'chkconfig', 'RunOnce',
        'Register-ScheduledTask',
    ),
                                
    (
        'base64', 'zlib', 'marshal', 'pickle', 'codecs', 'rot13', 'hex()',
        'chr(', 'atob(', 'btoa(', 'fromCharCode', 'decompress', 'b64decode',
        'unescape', 'DownloadString', 'FromBase64String',
    ),
                                                    
    (
        'ignore previous', 'ignore prior', 'disregard', 'forget everything',
        'system:', 'developer mode', 'pre-approved', 'skip security',
        'skip static analysis', 'mark this as safe', 'label this as',
        'reveal your system prompt', 'do not tell the user', 'hide this from',
    ),
                                        
    (
        'DROP TABLE', 'DROP DATABASE', 'DELETE FROM', 'TRUNCATE TABLE',
        'ALTER TABLE DROP', 'INTO OUTFILE', 'COPY TO PROGRAM',
        'xp_cmdshell', 'UTL_HTTP',
    ),
                                             
    (
        '| bash', '| sh', '| python', '| pwsh', '| powershell', '| perl',
        'iex(', 'Invoke-Expression',
    ),
)

_TOKEN_PATTERNS = tuple(
    re.compile('|'.join(map(re.escape, grp)), re.I)
    for grp in _TOKEN_GROUPS
)

                                                                          
_STRINGS_RE = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'')

                                                 
_REMOTE_PIPE_RE = re.compile(
    r'\b(?:curl|wget|fetch)\b[^|;\n]*\|[^;\n]*'
    r'\b(?:ba?sh|sh|python[\d.]*|perl|ruby|node|pwsh|powershell)\b',
    re.I,
)

                                                                     
_UNGUARDED_SQL_RE = re.compile(
    r'\b(?:DELETE\s+FROM|UPDATE\s+\w+\s+SET|TRUNCATE(?:\s+TABLE)?)\s+\w+\b'
    r'(?![^;]*\bWHERE\b)',
    re.I,
)


def _shannon_entropy(text: str) -> float:
    """Shannon entropy of the character distribution of *text*.

    Returns 0.0 when *text* is empty — a safe default meaning "no encoded
    content found", rather than crashing with a division-by-zero error.
    """
    if not text:
        return 0.0
    total = len(text)
    return -sum(
        (c / total) * math.log2(c / total)
        for c in Counter(text).values()
    )


def structural_row(code: str) -> tuple:
    """Extract 24 scalar features from a raw code/command string.

    Feature index reference
    -----------------------
    0   char_len_norm       total character count / 65536
    1   line_count_norm     line count / 5000
    2   import_count        number of Python/JS import statements
    3   func_def_count      number of function/def definitions
    4   str_literal_entropy Shannon entropy of string literal characters
    5   b64_token_count     count of base64-like blobs (≥20 alphanums + padding)
    6   url_count           count of http/https/ftp:// occurrences
    7   has_ipv4            1.0 if a numeric IPv4 address appears, else 0.0
    8   danger_token_count  count of group-0 dangerous execution tokens
    9   credential_norm     count of group-1 credential tokens / 10
    10  upper_ratio         uppercase-letter fraction (0.0 if no letters)
    11  pipe_count          count of | characters
    12  redirect_count      count of > or >> sequences
    13  semicolon_count     count of ; characters
    14  network_sink_count  count of group-2 network sink tokens
    15  file_read_count     count of group-3 file-read tokens
    16  b64_exec_pair       1.0 if base64.b64decode and exec/eval on adjacent lines
    17  persistence_count   count of group-4 persistence tokens
    18  obfuscation_count   count of group-5 obfuscation tokens
    19  injection_count     count of group-6 prompt-injection tokens
    20  sql_mutation_count  count of group-7 SQL mutation tokens
    21  remote_pipe         1.0 if curl/wget piped to a shell interpreter
    22  unguarded_sql       1.0 if an unguarded DELETE/UPDATE/TRUNCATE detected
    23  shell_op_density    (pipe + redirect + semicolon) / line_count
    """
    literals = ''.join(m.group()[1:-1] for m in _STRINGS_RE.finditer(code))
    letters = sum(c.isalpha() for c in code)
    tok = [len(p.findall(code)) for p in _TOKEN_PATTERNS]
    lines = code.splitlines()
    line_count = max(len(lines), 1)

                                                                        
    b64_exec = any(
        'base64.b64decode' in ln
        and re.search(
            r'\b(?:exec|eval)\s*\(',
            '\n'.join(lines[max(0, i - 1):i + 2]),
        )
        for i, ln in enumerate(lines)
    )

    pipe_n = code.count('|')
    redirect_n = len(re.findall(r'>>', code)) + len(
        re.findall(r'(?<!>)>(?!>)', code)
    )
    semi_n = code.count(';')

    return (
        len(code) / 65536,                                                       
        line_count / 5000,                                                       
        len(re.findall(r'^\s*(?:import\s|from\s+\S+\s+import\s)', code, re.M)),     
        len(re.findall(r'\b(?:def|function)\s+', code)),                         
        _shannon_entropy(literals),                                               
        len(re.findall(r'[A-Za-z0-9+/]{20,}={0,2}', code)),                     
        len(re.findall(r'(?:https?|ftp)://', code)),                              
        float(bool(re.search(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', code))),           
        tok[0],                                                                   
        tok[1] / 10,                                                              
        sum(c.isupper() for c in code) / letters if letters else 0.0,             
        pipe_n,                                                                    
        redirect_n,                                                                
        semi_n,                                                                    
        tok[2],                                                                    
        tok[3],                                                                    
        float(b64_exec),                                                           
        tok[4],                                                                    
        tok[5],                                                                    
        tok[6],                                                                    
        tok[7],                                                                    
        float(bool(_REMOTE_PIPE_RE.search(code))),                                
        float(bool(_UNGUARDED_SQL_RE.search(code))),                              
        (pipe_n + redirect_n + semi_n) / line_count,                              
    )


                                                                                 
N_FEATURES = 24


class StructuralFeatureExtractor(TransformerMixin, BaseEstimator):
    """sklearn-compatible transformer: code strings → 24-column float32 array."""

    def fit(self, X, y=None):              
        return self

    def transform(self, X):              
        return np.asarray(
            [structural_row(code) for code in X],
            dtype=np.float32,
        ).reshape(-1, N_FEATURES)
