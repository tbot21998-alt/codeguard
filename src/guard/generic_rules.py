import re

from guard.patterns import TOKEN, internal_url
from guard.schema import Finding


def R(pattern):
    return re.compile(pattern, re.I)


READ_VERBS = R(r"\b(?:cat|type|more|less|head|tail|grep|egrep|rg|cp|copy|mv|scp|rsync|curl|wget|base64|xxd|strings|sqlite3|gc|Get-Content|Select-String|open|read_text|read_bytes|readFile\w*|readlines|fs\.read\w*|File\.read|ReadAllText|load)\b|<")
SECRET_PATH = R(
    r"\.aws[/\\](?:credentials|config)|\.ssh[/\\](?:id_[\w.-]+|[^/\\\s'\"]*\.pem|authorized_keys)|\.docker[/\\]config\.json|\.kube[/\\]config"
    r"|/etc/(?:shadow|passwd|gshadow|ssl/private)|(?:^|[/\\\s'\"=])\.env(?:\.[\w-]+)?(?=$|[\s'\"])|credentials\.json|application_default_credentials\.json"
    r"|gcloud[/\\](?:credentials|legacy_credentials|access_tokens)|\.netrc|\.pgpass|\.npmrc|\.pypirc|\.git-credentials|\.gnupg|Login\\? Data|Library/Keychains"
    r"|\.local/share/keyrings|/proc/(?:self|\d+)/environ|\bid_rsa\b|\bid_ed25519\b|\bid_ecdsa\b|terraform\.tfstate|\.vault-token|wallet\.dat"
)
TOKEN2 = R(r"\b(?:sk-(?:proj-|live-|ant-)?[A-Za-z0-9_-]{24,}|AIza[0-9A-Za-z_-]{35}|glpat-[A-Za-z0-9_-]{20}|npm_[A-Za-z0-9]{36}|sk_live_[A-Za-z0-9]{16,}|-----BEGIN (?:RSA |OPENSSH |EC |DSA |PGP )?PRIVATE KEY)")
SECRET_ENV = r"\$\{?(?:env:)?[A-Za-z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE_KEY|ACCESS_KEY|API_KEY|CREDENTIAL)[A-Za-z0-9_]*\}?"
SAFE_RM_TARGET = re.compile(r"^(?:\./)?(?:node_modules|build|dist|target|__pycache__|\.cache|\.pytest_cache|\.next|out|coverage|\.venv|venv|\.tox|\.mypy_cache)(?:/.*)?$|^/tmp/[^/*]+(?:/.*)?$")

                                                                                             
LINE_RULES = [
    ("secret_access", R(r"\b(?:mimikatz|sekurlsa|lazagne|hashdump|secretsdump|gsecdump|pypykatz)\b|procdump\b.*lsass|comsvcs\.dll.*minidump"), "Credential-dumping tool or LSASS memory access."),
    ("secret_access", R(r"\bsecurity\s+(?:find-(?:generic|internet)-password|dump-keychain)\b"), "Reads the operating-system keychain."),
    ("secret_access", R(r"\b(?:grep|egrep|rg|find)\b.*(?:PRIVATE KEY|BEGIN\s+(?:RSA|OPENSSH|EC|DSA))"), "Searches the filesystem for private key material."),
    ("secret_access", R(r"\b(?:grep|egrep|rg|find)\b.*(?:password|secret|token|api[_-]?key).*\s(?:/home|/root|/etc|/Users|~)(?:\s|/|$)"), "Searches user or system directories for credentials."),
    ("secret_access", R(r"\b(?:echo|printf|print|Write-Host|Write-Output)\b[^\n]*" + SECRET_ENV), "Prints a secret environment variable."),
    ("secret_access", R(r"\bprintenv\b|\benv\s*\|\s*(?:grep|sort|less|curl|nc)|\b(?:set|export\s+-p)\s*\|\s*(?:grep|curl|nc)"), "Dumps environment variables that may hold secrets."),
    ("secret_access", TOKEN, "Source embeds a credential-like token."),
    ("secret_access", TOKEN2, "Source embeds a credential-like token or private key."),
                       
    ("data_exfiltration", R(r"\b(?:scp|rsync|sftp)\b(?=[^\n]*\s[\w.-]+@[\w.-]+:)(?=[^\n]*(?:\s-\w*[ra]\w*\s|\s~|\s/(?:home|etc|var|root|Users)|\.ssh))"), "Copies local directories or sensitive paths to a remote host."),
    ("data_exfiltration", R(r"\b(?:curl|wget)\b[^\n]*(?:\s-F\s*['\"]?\w+=@|--form\b[^\n]*@|\s-T\s|--upload-file|--post-file|--data-urlencode\s+\S*@)"), "Uploads a local file to a remote server."),
    ("data_exfiltration", R(r"\b(?:curl|wget)\b[^\n]*(?:\s-d|\s--data\S*)\s*[\"']?\$\((?:cat|base64|tar|env|printenv|head|tail)\b"), "Sends the output of a local file read to a remote server."),
    ("data_exfiltration", R(r"\b(?:tar|zip|7z|gzip|cat|dd)\b[^\n]*\|\s*(?:curl|wget|nc|ncat|socat|ssh|openssl\s+s_client)\b"), "Pipes local data to a network tool."),
    ("data_exfiltration", R(r"\b(?:nc|ncat|netcat|socat)\b[^\n]*(?:<|\|)"), "Streams local data through a raw network channel."),
    ("data_exfiltration", R(r"\b(?:mysqldump|pg_dump|mongodump|redis-cli\s+--rdb)\b[^\n]*(?:\|\s*(?:curl|nc|ncat|ssh|gzip[^\n]*\|)|>\s*/var/www|>\s*/srv/www)"), "Dumps a database to a network or web-served location."),
    ("data_exfiltration", R(r"\b(?:dig|nslookup|host|resolve-dnsname)\b[^\n]*(?:\$\(|`)"), "Encodes local data into DNS lookups."),
    ("data_exfiltration", R(r"\bINTO\s+(?:OUT|DUMP)FILE\b|\bCOPY\b[^\n]*\bTO\s+PROGRAM\b|\bUTL_HTTP\b|\bxp_cmdshell\b"), "SQL writes query results to disk or runs external programs."),
    ("data_exfiltration", R(r"/dev/(?:tcp|udp)/"), "Opens a raw network channel from the shell (reverse shell or exfiltration)."),
                         
    ("destructive_command", R(r"\bfind\s+(?:/|~|\$HOME|/(?:home|var|etc|usr|srv|opt|root)\b)[^\n]*(?:-delete\b|-exec\s+(?:sudo\s+)?rm\b)"), "find deletes files across system directories."),
    ("destructive_command", R(r"\b(?:shred|srm|wipe|blkdiscard|wipefs|sdelete)\b"), "Securely erases files or devices."),
    ("destructive_command", R(r"\bchmod\s+(?:-\w+\s+)*[0-7]{3,4}\s+/(?:\s|\*|$)|\bchown\s+-R\s+\S+\s+/(?:\s|\*|$)"), "Changes permissions or ownership across the root filesystem."),
    ("destructive_command", R(r"\bmv\b[^\n]*\s/dev/null\b"), "Moves data into /dev/null, destroying it."),
    ("destructive_command", R(r"(?<![>\w])>\s*/(?:etc|boot|bin|sbin|lib|usr|var/lib)/\S+|\btruncate\s+-s\s*0\s+/(?:etc|boot|var/lib|var/log)/"), "Truncates a system file."),
    ("destructive_command", R(r"\bkill\s+(?:-\w+\s+)*-1\b|\bkillall5\b|\bkillall\s+-9\s+\S*(?:init|systemd|sshd)"), "Kills every process or critical daemons."),
    ("destructive_command", R(r"\bdocker\s+(?:system|volume|container|image)\s+prune\b[^\n]*(?:-\w*[af]\w*|--all|--force|--volumes)|\bdocker\s+rm\s+-f\s+\$\(docker\s+ps"), "Force-removes Docker containers, images or volumes."),
    ("destructive_command", R(r"\biptables\s+(?:-t\s+\w+\s+)?(?:-F|-X|--flush)\b|\bufw\s+disable\b|\bsetenforce\s+0\b|\bsystemctl\s+(?:stop|disable|mask)\s+(?:firewalld|auditd|apparmor|ufw)\b"), "Disables the firewall or other host security controls."),
    ("destructive_command", R(r"\bhistory\s+-c\b|\bunset\s+HISTFILE\b|\bHISTFILE=/dev/null|(?:rm|shred|unlink)\b[^\n]*(?:bash_history|zsh_history|/var/log)|>\s*~?/?[\w/.]*\.(?:bash|zsh)_history|os\.(?:unlink|remove)\([^)]*_history"), "Erases shell history or logs to hide activity."),
    ("destructive_command", R(r"\bkubectl\s+delete\s+(?:namespaces?|ns)\b|\bkubectl\s+delete\b[^\n]*(?:--all\b|-A\b|--all-namespaces)"), "Deletes Kubernetes namespaces or every resource."),
    ("destructive_command", R(r"\bterraform\s+destroy\b|\baws\s+s3\s+(?:rb|rm)\b[^\n]*(?:--force|--recursive)|\baws\s+ec2\s+terminate-instances\b|\bgcloud\b[^\n]*\bdelete\b[^\n]*(?:--quiet|-q)"), "Destroys cloud infrastructure or data."),
    ("destructive_command", R(r"\bfs\.(?:rm|rmSync|rmdirSync|unlinkSync|rmdir)\s*\(\s*['\"`](?:/|~|[A-Za-z]:)"), "Node.js deletes files from the root or home filesystem."),
    ("destructive_command", R(r"\bgit\s+push\b[^\n]*--delete\s+(?:origin\s+)?(?:main|master)\b|\bgit\s+filter-(?:branch|repo)\b"), "Rewrites or deletes shared git history."),
    ("destructive_command", R(r"\bformat-volume\b|\bClear-Disk\b|\bRemove-Item\b[^\n]*(?:-Recurse|-r\b)[^\n]*(?:C:\\|\\Windows|\\Users)"), "Wipes a Windows volume or system directory."),
                            
    ("persistence_or_privesc", R(r"\bchmod\s+(?:-\w+\s+)*(?:[ugoa]*\+[rwx]*s\b|[2467][0-7]{3}\b)"), "Sets the setuid or setgid bit."),
    ("persistence_or_privesc", R(r"\b(?:useradd|adduser)\b[^\n]*(?:-u\s*0\b|\s-o\b|-G\s*\S*(?:sudo|wheel|root))|\busermod\b[^\n]*-a?G\s*\S*(?:sudo|wheel|root|admin|docker)|\bnet\s+(?:user|localgroup)\b[^\n]*/add\b"), "Creates a privileged account or grants administrator rights."),
    ("persistence_or_privesc", R(r"\breg\s+add\b[^\n]*\\(?:Run|RunOnce|Winlogon|Image File Execution Options)\b|\bschtasks\b[^\n]*/create|\bsc(?:\.exe)?\s+(?:create|config)\b|\b(?:New-Service|Register-ScheduledTask|New-ScheduledTask)\b"), "Registers a Windows autorun, service or scheduled task."),
    ("persistence_or_privesc", R(r"\blaunchctl\s+(?:load|bootstrap|submit)\b|/Library/Launch(?:Agents|Daemons)\b"), "Installs a macOS launch agent or daemon."),
    ("persistence_or_privesc", R(r"\bsetcap\b|\b(?:os\.)?(?:setuid|setgid|setresuid|seteuid)\s*\(\s*0\b|\bLD_PRELOAD\s*="), "Grants capabilities or switches to root."),
    ("persistence_or_privesc", R(r"\bdocker\s+run\b[^\n]*(?:--privileged|-v\s*/:/|--pid=host|--cap-add=(?:ALL|SYS_ADMIN))|\bnsenter\s+(?:-\w+\s+)*-t\s*1\b|\bchroot\s+/host\b"), "Starts a privileged container with host access."),
    ("persistence_or_privesc", R(r"^\s*at\s+(?:now|midnight|noon|teatime|tomorrow|\d)|\b(?:update-rc\.d|chkconfig)\b"), "Schedules deferred execution or boot-time services."),
    ("persistence_or_privesc", R(r"\bsudo\s+(?:su|-s|-i)\b[^\n]*(?:\||-c)|\bsudo\s+chmod\s+\+s\b"), "Escalates to a root shell."),
                          
    ("obfuscated_execution", R(r"\bpowershell(?:\.exe)?\b[^\n]*(?:\s-e(?:nc\w*)?\s+[A-Za-z0-9+/=]{12,}|-w(?:indowstyle)?\s+hidden|-nop\b)|\b(?:iex|Invoke-Expression)\b|\bDownloadString\b|\bFromBase64String\b"), "PowerShell runs encoded, hidden or downloaded code."),
    ("obfuscated_execution", R(r"\b(?:curl|wget|fetch|iwr|Invoke-WebRequest)\b[^|;&\n]*\|\s*(?:sudo\s+)?(?:(?:ba|z|k|da|c)?sh|python[\d.]*|perl|ruby|node|php|pwsh|powershell)\b"), "Downloads a script and runs it without inspection."),
    ("obfuscated_execution", R(r"(?:\beval|\bsource|\bsh\s+-c|\bbash\s+-c|\bpython[\d.]*\s+-c)\s+[\"']?(?:\$\(|`)\s*(?:curl|wget)|\b(?:ba|z)?sh\s+<\(\s*(?:curl|wget)|\bsource\s+<\(\s*(?:curl|wget)"), "Executes remotely fetched shell code."),
    ("obfuscated_execution", R(r"\b(?:base64|xxd|openssl\s+enc|gunzip|zcat|gzip\s+-d|rev|uudecode|unxz|bzcat)\b[^\n]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b"), "Decodes data and pipes it straight into a shell."),
    ("obfuscated_execution", R(r"\bgetattr\s*\(\s*(?:__builtins__|builtins|__import__\()|\b__builtins__\s*\[|\bglobals\s*\(\s*\)\s*\[\s*['\"]__builtins__"), "Resolves built-in functions indirectly to hide execution."),
    ("obfuscated_execution", R(r"\b(?:perl|ruby|php|lua)\s+-[er]\b[^\n]*\b(?:eval|system|exec|pack|decode_base64|base64_decode|popen)\b"), "Interpreter one-liner decodes or evaluates hidden code."),
    ("obfuscated_execution", R(r"(?:\\x[0-9a-f]{2}){8,}|String\.fromCharCode\((?:\s*\d+\s*,){5,}|(?:\\u00[0-9a-f]{2}){6,}|\beval\s*\(\s*unescape\b"), "Code is hidden behind character-encoding tricks."),
    ("obfuscated_execution", R(r"\b(?:eval|exec|system|popen|Function|decode|decompress|loads)\b[^\n]*[\"'][A-Za-z0-9+/]{60,}={0,2}[\"']|[\"'][A-Za-z0-9+/]{60,}={0,2}[\"'][^\n]*\b(?:eval|exec|decode|decompress|loads)\b"), "Long encoded blob is decoded or executed."),
    ("obfuscated_execution", R(r"\bnew\s+Function\s*\(|\bvm\.(?:runIn\w+|Script)\b|\bchild_process\b[^\n]*(?:Buffer\.from|atob)|\bBuffer\.from\([^)]*base64[^)]*\)[^\n]*\b(?:exec|eval)\b|\bexec\w*\([^\n]*Buffer\.from"), "JavaScript builds and runs code dynamically."),
                     
    ("dependency_risk", R(r"\b(?:pip\d*|python[\d.]*\s+-m\s+pip)\s+install\b[^\n]*(?:--(?:extra-)?index-url|-i\s+https?://|--trusted-host|--find-links|-f\s+https?://)"), "Installs packages from a non-default package index."),
    ("dependency_risk", R(r"\b(?:npm|yarn|pnpm)\b[^\n]*(?:--registry[= ]\s*https?://(?!registry\.npmjs\.org|registry\.yarnpkg\.com)|config\s+set\s+registry\s+https?://(?!registry\.npmjs\.org))"), "Installs packages from a non-default registry."),
    ("dependency_risk", R(r"\b(?:curl|wget)\b[^\n]*(?:setup\.py|requirements\.txt|\.whl|\.tar\.gz|install\.sh)[^\n]*(?:\||&&|;)\s*(?:python[\d.]*|pip|sh|bash)"), "Fetches and installs a remote package without review."),
    ("dependency_risk", R(r"\bpip\d*\s+install\b[^\n]*\s--(?:break-system-packages|no-verify|allow-external)\b|\bnpm\s+install\b[^\n]*--ignore-scripts=false"), "Disables package-installation safety checks."),
                         
    ("resource_exhaustion", R(r"\byes\b[^|;\n]*>\s*/dev/null"), "yes redirected to /dev/null burns CPU indefinitely."),
    ("resource_exhaustion", R(r"\bfallocate\s+-l\s*\d+\s*[GT]|\btruncate\s+-s\s*\d+\s*[GT]|\bhead\s+-c\s*\d+\s*[GT]|\bdd\b[^\n]*\bcount=\d{8,}"), "Allocates an enormous file."),
    ("resource_exhaustion", R(r"\bcat\s+/dev/(?:zero|u?random)\b(?![^\n]*\|\s*head)"), "Streams an endless device into storage or memory."),
    ("resource_exhaustion", R(r"\bping\b[^\n]*\s-f\b|\bhping3\b[^\n]*--flood|\bab\s+(?:-\w+\s+)*-n\s*\d{6,}|\bsiege\b|\bslowloris\b|\bwrk\b[^\n]*-c\s*\d{4,}|\bstress(?:-ng)?\b[^\n]*--(?:cpu|vm|io|hdd)\b"), "Floods a target or stress-tests the host."),
    ("resource_exhaustion", R(r"\b(\w+)\s*\(\s*\)\s*\{\s*\1\s*\|\s*\1\s*&"), "Fork bomb."),
    ("resource_exhaustion", R(r"\bwhile\s*\(\s*(?:true|1)\s*\)\s*\{\s*\}|\bfor\s*\(\s*;\s*;\s*\)\s*\{\s*\}|\bsetInterval\s*\([^)]*,\s*[01]\s*\)"), "Empty or zero-delay infinite loop."),
    ("resource_exhaustion", R(r"\bsys\.setrecursionlimit\s*\(\s*(?:10\s*\*\*\s*[6-9]|\d{6,})"), "Raises the recursion limit to an unsafe value."),
                        
    ("ssrf_network_exfil", R(r"169\.254\.169\.254|100\.100\.100\.200|fd00:ec2::254|metadata\.google\.internal|\bkubernetes\.default(?:\.svc)?\b"), "Targets a cloud metadata or cluster-internal API endpoint."),
]

                                                                               


def _has(pattern, text):
    return re.search(pattern, text, re.I) is not None


CODE_RULES = [
    ("data_exfiltration", lambda t: _has(r"document\.cookie|localStorage|sessionStorage", t) and _has(r"\bfetch\s*\(|XMLHttpRequest|sendBeacon|new\s+Image|WebSocket|\.src\s*=", t), "Browser storage or cookies are sent to a remote server."),
    ("data_exfiltration", lambda t: _has(r"\.(?:sendmail|send_message|storbinary|storlines)\s*\(", t) and _has(r"\bopen\s*\(|\.read\(|/etc/|/var/|\.ssh|\.env", t), "Local file contents are mailed or uploaded over FTP."),
    ("secret_access", lambda t: _has(r"environ\.(?:items|values)\s*\(|\bdict\s*\(\s*os\.environ\s*\)|os\.environ\.copy\s*\(", t) and _has(r"KEY|TOKEN|SECRET|PASS", t), "Iterates environment variables looking for secrets."),
    ("resource_exhaustion", lambda t: _has(r"\bwhile\s*\(\s*(?:true|1)\s*\)|\bfor\s*\(\s*;\s*;\s*\)", t) and not _has(r"\b(?:break|return|await|setTimeout|process\.exit|sleep)\b", t), "JavaScript loop never exits or yields."),
    ("ssrf_network_exfil", lambda t: _has(r"\b(?:fetch|axios(?:\.\w+)?|got|request|http\.get|https\.get)\s*\(\s*req\.(?:query|body|params)", t), "Request input chooses the URL that the server fetches."),
]


def _strip_comment_lines(code):
    lines = []
    for number, raw in enumerate(code.splitlines(), 1):
        stripped = raw.strip()
        if stripped.startswith(("#!",)) or not stripped.startswith(("#", "//", "--", "/*", "*", "<!--")):
            lines.append((number, raw))
    return lines


def generic_findings(code):
    findings = []
    lines = _strip_comment_lines(code)
    for number, raw in lines:
        line = raw.strip()
        for category, pattern, reason in LINE_RULES:
            if pattern.search(line):
                findings.append(Finding(category, reason, number))
        if SECRET_PATH.search(line) and READ_VERBS.search(line) and not re.search(r"\b(?:cp|copy|mv|ln)\b[^|;&\n]*\.env\.(?:example|sample|template|dist)", line, re.I):
            findings.append(Finding("secret_access", "Reads a protected credential or account file.", number))
        if re.search(r"\b(?:rm|del|rmdir)\b", line, re.I):
            tokens = line.replace("\\", "/").split()
            if "rm" in tokens and any(re.fullmatch(r"-[A-Za-z]*[rR][A-Za-z]*|--recursive", token) for token in tokens):
                targets = [token.strip("'\"") for token in tokens[tokens.index("rm") + 1:] if not token.startswith("-") and token not in {"&&", ";", "|", "||"}]
                if targets and not all(SAFE_RM_TARGET.match(target) for target in targets):
                    findings.append(Finding("destructive_command", "Recursive removal can destroy filesystem data.", number))
        for url in re.findall(r"[a-z][a-z0-9+.-]*://[^\s'\"`<>)\]}]*(?:\[[0-9a-f:]+\][^\s'\"`<>)]*)?", line, re.I):
            if internal_url(url):
                findings.append(Finding("ssrf_network_exfil", "Source references a metadata endpoint, internal service, or unsafe URL scheme.", number))
    body = "\n".join(raw for _, raw in lines)
    for category, predicate, reason in CODE_RULES:
        if predicate(body):
            first = next((number for number, raw in lines if raw.strip()), 1)
            findings.append(Finding(category, reason, first))
    return findings


STRONG_INJECTION = R(
    r"ignore\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|above|earlier|preceding)\s+(?:instructions?|rules|prompts?|directions?|guidelines)"
    r"|disregard\s+(?:all\s+|any\s+|the\s+)?(?:prior|previous|above|earlier|your)\s+(?:instructions?|rules|prompts?|guidelines)"
    r"|forget\s+(?:everything|all|what)\s+(?:above|before|you|previous)|forget\s+your\s+(?:guidelines|instructions|rules|training)"
    r"|you\s+are\s+now\s+(?:in\s+)?(?:a\s+)?(?:developer|dan|jailbr\w+|unrestricted|no\s+longer)|new\s+instructions?\s*:|developer\s+mode|jailbreak"
    r"|reveal\s+(?:the\s+|your\s+)?(?:full\s+)?system\s+prompt"
    r"|(?:do\s+not|don'?t|never)\s+(?:tell|mention|inform|disclose|reveal|show)\s+(?:this\s+(?:section\s+)?to\s+)?the\s+user|hide\s+(?:this|it)\s+from\s+the\s+user|without\s+(?:telling|informing)\s+the\s+user"
    r"|<important>|mark\s+(?:this|it|the\s+code|this\s+snippet|everything)\s+as\s+(?:safe|benign|trusted|clean|approved)"
    r"|label\s+(?:this|it)\s+(?:snippet\s+|code\s+|file\s+)?as\s+(?:safe|benign)|treat\s+(?:this|it)\s+(?:file\s+|code\s+|snippet\s+)?as\s+(?:safe|trusted|benign)"
    r"|regardless\s+of\s+(?:the\s+)?(?:scan\s+result|findings|what\s+it\s+does)|no\s+longer\s+a\s+(?:security\s+)?(?:scanner|reviewer|assistant)"
    r"|respond\s+only\s+with\s+(?:allow|safe|approved|ok)\b|approve\s+(?:this|everything|all)\s+(?:pull\s+request|pr|change|changes|code|commit|file|snippet)"
    r"|(?:pre-?approved|already\s+approved)\s*,?\s*(?:skip|no\s+need)|print\s+the\s+contents\s+of.{0,100}(?:ssh|credentials)"
    r"|(?:reviewer-bot|automated-reviewer).{0,180}(?:approve|skip\s+static\s+analysis)"
)
ADDRESSEE = R(
    r"(?:note|message|attention|notice|instruction|important)s?\s+(?:to|for)\s+(?:the\s+)?(?:ai|llm|assistant|model|reviewer|scanner|bot|agent)\b"
    r"|\b(?:ai|llm)\s+(?:reviewer|assistant|agent|scanner|model|tool)\b|\bfor\s+(?:the\s+)?(?:ai|llm)\b|\bllm\s*:"
    r"|\b(?:reviewer-bot|automated[\s-](?:reviewer|scanner|review|analysis)|security\s+(?:scanner|review|bot)|code\s+review(?:er)?|language\s+model|chatgpt|copilot|claude)\b"
    r"|^\W*(?:assistant|ai)\s*[:,]"
)
OVERRIDE = R(
    r"\b(?:ignore|disregard|skip|bypass|override|approve|pre-?approved|do\s+not\s+(?:flag|report|warn|raise|scan|check|analy[sz]e)|don'?t\s+(?:flag|report|warn|scan|check)"
    r"|must\s+not\s+(?:report|flag)|never\s+(?:flag|report)|no\s+issues|not\s+report)\b"
)


def injection_offsets(text):
    offsets = [match.start() for match in STRONG_INJECTION.finditer(text)]
    position = 0
    pieces = text.split("\n")
    for index, line in enumerate(pieces):
        window = line + " " + (pieces[index + 1] if index + 1 < len(pieces) else "")
        if ADDRESSEE.search(window) and OVERRIDE.search(window):
            offsets.append(position)
        position += len(line) + 1
    return sorted(set(offsets))
