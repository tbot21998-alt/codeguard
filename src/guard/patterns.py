import ipaddress
import re
import socket
from urllib.parse import urlsplit

from rapidfuzz.distance import DamerauLevenshtein

SECRET_PATH = re.compile(r"(?:\.aws[/\\](?:credentials|config)|\.docker[/\\]config\.json|\.ssh[/\\](?:id_[\w-]+|[^/\\]*\.pem)|/etc/(?:shadow|passwd)|(?:^|[/\\])\.env(?:\.[\w-]+)?$|\.kube[/\\]config|credentials\.json)", re.I)
PERSISTENCE_PATH = re.compile(r"(?:/etc/(?:systemd/system|sudoers|cron(?:tab|\.d|\.daily))|(?:^|[/\\])\.(?:bashrc|profile|zshrc)|authorized_keys|/etc/(?:ld\.so\.(?:preload|conf)|pam\.d|profile\.d|rc\.local|init\.d|environment|ssh/sshd_config|rc\d?\.d)|\.bash_(?:profile|logout)|\.ssh/rc|\.git/hooks/|Library/Launch(?:Agents|Daemons)|Start Menu[/\\]Programs[/\\]Startup)", re.I)
TOKEN = re.compile(r"\b(?:AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|xox[baprs]-[0-9A-Za-z-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b")
INJECTION = re.compile(r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions|reveal\s+(?:the\s+)?(?:full\s+)?system\s+prompt|(?:reviewer-bot|automated-reviewer).{0,180}(?:approve|skip\s+static\s+analysis)|mark\s+(?:this|it|the\s+code)\s+as\s+safe|regardless\s+of\s+(?:the\s+)?(?:scan\s+result|findings)|print\s+the\s+contents\s+of.{0,100}(?:ssh|credentials)", re.I | re.S)
KNOWN_PACKAGES = frozenset("requests urllib3 urllib2 urllib colorama python-dateutil numpy pandas scipy scikit-learn sklearn fastapi flask django starlette pydantic uvicorn gunicorn httpx aiohttp click rich tabulate bandit pytest pytest-cov pytest-asyncio pytest-mock pytest-xdist coverage black ruff mypy pylint flake8 isort setuptools wheel pip poetry virtualenv certifi charset-normalizer idna six typing-extensions packaging platformdirs filelock fsspec pyyaml yaml jinja2 markupsafe werkzeug itsdangerous boto3 botocore s3transfer awscli cryptography cffi pycparser pyopenssl paramiko bcrypt pynacl pillow opencv-python matplotlib seaborn plotly bokeh sqlalchemy alembic psycopg2 psycopg2-binary pymysql redis celery kombu amqp billiard asyncpg aiosqlite motor pymongo protobuf grpcio google-auth google-api-core google-cloud-storage google-cloud-bigquery googleapis-common-protos cachetools rsa pyasn1 pyasn1-modules oauthlib requests-oauthlib beautifulsoup4 lxml soupsieve html5lib scrapy twisted selenium playwright websocket-client websockets docker kubernetes ansible psutil tqdm joblib threadpoolctl torch torchvision transformers tokenizers huggingface-hub safetensors sentencepiece datasets evaluate nltk spacy regex networkx sympy mpmath numba llvmlite pyarrow polars duckdb sqlglot rapidfuzz detect-secrets python-dotenv python-multipart email-validator dnspython orjson ujson msgpack toml tomli tomlkit zipp importlib-metadata importlib-resources attrs exceptiongroup iniconfig pluggy distlib identify pre-commit nodeenv cfgv chardet jsonschema referencing rpds-py jsonschema-specifications jupyter jupyterlab notebook ipython ipykernel traitlets tornado pyzmq prompt-toolkit pygments wcwidth decorator stack-data asttokens pure-eval comm debugpy nest-asyncio nbformat nbclient nbconvert pandocfilters mistune bleach defusedxml send2trash terminado python-json-logger prometheus-client multiprocess dill tenacity backoff croniter apscheduler express react react-dom next vue nuxt angular typescript lodash axios moment dayjs chalk commander yargs webpack vite rollup esbuild babel eslint prettier jest vitest mocha chai sinon dotenv cors body-parser nodemon socket.io ws zod joi mongoose mongodb mysql2 pg sequelize prisma sharp multer helmet winston pino debug minimist glob rimraf semver ts-node tslib @types/node @types/react @babel/core @angular/core opensearch-dashboards-plugin".split())


KNOWN_MALICIOUS = frozenset("crossenv cross-env-js colourama python3-dateutil jeilyfish urlib3 setup-tools setuptool acqusition apidev-coop django-server babelcli mongose mssql-node nodefabric node-fabric flatmap-stream discordi electorn loadyaml nodecaffe noblox-js-proxy ffmepg gruntcli mysqljs".split())


def risky_package(spec):
    if re.match(r"(?:git\+|https?://|ssh://)", spec):
        return "Remote dependency requires an explicit trust review; its contents are not inspected."
    name = re.split(r"[=<>!~\[]", spec)[0]
    name = name.rsplit("@", 1)[0] if "@" in name[1:] else name
    name = re.sub(r"[-_.]+", "-", name.lower())
    if re.sub(r"-(?:js|py|python|node)$", "", name) in KNOWN_MALICIOUS:
        return f"Package '{name}' matches a publicly documented malicious or typosquatted package."
    if name in KNOWN_PACKAGES or not re.fullmatch(r"[@a-z0-9][a-z0-9_./-]*", name):
        return None
    neighbors = [p for p in KNOWN_PACKAGES if len(p) >= 5 and len(name) >= 5 and DamerauLevenshtein.distance(name, p, score_cutoff=1) == 1]
    if neighbors:
        return f"Package name resembles a known dependency ({sorted(neighbors)[0]}); possible typosquat."
    return None


SENSITIVE_PORTS = {22, 23, 25, 2375, 2376, 2379, 3306, 5432, 5984, 6379, 6443, 8500, 9200, 9300, 10250, 11211, 15672, 27017}
INTERNAL_SUFFIXES = (".internal", ".local", ".localdomain", ".lan", ".corp", ".intranet", ".svc", ".cluster.local")


def _ip(host):
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        pass
    try:
        return ipaddress.IPv4Address(socket.inet_aton(host))
    except (OSError, ValueError):
        return None


def internal_url(value):
    if not re.match(r"^[a-z][a-z0-9+.-]*://", value, re.I):
        return False
    try:
        url = urlsplit(value)
        host = (url.hostname or "").lower().rstrip(".")
        port = url.port
    except ValueError:
        return False
    if url.scheme.lower() in {"gopher", "file", "dict", "ldap", "tftp"}:
        return True
    if host in {"169.254.169.254", "fd00:ec2::254", "metadata.google.internal", "100.100.100.200"} or host.startswith("kubernetes.default"):
        return True
    if host.endswith(INTERNAL_SUFFIXES):
        return True
    address = _ip(host) if host else None
    if address is not None:
        if address.is_loopback or address.is_unspecified:
            return port in SENSITIVE_PORTS
        return address.is_private or address.is_link_local or address.is_reserved or address in ipaddress.ip_network("100.64.0.0/10")
    return host == "localhost" and port in SENSITIVE_PORTS
