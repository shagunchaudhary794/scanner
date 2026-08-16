"""
Default-credential detection.

PCI reference doc §6.1 (exact wording): "The ASV scan must detect known
vendor default accounts and passwords (not via brute-force, but by testing
known vendor defaults). Detection results in an automatic failure."

This is the operative constraint on this module: every check here makes
AT MOST ONE authentication attempt per credential pair per service, and
stops at the first success. It is explicitly not a brute-force module --
§5.4 forbids "brute-force attacks resulting in an account lockout or
password reset," and a curated vendor-default list run once each does not
risk that the way a wordlist attack would.

Each checker takes (host, port) and returns a list of dicts:
    {'service': str, 'username': str, 'note': str}
one per credential pair that succeeded (usually 0 or 1). Any checker whose
required client library isn't installed is skipped, not fatal --
_run_default_creds_scan degrades gracefully rather than failing the whole
finding pipeline over an optional dependency.
"""

import socket

# --- optional dependencies -------------------------------------------------
try:
    import paramiko
except ImportError:
    paramiko = None

try:
    import pymysql
except ImportError:
    pymysql = None

try:
    import psycopg2
except ImportError:
    psycopg2 = None

try:
    import redis as redis_lib
except ImportError:
    redis_lib = None

try:
    import pymongo
except ImportError:
    pymongo = None

import requests
from requests.auth import HTTPBasicAuth
import ftplib

CONNECT_TIMEOUT = 5

# Curated vendor-default pairs -- deliberately short. This is the list PCI
# means by "known vendor defaults," not a general password dictionary.
SSH_DEFAULTS = [('root', 'root'), ('root', 'toor'), ('admin', 'admin'), ('pi', 'raspberry')]
FTP_DEFAULTS = [('anonymous', 'anonymous'), ('admin', 'admin'), ('ftp', 'ftp')]
MYSQL_DEFAULTS = [('root', ''), ('root', 'root'), ('root', 'toor')]
POSTGRES_DEFAULTS = [('postgres', 'postgres'), ('postgres', '')]
HTTP_BASIC_DEFAULTS = [('admin', 'admin'), ('admin', 'password'), ('tomcat', 'tomcat')]


def check_ssh(host, port=22):
    if paramiko is None:
        return []
    for user, pwd in SSH_DEFAULTS:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(host, port=port, username=user, password=pwd,
                            timeout=CONNECT_TIMEOUT, banner_timeout=CONNECT_TIMEOUT,
                            allow_agent=False, look_for_keys=False)
            client.close()
            return [{'service': 'ssh', 'username': user, 'note': f'SSH accepted default credential {user}/{pwd}'}]
        except paramiko.AuthenticationException:
            continue
        except Exception:
            # Connection-level failure (closed port, banner mismatch, etc.) --
            # not worth trying further pairs against an unreachable service.
            return []
        finally:
            try:
                client.close()
            except Exception:
                pass
    return []


def check_ftp(host, port=21):
    for user, pwd in FTP_DEFAULTS:
        try:
            ftp = ftplib.FTP()
            ftp.connect(host, port, timeout=CONNECT_TIMEOUT)
            ftp.login(user, pwd)
            ftp.quit()
            return [{'service': 'ftp', 'username': user, 'note': f'FTP accepted default credential {user}/{pwd}'}]
        except ftplib.error_perm:
            continue
        except Exception:
            return []
    return []


def check_mysql(host, port=3306):
    if pymysql is None:
        return []
    for user, pwd in MYSQL_DEFAULTS:
        try:
            conn = pymysql.connect(host=host, port=port, user=user, password=pwd,
                                    connect_timeout=CONNECT_TIMEOUT)
            conn.close()
            return [{'service': 'mysql', 'username': user, 'note': f'MySQL accepted default credential {user}/{pwd or "(empty)"}'}]
        except pymysql.err.OperationalError:
            continue
        except Exception:
            return []
    return []


def check_postgres(host, port=5432):
    if psycopg2 is None:
        return []
    for user, pwd in POSTGRES_DEFAULTS:
        try:
            conn = psycopg2.connect(host=host, port=port, user=user, password=pwd,
                                     dbname='postgres', connect_timeout=CONNECT_TIMEOUT)
            conn.close()
            return [{'service': 'postgresql', 'username': user, 'note': f'PostgreSQL accepted default credential {user}/{pwd or "(empty)"}'}]
        except psycopg2.OperationalError:
            continue
        except Exception:
            return []
    return []


def check_redis(host, port=6379):
    """Redis has no default username/password -- an unauthenticated
    instance reachable from the Internet is itself the finding, matching
    §6.1's 'unauthenticated services' + PCI 1.4.4 database-exposure logic.
    """
    if redis_lib is None:
        return []
    try:
        r = redis_lib.Redis(host=host, port=port, socket_connect_timeout=CONNECT_TIMEOUT,
                             socket_timeout=CONNECT_TIMEOUT)
        if r.ping():
            return [{'service': 'redis', 'username': '(none)', 'note': 'Redis instance accessible with no authentication'}]
    except Exception:
        pass
    return []


def check_mongodb(host, port=27017):
    if pymongo is None:
        return []
    try:
        client = pymongo.MongoClient(host, port, serverSelectionTimeoutMS=CONNECT_TIMEOUT * 1000)
        client.admin.command('ping')
        client.close()
        return [{'service': 'mongodb', 'username': '(none)', 'note': 'MongoDB instance accessible with no authentication'}]
    except Exception:
        pass
    return []


def check_http_basic_auth(host, port, scheme='http'):
    """Probes common admin paths that are typically protected by HTTP
    Basic Auth with a vendor default. A 401 with no successful default
    means the service is present but not misconfigured -- not a finding.
    """
    paths = ['/manager/html', '/admin', '/', ]
    base = f"{scheme}://{host}:{port}"
    for path in paths:
        url = base + path
        try:
            probe = requests.get(url, timeout=CONNECT_TIMEOUT, verify=False)
        except Exception:
            continue
        if probe.status_code != 401:
            continue
        for user, pwd in HTTP_BASIC_DEFAULTS:
            try:
                r = requests.get(url, auth=HTTPBasicAuth(user, pwd), timeout=CONNECT_TIMEOUT, verify=False)
                if r.status_code != 401:
                    return [{'service': 'http-basic-auth', 'username': user,
                              'note': f'{path} accepted default credential {user}/{pwd}'}]
            except Exception:
                continue
    return []


# Maps Nmap-reported service name / well-known port -> checker function.
_SERVICE_CHECKERS = {
    'ssh': check_ssh,
    'ftp': check_ftp,
    'mysql': check_mysql,
    'postgresql': check_postgres,
    'redis': check_redis,
    'mongodb': check_mongodb,
}
_PORT_CHECKERS = {
    22: check_ssh,
    21: check_ftp,
    3306: check_mysql,
    5432: check_postgres,
    6379: check_redis,
    27017: check_mongodb,
}


def run_default_creds_scan(host, open_ports, web_scheme='http', web_ports=()):
    """open_ports: list of {'port': int, 'service': str} from Nmap.
    Returns a flat list of hit dicts (each already tagged with 'service',
    'username', 'note'); a hit's 'port' key is added here.
    """
    hits = []
    checked_ports = set()

    for p in open_ports:
        port = p.get('port')
        service = (p.get('service') or '').lower()
        checker = _SERVICE_CHECKERS.get(service) or _PORT_CHECKERS.get(port)
        if not checker or port in checked_ports:
            continue
        checked_ports.add(port)
        try:
            results = checker(host, port)
        except Exception:
            results = []
        for r in results:
            r['port'] = port
            hits.append(r)

    for port in web_ports:
        if port in checked_ports:
            continue
        checked_ports.add(port)
        try:
            results = check_http_basic_auth(host, port, scheme=web_scheme)
        except Exception:
            results = []
        for r in results:
            r['port'] = port
            hits.append(r)

    return hits
