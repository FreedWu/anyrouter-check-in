import sys
from pathlib import Path
from types import SimpleNamespace

project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from utils.agentrouter_oauth import (
	_cookies_to_string,
	extract_code,
	load_linuxdo_session,
	save_linuxdo_session,
)


def test_extract_code_from_callback_location():
	assert extract_code('https://agentrouter.org/api/oauth/linuxdo?code=abc123&state=xyz') == 'abc123'


def test_extract_code_ignores_github_login_redirect():
	assert extract_code('https://github.com/login?client_id=x') is None


def test_extract_code_returns_none_without_code():
	assert extract_code(None) is None
	assert extract_code('https://connect.linux.do/oauth2/authorize?state=x') is None


def test_linuxdo_session_roundtrip(tmp_path, monkeypatch):
	monkeypatch.setenv('CHECKIN_STATE_DIR', str(tmp_path))
	account = SimpleNamespace(name='agentrouter', api_user='104680', linuxdo_session='_t=old')
	assert load_linuxdo_session(account) is None
	save_linuxdo_session(account, '_t=new; _forum_session=def')
	assert load_linuxdo_session(account) == '_t=new; _forum_session=def'


def test_linuxdo_session_ignored_after_config_change(tmp_path, monkeypatch):
	monkeypatch.setenv('CHECKIN_STATE_DIR', str(tmp_path))
	account = SimpleNamespace(name='agentrouter', api_user='104680', linuxdo_session='_t=old')
	save_linuxdo_session(account, '_t=new')
	account.linuxdo_session = '_t=manual-refresh'
	assert load_linuxdo_session(account) is None


def test_cookies_to_string_keeps_linuxdo_only():
	cookies = [
		{'name': '_t', 'value': 'a', 'domain': '.linux.do'},
		{'name': '_t', 'value': 'b', 'domain': 'connect.linux.do'},
		{'name': 'cf_clearance', 'value': 'c', 'domain': '.linux.do'},
		{'name': 'session', 'value': 'd', 'domain': '.agentrouter.org'},
	]
	assert _cookies_to_string(cookies) == '_t=a; cf_clearance=c'
