import sys
from pathlib import Path

project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from utils.agentrouter_oauth import extract_code


def test_extract_code_from_callback_location():
	assert extract_code('https://agentrouter.org/api/oauth/linuxdo?code=abc123&state=xyz') == 'abc123'


def test_extract_code_ignores_github_login_redirect():
	assert extract_code('https://github.com/login?client_id=x') is None


def test_extract_code_returns_none_without_code():
	assert extract_code(None) is None
	assert extract_code('https://connect.linux.do/oauth2/authorize?state=x') is None
