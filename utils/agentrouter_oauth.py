"""AgentRouter 没有签到接口：额度只在登录鉴权回调中发放（官方 FAQ：需退出后重新登录才到账）。

所以用账号绑定的第三方 OAuth 会话走一次静默重登录，回调返回 checked_in 即代表发奖。
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import httpx

GITHUB_AUTHORIZE = 'https://github.com/login/oauth/authorize'
LINUXDO_AUTHORIZE = 'https://connect.linux.do/oauth2/authorize'


def extract_code(location: str | None) -> str | None:
	"""从 302 Location 中取授权码；跳回登录页说明第三方会话已失效。"""
	if not location or 'code=' not in location:
		return None
	if location.startswith('https://github.com/login'):
		return None
	codes = parse_qs(urlparse(location).query).get('code')
	return codes[0] if codes else None


def _authorize(client: httpx.Client, url: str, params: dict, cookies: dict, label: str) -> str:
	# 第三方会话 cookie 按域名放进 jar，不会发给 AgentRouter
	domain = urlparse(url).hostname
	for name, value in cookies.items():
		client.cookies.set(name, value, domain=domain)
	response = client.get(url, params=params)
	code = extract_code(response.headers.get('location'))
	if not code:
		raise RuntimeError(f'{label} 未返回授权码（HTTP {response.status_code}），会话可能已失效')
	return code


def relogin(client: httpx.Client, account, domain: str) -> tuple[bool, str]:
	"""静默重登录一次，触发服务端发放当日额度。"""
	if account.github_session:
		provider = 'github'
	elif account.linuxdo_session:
		provider = 'linuxdo'
	else:
		return False, '未配置 github_session 或 linuxdo_session，无法触发 AgentRouter 发奖'

	# client_id 由平台自己发布，不写死
	status = client.get(f'{domain}/api/status').json().get('data') or {}
	state = client.get(f'{domain}/api/oauth/state', params={'mode': 'login'}).json()['data']

	if provider == 'github':
		code = _authorize(
			client,
			GITHUB_AUTHORIZE,
			{'client_id': status['github_client_id'], 'state': state, 'scope': 'user:email'},
			{'user_session': account.github_session, 'logged_in': 'yes'},
			'GitHub',
		)
	else:
		code = _authorize(
			client,
			LINUXDO_AUTHORIZE,
			{'response_type': 'code', 'client_id': status['linuxdo_client_id'], 'state': state},
			{'_forum_session': account.linuxdo_session},
			'LinuxDO',
		)

	body = client.get(f'{domain}/api/oauth/{provider}', params={'code': code, 'state': state, 'mode': 'login'}).json()
	if not body.get('success'):
		return False, body.get('message', 'OAuth 回调登录失败')

	checked_in = bool((body.get('data') or {}).get('checked_in'))
	return True, '签到成功，额度已到账' if checked_in else '登录成功，今日已签到'
