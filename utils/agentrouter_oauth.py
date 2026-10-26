"""AgentRouter 没有签到接口：额度只在登录鉴权回调中发放（官方 FAQ：需退出后重新登录才到账）。

所以用账号绑定的第三方 OAuth 会话走一次静默重登录，回调返回 checked_in 即代表发奖。
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlencode, urlparse

import httpx
from cloakbrowser import launch_async

from utils.browser import prepare_browser_page
from utils.proxy import get_playwright_proxy

GITHUB_AUTHORIZE = 'https://github.com/login/oauth/authorize'
LINUXDO_AUTHORIZE = 'https://connect.linux.do/oauth2/authorize'
LINUXDO_CALLBACK_PATH = '/oauth/linuxdo'
CF_WAIT_ROUNDS = 20
CF_WAIT_MS = 2000
GOTO_ATTEMPTS = 3


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


def parse_cookie_string(cookie_str: str) -> dict[str, str]:
	"""解析从浏览器复制的 "name1=value1; name2=value2"，值保持 URL 编码原样。"""
	pairs: dict[str, str] = {}
	for part in cookie_str.split(';'):
		name, sep, value = part.strip().partition('=')
		if sep and name:
			pairs[name] = value
	return pairs


async def _goto_with_retry(page, url: str) -> None:
	for attempt in range(GOTO_ATTEMPTS):
		try:
			await page.goto(url, wait_until='domcontentloaded', timeout=60_000)
			return
		except Exception:
			if attempt == GOTO_ATTEMPTS - 1:
				raise
			await page.wait_for_timeout(3000)


async def _wait_out_challenge(page) -> None:
	"""Cloudflare 挑战页标题是「请稍候…」，等它自己跳走。"""
	for _ in range(CF_WAIT_ROUNDS):
		try:
			title = await page.title()
		except Exception:
			title = ''
		if title and '请稍候' not in title and 'Just a moment' not in title:
			return
		await page.wait_for_timeout(CF_WAIT_MS)


async def _authorize_linuxdo(params: dict, session: str, *, use_proxy: bool) -> str:
	"""connect.linux.do 有 Cloudflare 挑战，httpx 一律 403，只能让浏览器过挑战拿 code。"""
	launch_kwargs: dict = {'headless': True}
	proxy = get_playwright_proxy(use_proxy=use_proxy)
	if proxy:
		launch_kwargs['proxy'] = proxy

	cookies = parse_cookie_string(session)
	if not cookies:
		raise RuntimeError('linuxdo_session 不是合法的 cookie 字符串（应形如 "_t=...; _forum_session=..."）')

	browser = await launch_async(**launch_kwargs)
	captured: list[str] = []

	async def capture(route) -> None:
		code = extract_code(route.request.url)
		if code:
			captured.append(code)
			await route.abort()
		else:
			await route.continue_()

	try:
		context = await browser.new_context()
		# 统一种到父域 .linux.do：connect.linux.do 的 sso_provider 会跳回 linux.do 读会话
		await context.add_cookies(
			[
				{'name': name, 'value': value, 'domain': '.linux.do', 'path': '/', 'secure': True, 'httpOnly': True}
				for name, value in cookies.items()
			]
		)
		page = await context.new_page()
		await page.route(f'**{LINUXDO_CALLBACK_PATH}**', capture)
		await prepare_browser_page(page)
		# 先在 linux.do 过掉 Cloudflare 拿 cf_clearance，否则直接开 connect.linux.do 会被 ERR_CONNECTION_CLOSED
		await _goto_with_retry(page, 'https://linux.do/')
		await _wait_out_challenge(page)
		await _goto_with_retry(page, f'{LINUXDO_AUTHORIZE}?{urlencode(params)}')

		approved = False
		for _ in range(CF_WAIT_ROUNDS):
			if captured:
				return captured[0]
			# 首次授权要点头「允许」，之后会话记住了授权就直接跳回调
			if not approved:
				approve = page.locator('a[href*="/oauth2/approve/"]')
				if await approve.count():
					await approve.first.click()
					approved = True
			await page.wait_for_timeout(CF_WAIT_MS)
			if page.url.startswith('https://linux.do/login'):
				raise RuntimeError('LinuxDO 会话已失效（被跳回登录页），请重新取 _t')
		if captured:
			return captured[0]
		raise RuntimeError(f'LinuxDO 未返回授权码（最终停在 {page.url[:60]}）')
	finally:
		await browser.close()


async def relogin(client: httpx.Client, account, domain: str, *, use_proxy: bool = False) -> tuple[bool, str]:
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
		code = await _authorize_linuxdo(
			{'response_type': 'code', 'client_id': status['linuxdo_client_id'], 'state': state},
			account.linuxdo_session,
			use_proxy=use_proxy,
		)

	body = client.get(f'{domain}/api/oauth/{provider}', params={'code': code, 'state': state, 'mode': 'login'}).json()
	if not body.get('success'):
		return False, body.get('message', 'OAuth 回调登录失败')

	checked_in = bool((body.get('data') or {}).get('checked_in'))
	return True, '签到成功，额度已到账' if checked_in else '登录成功，今日已签到'
