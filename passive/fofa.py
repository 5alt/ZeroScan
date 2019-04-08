# encoding=utf-8
import os
import requests
import base64
import re
# from urllib.parse import urlparse
from urlparse import urlparse

def fofa_search(domain):
	if not os.environ.get('fofa_username') or not os.environ.get('fofa_password'):
		return []
	data_set = set()

	# get访问登录页面，获取到token，session，It，这三个数据时页面随机生成的，请求数据时需要加上
	loginurl='https://i.nosec.org/login'
	getlogin=requests.get(loginurl)
	token0=re.findall('<input type="hidden" name="authenticity_token" value="(.*)" />',getlogin.text)
	session0=re.findall('(_nosec_cas_session=.*); path=/',getlogin.headers['Set-Cookie'])
	It0=re.findall('<input type="hidden" name="lt" id="lt" value="(.*)" />',getlogin.text)
	token=token0[0]
	session1=session0[0]
	It=It0[0]
	# 设置data数据和header头，将我们获取的数据加到里面
	datas={
	    'utf8':'%E2%9C%93',
	    'authenticity_token': token,
	    'lt': It,
		'username': os.environ.get('fofa_username'),
		'password': os.environ.get('fofa_password'),
		'rememberMe':'1',
		'button': ''
	}
	headers={
	'Host': 'i.nosec.org',
	'Connection': 'close',
	'Content-Length': '302',
	'Cache-Control': 'max-age=0',
	'Origin': 'https://i.nosec.org',
	'Upgrade-Insecure-Requests': '1',
	'Content-Type': 'application/x-www-form-urlencoded',
	'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.106 Safari/537.36',
	'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
	'Referer': 'https://i.nosec.org/login',
	'Accept-Encoding': 'gzip, deflate, br',
	'Cookie': '__lnkrntdmcvrd=-1; '+session1,
	'Accept-Language': 'zh-CN,zh;q=0.9'
	}
	# 使用session登录，可以保证在之后的访问中保持登录信息
	session=requests.Session()
	postlogin=session.post(loginurl,headers=headers,data=datas)
	sess_headers={
		'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.106 Safari/537.36',
		'X-Requested-With': 'XMLHttpRequest',
		'Accept': 'text/javascript'
	}
	# fofa的登陆界面和一般网站不同，他是类似于一个第三方的登录界面，在nosec登录成功后，你直接访问fofa是出于未登录状态，因为只是存在nosec的cookie，并没有fofa的cookie，
	# 需要访问该链接才会生成fofa的cookie
	signlogin=session.get('https://fofa.so/users/sign_in',headers=sess_headers)

	search='domain="%s"' % domain
	#searchbs64=(str(base64.b64encode(search.encode('utf-8')),'utf-8'))
	searchbs64=str(base64.b64encode(search.encode('utf-8')))
	pageurl=session.get('https://fofa.so/result?full=true&qbase64='+searchbs64)
	pagenum=re.findall('>(\d*)</a> <a class="next_page" rel="next"',pageurl.text)
	pagenum=int(pagenum[0]) if pagenum else 1
	session.headers.update(sess_headers)
	for i in range(1, pagenum+1):
		finurl=session.get('https://fofa.so/result?full=true&page='+str(i)+'&qbase64='+searchbs64)
		finurl=re.findall(r'<a target=\\\"_blank\\\" href=\\\"(.*?)\\\">.*?<i class=\\\"fa fa-link\\\"><\\/i>',finurl.text)
		for j in finurl:
			data_set.add(urlparse(j).hostname)
	return data_set

def passive_search(domain):
    return fofa_search(domain)

if __name__ == '__main__':
    print(fofa_search('5alt.me'))