import requests
from lxml import html
from urlparse import urlparse

class duckduckgo(object):
    def __init__(self):
        self.url = []
        self.page = 0
        self.maxPage = 0

    def search(self,query,s=0,dc=0,nextParams=None, maxPage=None):
        if nextParams == None:
            self.page = 0
        if maxPage:
            self.maxPage = maxPage
        if self.maxPage and self.page >= self.maxPage:
            return self.url

        self.page += 1
        self.query = query
        url = 'https://duckduckgo.com/html/'
        params = {'q':query,'dc':dc,'s':s,'nextParams':nextParams,'v':'l','o':'json','api':'/d.js'}
        r = requests.post(url,data=params)
        tree = html.fromstring(r.content)
        self.find(tree)
        return self.url

    def find(self,tree):
        links,nextParams,s,dc = [tree.xpath('//*[@id="links"]/div/div/h2/a/@href'),tree.xpath('//*[@class="nav-link"]/form/input[4]/@value'),tree.xpath('//*[@class="nav-link"]/form/input[3]/@value'),tree.xpath('//*[@class="nav-link"]/form/input[7]/@value')]
        for link in links:
            self.url.append(link)
        if len(s) == 1:
            self.search(self.query,s=s[0],dc=dc[0],nextParams=nextParams[0])
        elif len(s) >= 2:
            self.search(self.query,s=s[1],dc=dc[1],nextParams=nextParams[0])

def subdomain(domain):
    domains = set()
    dd = duckduckgo()
    urls = dd.search('site:'+domain, maxPage=5)
    for url in urls:
        domains.add(urlparse(url).netloc.split(":")[0])
    print domains
    return list(domains)

if __name__ == '__main__':
    import json
    domains = ['tencent.com']
    for domain in domains:
        data = subdomain(domain)
        if data:
            json.dump(data, open('../input/%s_duck.json' % domain, 'w'))


