import unittest,tempfile,io,json,re,os
from pathlib import Path
from urllib.parse import urlencode
from app import App

class Tests(unittest.TestCase):
    def setUp(self):
        self.testbase=Path(__file__).resolve().parent/'_test_state';self.testbase.mkdir(exist_ok=True)
        self.temp=tempfile.TemporaryDirectory(dir=self.testbase);self.app=App(self.temp.name,'s'*40,'test-password-long-enough','https://approval.example');self.cookie=''
        os.environ['PUBLISHER_TOKEN']='test-publisher-only'
    def tearDown(self):
        assert Path(self.temp.name).resolve().is_relative_to(self.testbase)
        self.temp.cleanup()
    def call(self,path='/',method='GET',fields=None,raw=None,headers=None,cookie=True):
        base,_,query=path.partition('?');body=raw if raw is not None else urlencode(fields or {}).encode()
        env={'HTTP_HOST':'approval.example','PATH_INFO':base,'QUERY_STRING':query,'REQUEST_METHOD':method,'wsgi.input':io.BytesIO(body),'CONTENT_LENGTH':str(len(body)),'CONTENT_TYPE':'video/mp4' if raw is not None else 'application/x-www-form-urlencoded','HTTP_ORIGIN':'https://approval.example'}
        if cookie:env['HTTP_COOKIE']=self.cookie
        env.update(headers or {});out={}
        def start(s,h):out.update(status=int(s.split()[0]),headers=dict(h))
        out['body']=b''.join(self.app(env,start)).decode(errors='replace')
        if out['headers'].get('Set-Cookie'):self.cookie=out['headers']['Set-Cookie'].split(';')[0]
        return out
    def login(self):
        r=self.call('/login');csrf=re.search('name="csrf" value="([^"]+)"',r['body'])[1]
        self.assertEqual(self.call('/login','POST',{'csrf':csrf,'password':'test-password-long-enough'})['status'],303)
        self.csrf=self.app.session({'HTTP_COOKIE':self.cookie})['csrf']
    def upload(self,replace=''):
        r=self.call('/admin/upload?'+urlencode({'title':'A <b>puzzle</b>','caption':'Find it!','replace':replace}),'POST',raw=b'\x00\x00\x00\x18ftypmp42some-video-bytes',headers={'HTTP_X_CSRF_TOKEN':self.csrf})
        self.assertEqual(r['status'],200,r['body']);jid=json.loads(r['body'])['id']
        with self.app.db() as d:return dict(d.execute('SELECT * FROM jobs WHERE id=?',(jid,)).fetchone())
    def decide(self,j,action='approve',**overrides):
        fields={'csrf':self.csrf,'action':action,'version':j['version'],'digest':j['digest']};fields.update(overrides)
        return self.call('/review/'+j['review_token'],'POST',fields)
    def claim(self):return self.call('/api/claim','POST',headers={'HTTP_AUTHORIZATION':'Bearer test-publisher-only'})
    def test_health_and_protected_home(self):
        self.assertEqual(self.call('/healthz')['status'],200);self.assertEqual(self.call('/')['status'],303)
    def test_host_rejected(self):self.assertEqual(self.call('/healthz',headers={'HTTP_HOST':'evil.example'})['status'],400)
    def test_login_csrf(self):self.assertEqual(self.call('/login','POST',{'password':'test-password-long-enough'})['status'],403)
    def test_unauthenticated_upload(self):self.assertEqual(self.call('/admin/upload','POST',raw=b'bad')['status'],303)
    def test_cross_origin_rejected(self):
        self.login();self.assertEqual(self.call('/admin/kakao','POST',{'csrf':self.csrf},headers={'HTTP_ORIGIN':'https://evil.example'})['status'],403)
    def test_kakao_state_rejected(self):
        self.login();self.assertEqual(self.call('/kakao/callback?state=bad')['status'],400)
    def test_token_encryption(self):
        self.app.seal('test',{'secret':'not-plaintext'});self.assertEqual(self.app.unseal('test')['secret'],'not-plaintext')
        self.assertNotIn(b'not-plaintext',self.app.dbfile.read_bytes())
    def test_pending_not_claimed(self):
        self.login();self.upload();self.assertEqual(json.loads(self.claim()['body']),None)
    def test_reject_not_claimed(self):
        self.login();j=self.upload();self.assertEqual(self.decide(j,'reject')['status'],303);self.assertEqual(json.loads(self.claim()['body']),None)
    def test_double_approval_conflicts(self):
        self.login();j=self.upload();self.assertEqual(self.decide(j)['status'],303);self.assertEqual(self.decide(j)['status'],409)
    def test_stale_digest_rejected(self):
        self.login();j=self.upload();self.assertEqual(self.decide(j,digest='incorrect')['status'],409)
    def test_new_version_revokes_old_approval(self):
        self.login();j=self.upload();self.decide(j);new=self.upload(j['id']);self.assertEqual(new['version'],2)
        self.assertEqual(self.call('/review/'+j['review_token'])['status'],404);self.assertEqual(json.loads(self.claim()['body']),None)
    def test_claim_only_once_and_no_replacement_after_claim(self):
        self.login();j=self.upload();self.decide(j);self.assertEqual(json.loads(self.claim()['body'])['id'],j['id']);self.assertEqual(json.loads(self.claim()['body']),None)
        r=self.call('/admin/upload?'+urlencode({'title':'replace','replace':j['id']}),'POST',raw=b'0000ftypmp42bytes',headers={'HTTP_X_CSRF_TOKEN':self.csrf});self.assertEqual(r['status'],409)
    def test_private_media_and_range(self):
        self.login();j=self.upload();path='/media/'+j['id'];self.assertEqual(self.call(path,cookie=False)['status'],403)
        r=self.call(path,headers={'HTTP_RANGE':'bytes=4-7'});self.assertEqual(r['status'],206);self.assertEqual(r['body'],'ftyp')
    def test_signed_media_for_publisher(self):
        self.login();j=self.upload();self.decide(j);url=json.loads(self.claim()['body'])['media_url'];path=url.replace('https://approval.example','')
        self.assertEqual(self.call(path,cookie=False)['status'],200)
        self.assertEqual(self.call(path.replace('sig=','sig=bad'),cookie=False)['status'],403)
    def test_html_escaped(self):
        self.login();j=self.upload();body=self.call('/review/'+j['review_token'])['body'];self.assertIn('&lt;b&gt;',body);self.assertNotIn('A <b>puzzle</b>',body)
    def test_partial_delivery_requires_attention(self):
        self.login();j=self.upload();self.decide(j);self.claim()
        raw=json.dumps({'id':j['id'],'version':1,'receipts':{'youtube':'metricool-post-1'}}).encode()
        r=self.call('/api/complete','POST',raw=raw,headers={'CONTENT_TYPE':'application/json','HTTP_AUTHORIZATION':'Bearer test-publisher-only'})
        self.assertEqual(json.loads(r['body'])['status'],'needs_attention');self.assertEqual(json.loads(self.claim()['body']),None)

if __name__=='__main__':unittest.main(verbosity=2)
