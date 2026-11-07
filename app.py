"""Single-owner video approval inbox; publishing is performed by a separate dispatcher."""
import os, json, sqlite3, secrets, time, hmac, hashlib, base64, html, re
from pathlib import Path
from http.cookies import SimpleCookie
from urllib.parse import parse_qs, urlencode, urlsplit
from urllib.request import Request, urlopen
from urllib.error import HTTPError
from cryptography.fernet import Fernet
from contextlib import contextmanager

STYLE='''body{font:18px/1.65 "Malgun Gothic",Arial,sans-serif;background:#10172d;color:#f7f9ff;max-width:760px;margin:30px auto;padding:20px}h1{font-size:30px}a{color:#cdfa64}input,textarea{width:100%;padding:12px;box-sizing:border-box;margin:8px 0 20px;font:inherit}button,.button{background:#cdfa64;color:#10172d;border:0;border-radius:10px;padding:13px 20px;font:inherit;cursor:pointer;margin:5px}section{padding:24px;background:#1c2743;border-radius:20px;margin:20px 0}small{color:#b8c6df}video{width:100%;max-height:65vh;background:#000}.reject{background:#ff8b80}pre{white-space:pre-wrap;overflow-wrap:anywhere}code{overflow-wrap:anywhere}'''
E=lambda x:html.escape(str(x),quote=True)
class SafeError(Exception):
    def __init__(self,message,status=400):self.message=message;self.status=status

class App:
    def __init__(self,data=None,secret=None,password=None,public_url=None):
        self.data=Path(data or os.environ.get('DATA_DIR','./private_data'));self.data.mkdir(parents=True,exist_ok=True)
        self.secret=(secret or os.environ['APP_SECRET']).encode();self.password=password or os.environ['ADMIN_PASSWORD']
        if len(self.secret)<32 or len(self.password)<16:raise ValueError('APP_SECRET >=32 and ADMIN_PASSWORD >=16 characters required')
        self.origin=(public_url or os.environ.get('PUBLIC_URL') or os.environ.get('RENDER_EXTERNAL_URL','')).rstrip('/')
        if not self.origin:raise ValueError('PUBLIC_URL or RENDER_EXTERNAL_URL required')
        self.encrypt=Fernet(base64.urlsafe_b64encode(hashlib.sha256(self.secret+b'/token-encryption').digest()))
        self.dbfile=self.data/'state.sqlite3';self.secure=self.origin.startswith('https://')
        with self.db() as d:d.executescript('''
          CREATE TABLE IF NOT EXISTS sessions(id TEXT PRIMARY KEY,role TEXT,csrf TEXT,expires REAL);
          CREATE TABLE IF NOT EXISTS kv(k TEXT PRIMARY KEY,v BLOB);
          CREATE TABLE IF NOT EXISTS login_attempts(t REAL);
          CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY,version INTEGER,title TEXT,caption TEXT,file TEXT,digest TEXT,review_token TEXT,expires REAL,status TEXT,decision_at REAL,note TEXT DEFAULT '');
          CREATE TABLE IF NOT EXISTS deliveries(job_id TEXT,version INTEGER,provider TEXT,status TEXT,receipt TEXT DEFAULT '',PRIMARY KEY(job_id,version,provider));
          CREATE TABLE IF NOT EXISTS audit(t REAL,job_id TEXT,version INTEGER,event TEXT);
        ''')
    @contextmanager
    def db(self):
        d=sqlite3.connect(self.dbfile,timeout=15);d.row_factory=sqlite3.Row
        try:
            with d:yield d
        finally:d.close()
    def seal(self,key,value):
        with self.db() as d:d.execute('INSERT OR REPLACE INTO kv VALUES(?,?)',(key,self.encrypt.encrypt(json.dumps(value).encode())))
    def unseal(self,key):
        with self.db() as d:r=d.execute('SELECT v FROM kv WHERE k=?',(key,)).fetchone()
        return json.loads(self.encrypt.decrypt(r['v'])) if r else None
    def session(self,env):
        c=SimpleCookie()
        try:c.load(env.get('HTTP_COOKIE',''))
        except Exception:pass
        sid=c['sid'].value if 'sid' in c else ''
        with self.db() as d:r=d.execute('SELECT * FROM sessions WHERE id=? AND expires>?',(hashlib.sha256(sid.encode()).hexdigest(),time.time())).fetchone()
        return dict(r) if r else None
    def new_session(self,role):
        sid=secrets.token_urlsafe(32);csrf=secrets.token_urlsafe(32)
        with self.db() as d:
            d.execute('DELETE FROM sessions WHERE expires<?',(time.time(),))
            d.execute('INSERT INTO sessions VALUES(?,?,?,?)',(hashlib.sha256(sid.encode()).hexdigest(),role,csrf,time.time()+1800))
        return f'sid={sid}; Path=/; HttpOnly; SameSite=Lax; Max-Age=1800'+('; Secure' if self.secure else ''),csrf
    def response(self,status,body='',headers=None,content_type='text/html; charset=utf-8'):
        if isinstance(body,str):body=body.encode()
        base=[('Content-Type',content_type),('Content-Length',str(len(body))),('Cache-Control','no-store'),('Referrer-Policy','no-referrer'),('X-Frame-Options','DENY'),('X-Content-Type-Options','nosniff'),('Content-Security-Policy',"default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; media-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")]
        if self.secure:base.append(('Strict-Transport-Security','max-age=31536000'))
        return status,base+(headers or []),body
    def page(self,body,status=200,headers=None):return self.response(status,f'<!doctype html><html lang="ko"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>영상 검토·승인</title><style>{STYLE}</style><h1>영상 검토·승인</h1>{body}',headers)
    def redirect(self,path,headers=None):return self.response(303,'',[('Location',path)]+(headers or []))
    def form(self,action,csrf,fields,label):return f'<form method="post" action="{action}"><input type="hidden" name="csrf" value="{csrf}">{fields}<button>{label}</button></form>'
    def require(self,s):
        if not s or s['role']!='admin':raise SafeError('관리자 로그인이 필요합니다.',401)
    def csrf(self,env,s,body):
        if not s or env.get('HTTP_ORIGIN')!=self.origin:raise SafeError('화면을 새로 열고 다시 시도하세요.',403)
        token=env.get('HTTP_X_CSRF_TOKEN') or body.get('csrf','')
        if not hmac.compare_digest(token,s['csrf']):raise SafeError('화면을 새로 열고 다시 시도하세요.',403)
    def kakaopost(self,url,fields,bearer=None):
        h={'Content-Type':'application/x-www-form-urlencoded;charset=utf-8'}
        if bearer:h['Authorization']='Bearer '+bearer
        try:
            with urlopen(Request(url,data=urlencode(fields).encode(),headers=h),timeout=25) as r:return json.load(r)
        except HTTPError as ex:raise SafeError(f'카카오 요청이 거절됐습니다(HTTP {ex.code}). 앱 설정과 동의항목을 확인하세요.',502) from None
        except Exception:raise SafeError('카카오 서버에 연결하지 못했습니다. 잠시 후 다시 시도하세요.',502) from None
    def access_token(self):
        d=self.unseal('kakao_tokens')
        if not d:raise SafeError('카카오 계정을 먼저 연결하세요.')
        if d['expires_at']<time.time()+60:
            creds=self.unseal('kakao_credentials');a=self.kakaopost('https://kauth.kakao.com/oauth/token',dict(grant_type='refresh_token',client_id=creds['id'],client_secret=creds['secret'],refresh_token=d['refresh_token']))
            d.update({k:a[k] for k in ['access_token','refresh_token'] if k in a});d['expires_at']=time.time()+a['expires_in'];self.seal('kakao_tokens',d)
        return d['access_token']
    def api_auth(self,env):
        expected=os.environ.get('PUBLISHER_TOKEN','')
        if not expected or not hmac.compare_digest(env.get('HTTP_AUTHORIZATION',''),'Bearer '+expected):raise SafeError('인증되지 않은 요청입니다.',401)
    def __call__(self,env,start):
        try:
            if env.get('HTTP_HOST')!=urlsplit(self.origin).netloc:raise SafeError('잘못된 접속 주소입니다.',400)
            n=int(env.get('CONTENT_LENGTH') or 0)
            if n>50*1024*1024:raise SafeError('50MB 이하의 MP4를 선택하세요.',413)
            raw=env['wsgi.input'].read(n) if n else b''
            ctype=env.get('CONTENT_TYPE','');body={}
            if ctype.startswith('application/x-www-form-urlencoded'):body={k:v[0] for k,v in parse_qs(raw.decode(),keep_blank_values=True).items()}
            elif ctype.startswith('application/json'):body=json.loads(raw or b'{}')
            result=self.route(env,body,raw)
        except SafeError as ex:result=self.page(f'<section><p>{E(ex.message)}</p><a href="/">처음으로</a></section>',ex.status)
        except Exception:result=self.page('<section>요청을 처리하지 못했습니다. 값을 확인한 뒤 다시 시도하세요.</section>',500)
        status,headers,out=result;names={200:'OK',206:'Partial Content',303:'See Other',400:'Bad Request',401:'Unauthorized',403:'Forbidden',404:'Not Found',409:'Conflict',413:'Content Too Large',416:'Range Not Satisfiable',429:'Too Many Requests',500:'Internal Server Error',502:'Bad Gateway'}
        start(f'{status} {names.get(status,"Error")}',headers);return [out]
    def route(self,env,b,raw):
        path=env.get('PATH_INFO','/');method=env['REQUEST_METHOD'];s=self.session(env)
        query={k:v[0] for k,v in parse_qs(env.get('QUERY_STRING','')).items()}
        if path=='/healthz':
            with self.db() as d:d.execute('SELECT 1')
            return self.response(200,'ok',content_type='text/plain')
        if path=='/login' and method=='GET':
            cookie,csrf=self.new_session('anon');nextpath=query.get('next','/')
            if not re.fullmatch(r'/review/[A-Za-z0-9_-]+',nextpath):nextpath='/'
            return self.page('<section><h2>관리자 로그인</h2>'+self.form('/login',csrf,f'<input type="hidden" name="next" value="{E(nextpath)}"><label>관리자 비밀번호<input name="password" type="password" autocomplete="current-password" required></label>','로그인')+'</section>',headers=[('Set-Cookie',cookie)])
        if path=='/login' and method=='POST':
            self.csrf(env,s,b)
            with self.db() as d:
                d.execute('DELETE FROM login_attempts WHERE t<?',(time.time()-600,))
                if d.execute('SELECT count(*) FROM login_attempts').fetchone()[0]>=10:raise SafeError('로그인 시도가 많습니다. 10분 뒤 다시 시도하세요.',429)
                d.execute('INSERT INTO login_attempts VALUES(?)',(time.time(),))
            if not hmac.compare_digest(b.get('password','').encode(),self.password.encode()):raise SafeError('비밀번호를 확인하세요.',401)
            cookie,_=self.new_session('admin')
            with self.db() as d:
                d.execute('DELETE FROM sessions WHERE id=?',(s['id'],));d.execute('DELETE FROM login_attempts')
            dest=b.get('next','/')
            if not re.fullmatch(r'/review/[A-Za-z0-9_-]+',dest):dest='/'
            return self.redirect(dest,[('Set-Cookie',cookie)])
        if path=='/kakao/callback' and method=='GET':
            self.require(s);v=self.unseal('oauth_pending');self.seal('oauth_pending',None)
            if not v or v['session']!=s['id'] or v['expires']<time.time() or not hmac.compare_digest(v['state'],query.get('state','')):raise SafeError('카카오 연결 요청이 만료됐습니다.')
            if query.get('error'):raise SafeError('카카오 연결이 취소됐습니다.')
            creds=self.unseal('kakao_credentials');a=self.kakaopost('https://kauth.kakao.com/oauth/token',dict(grant_type='authorization_code',client_id=creds['id'],client_secret=creds['secret'],redirect_uri=self.origin+'/kakao/callback',code=query.get('code','')))
            if 'talk_message' not in a.get('scope','').split():raise SafeError('메시지 전송 동의가 필요합니다.')
            self.seal('kakao_tokens',dict(access_token=a['access_token'],refresh_token=a['refresh_token'],expires_at=time.time()+a['expires_in']))
            return self.redirect('/')
        if path.startswith('/api/'):
            self.api_auth(env)
            if path=='/api/claim' and method=='POST':
                with self.db() as d:
                    d.execute('BEGIN IMMEDIATE')
                    j=d.execute("SELECT * FROM jobs WHERE status='approved' ORDER BY decision_at LIMIT 1").fetchone()
                    if not j:return self.response(200,'null',content_type='application/json')
                    d.execute("UPDATE jobs SET status='publishing' WHERE id=?",(j['id'],));d.execute('INSERT INTO audit VALUES(?,?,?,?)',(time.time(),j['id'],j['version'],'publisher_claim'))
                    pending=[x['provider'] for x in d.execute("SELECT provider FROM deliveries WHERE job_id=? AND version=? AND status='ready'",(j['id'],j['version']))]
                expire=int(time.time()+3600);payload=f'{j["id"]}:{j["version"]}:{j["digest"]}:{expire}';sig=hmac.new(self.secret,payload.encode(),hashlib.sha256).hexdigest()
                data={k:j[k] for k in ['id','version','title','caption','digest']};data.update(providers=pending,media_url=f'{self.origin}/media/{j["id"]}?expires={expire}&sig={sig}')
                return self.response(200,json.dumps(data),content_type='application/json')
            if path=='/api/complete' and method=='POST':
                with self.db() as d:
                    d.execute('BEGIN IMMEDIATE');j=d.execute('SELECT * FROM jobs WHERE id=?',(b.get('id'),)).fetchone()
                    if not j or j['version']!=b.get('version') or j['status']!='publishing':raise SafeError('대기 중인 게시 작업과 일치하지 않습니다.',409)
                    receipts=b.get('receipts',{})
                    if not isinstance(receipts,dict) or any(k not in ['youtube','instagram'] for k in receipts):raise SafeError('게시 결과 형식이 잘못됐습니다.')
                    for provider,receipt in receipts.items():
                        if not isinstance(receipt,str) or not receipt:raise SafeError('게시 결과 ID가 필요합니다.')
                        d.execute("UPDATE deliveries SET status='scheduled',receipt=? WHERE job_id=? AND version=? AND provider=?",(receipt,j['id'],j['version'],provider))
                    remains=d.execute("SELECT count(*) FROM deliveries WHERE job_id=? AND version=? AND status!='scheduled'",(j['id'],j['version'])).fetchone()[0]
                    new='needs_attention' if remains else 'scheduled'
                    d.execute('UPDATE jobs SET status=? WHERE id=?',(new,j['id']));d.execute('INSERT INTO audit VALUES(?,?,?,?)',(time.time(),j['id'],j['version'],new))
                return self.response(200,json.dumps({'status':new}),content_type='application/json')
            raise SafeError('페이지가 없습니다.',404)
        if path.startswith('/media/') and method=='GET':
            jid=path.split('/')[-1]
            with self.db() as d:j=d.execute('SELECT * FROM jobs WHERE id=?',(jid,)).fetchone()
            if not j:raise SafeError('영상을 찾을 수 없습니다.',404)
            permitted=bool(s and s['role']=='admin')
            exp=query.get('expires','0')
            if exp.isdigit() and time.time()<int(exp)<time.time()+3700:
                payload=f'{j["id"]}:{j["version"]}:{j["digest"]}:{exp}';sig=hmac.new(self.secret,payload.encode(),hashlib.sha256).hexdigest()
                permitted=permitted or hmac.compare_digest(sig,query.get('sig',''))
            if not permitted:raise SafeError('영상 접근 권한이 필요합니다.',403)
            data=(self.data/j['file']).read_bytes();size=len(data);status=200;headers=[('Accept-Ranges','bytes')]
            rg=env.get('HTTP_RANGE')
            if rg:
                m=re.fullmatch(r'bytes=(\d*)-(\d*)',rg)
                if not m or not any(m.groups()):raise SafeError('영상 구간을 읽을 수 없습니다.',416)
                start=int(m[1]) if m[1] else max(0,size-int(m[2]));end=min(size-1,int(m[2]) if m[1] and m[2] else size-1)
                if start>=size or end<start:raise SafeError('영상 구간을 읽을 수 없습니다.',416)
                data=data[start:end+1];status=206;headers.append(('Content-Range',f'bytes {start}-{end}/{size}'))
            return self.response(status,data,headers,'video/mp4')
        if not s or s['role']!='admin':return self.redirect('/login?'+urlencode({'next':path}))
        if method=='POST':self.csrf(env,s,b)
        if path=='/' and method=='GET':
            with self.db() as d:jobs=d.execute('SELECT * FROM jobs ORDER BY rowid DESC LIMIT 100').fetchall()
            cards=''.join(f'<section><h2>{E(j["title"])}</h2><p>v{j["version"]} · {E(j["status"])}</p><a href="/review/{j["review_token"]}">영상 검토</a></section>' for j in jobs)
            connected=bool(self.unseal('kakao_tokens'))
            upload=f'''<section><h2>영상 등록</h2><label>영어 제목<input id="title" maxlength="100"></label><label>게시 설명<textarea id="caption" maxlength="2000"></textarea></label><input id="file" type="file" accept="video/mp4"><button onclick="uploadVideo()">검토함에 등록</button><p id="result"></p><small>게시 대상: 연결된 YouTube·Instagram. 등록만으로 게시되지 않습니다.</small></section><script>async function uploadVideo(){{let f=document.querySelector('#file').files[0];if(!f)return;let r=await fetch('/admin/upload?'+new URLSearchParams({{title:document.querySelector('#title').value,caption:document.querySelector('#caption').value}}),{{method:'POST',headers:{{'Content-Type':'video/mp4','X-CSRF-Token':'{s['csrf']}'}},body:f}});if(r.ok)location.reload();else document.querySelector('#result').textContent='등록 실패: 제목·MP4 형식·용량을 확인하세요.';}}</script>'''
            setup=self.form('/admin/kakao',s['csrf'],'<label>REST API 키<input name="id" type="password" autocomplete="off" required></label><label>클라이언트 시크릿<input name="secret" type="password" autocomplete="off" required></label>','카카오 계정 연결')
            replace=query.get('replace','')
            if replace and re.fullmatch(r'[a-f0-9]{32}',replace):upload=upload.replace("'/admin/upload?'","'/admin/upload?replace="+replace+"&'").replace('영상 등록','새 버전 등록')
            return self.page('<p><strong>검토 서버 준비 단계</strong> · 자동 게시 담당 프로그램은 아직 별도 연결해야 합니다.</p><section><h2>카카오 연결</h2><p>'+('연결 완료' if connected else '연결 전')+'</p><p>등록할 로그인 주소:</p><code>'+E(self.origin+'/kakao/callback')+'</code><p>카카오 제품 링크 관리에 등록할 웹 도메인:</p><code>'+E(self.origin)+'</code>'+setup+'</section>'+upload+cards)
        if path=='/admin/kakao' and method=='POST':
            if not b.get('id') or not b.get('secret'):raise SafeError('앱 키와 클라이언트 시크릿이 필요합니다.')
            self.seal('kakao_credentials',{'id':b['id'].strip(),'secret':b['secret'].strip()});state=secrets.token_urlsafe(32)
            self.seal('oauth_pending',{'state':state,'session':s['id'],'expires':time.time()+600})
            dest='https://kauth.kakao.com/oauth/authorize?'+urlencode(dict(response_type='code',client_id=b['id'].strip(),redirect_uri=self.origin+'/kakao/callback',scope='talk_message',state=state))
            return self.redirect(dest)
        if path=='/admin/upload' and method=='POST':
            title=query.get('title','').strip();caption=query.get('caption','')
            if not 1<=len(title)<=100 or len(caption)>2000 or len(raw)<12 or raw[4:8]!=b'ftyp':raise SafeError('제목·설명 길이 또는 MP4 형식을 확인하세요.')
            jid=query.get('replace') or secrets.token_hex(16);filename=secrets.token_hex(16)+'.mp4';digest=hashlib.sha256(raw).hexdigest();tok=secrets.token_urlsafe(32)
            (self.data/filename).write_bytes(raw)
            with self.db() as d:
                d.execute('BEGIN IMMEDIATE');version=1
                if query.get('replace'):
                    old=d.execute('SELECT * FROM jobs WHERE id=?',(jid,)).fetchone()
                    if not old or old['status'] not in ['pending','rejected','approved']:raise SafeError('게시를 시작한 영상은 교체할 수 없습니다.',409)
                    version=old['version']+1
                    d.execute("UPDATE jobs SET version=?,title=?,caption=?,file=?,digest=?,review_token=?,expires=?,status='pending',decision_at=NULL,note='' WHERE id=?",(version,title,caption,filename,digest,tok,time.time()+172800,jid))
                else:d.execute('INSERT INTO jobs(id,version,title,caption,file,digest,review_token,expires,status) VALUES(?,?,?,?,?,?,?,?,?)',(jid,version,title,caption,filename,digest,tok,time.time()+172800,'pending'))
                for provider in ['youtube','instagram']:d.execute('INSERT INTO deliveries(job_id,version,provider,status) VALUES(?,?,?,?)',(jid,version,provider,'waiting'))
                d.execute('INSERT INTO audit VALUES(?,?,?,?)',(time.time(),jid,version,'uploaded'))
            return self.response(200,json.dumps({'id':jid}),content_type='application/json')
        if path.startswith('/review/'):
            tok=path.split('/')[-1]
            with self.db() as d:j=d.execute('SELECT * FROM jobs WHERE review_token=?',(tok,)).fetchone()
            if not j or j['expires']<time.time():raise SafeError('검토 링크가 만료됐습니다.',404)
            if method=='GET':
                fields=f'<input type="hidden" name="version" value="{j["version"]}"><input type="hidden" name="digest" value="{j["digest"]}"><label>수정 요청 메모<textarea name="note" maxlength="1000"></textarea></label><button name="action" value="approve">이 버전 승인</button><button class="reject" name="action" value="reject">수정 요청</button>'
                decision=self.form(path,s['csrf'],fields,'상태 확인') if j['status']=='pending' else '<p>이미 처리된 버전입니다. 게시가 시작된 영상은 이 화면에서 변경하지 않습니다.</p>'
                return self.page(f'<section><h2>{E(j["title"])}</h2><p>v{j["version"]} · {E(j["status"])}</p><video controls playsinline preload="metadata" src="/media/{j["id"]}"></video><pre>{E(j["caption"])}</pre>{decision}<p><a href="/?replace={j["id"]}">새 영상으로 교체하고 다시 검토</a></p></section>'+self.form('/admin/notify',s['csrf'],f'<input type="hidden" name="id" value="{j["id"]}">','내 카카오톡에 검토 링크 보내기'))
            if method=='POST':
                action=b.get('action')
                if action not in ['approve','reject']:return self.redirect(path)
                status='approved' if action=='approve' else 'rejected'
                with self.db() as d:
                    d.execute('BEGIN IMMEDIATE')
                    n=d.execute("UPDATE jobs SET status=?,decision_at=?,note=? WHERE id=? AND version=? AND digest=? AND status='pending' AND expires>?",(status,time.time(),b.get('note','')[:1000],j['id'],int(b.get('version','0')),b.get('digest',''),time.time())).rowcount
                    if n!=1:raise SafeError('다른 창에서 처리됐거나 영상 버전이 바뀌었습니다. 다시 열어 확인하세요.',409)
                    if status=='approved':d.execute("UPDATE deliveries SET status='ready' WHERE job_id=? AND version=?",(j['id'],j['version']))
                    d.execute('INSERT INTO audit VALUES(?,?,?,?)',(time.time(),j['id'],j['version'],status))
                return self.redirect(path)
        if path=='/admin/notify' and method=='POST':
            with self.db() as d:j=d.execute('SELECT * FROM jobs WHERE id=?',(b.get('id'),)).fetchone()
            if not j or j['status']!='pending' or j['expires']<time.time():raise SafeError('승인 대기 중인 유효한 영상만 알림을 보낼 수 있습니다.')
            url=self.origin+'/review/'+j['review_token'];template={'object_type':'text','text':f'영상 검토 요청\n{j["title"]}\n미리보기를 확인한 뒤 승인 또는 수정 요청을 선택하세요.','link':{'web_url':url,'mobile_web_url':url},'button_title':'영상 확인·승인'}
            a=self.kakaopost('https://kapi.kakao.com/v2/api/talk/memo/default/send',{'template_object':json.dumps(template,ensure_ascii=False)},self.access_token())
            if a.get('result_code')!=0:raise SafeError('알림 전송 결과를 확인하지 못했습니다.',502)
            return self.page('<section><h2>카카오톡으로 검토 링크를 보냈습니다.</h2><p>나와의 채팅을 확인하세요.</p><a href="/">검토함으로</a></section>')
        raise SafeError('페이지가 없습니다.',404)

def create_app():return App()
