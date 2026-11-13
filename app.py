"""안심여행 — 가족 여행 공유 웹 앱 (Python 3.10+)
설치: python -m pip install -r requirement.txt
실행: python app.py   → http://localhost:8000
배포: HTTPS가 제공되는 Python 호스팅에 GitHub 저장소를 연결하고 위 설치 명령,
      시작 명령 python app.py 를 지정하세요. GitHub Pages에서는 실행되지 않습니다.
환경 변수:
  SECRET_KEY: 운영용 무작위 비밀 문자열(32자 이상 권장)
  DATA_DIR: 영구 저장 디스크 경로(기본 ./ansim_data)
  PORT: 기본 8000 / COOKIE_SECURE=1: HTTPS 운영 시 설정
위치: HTTPS 또는 localhost에서만 브라우저 GPS 허용. 화면을 열고 있을 때만 갱신됩니다.
앱 내 갱신은 12초 주기이며 네이티브 백그라운드 추적/푸시/자동 송금은 없습니다.
그룹 생성자만 부모 역할을 부여합니다. 초대 참여자는 기본 자녀입니다.
서비스 운영 전 개인정보 처리방침, 보호자 동의, 보관/삭제 정책 및 보안 검토가 필요합니다.
SQLite와 업로드는 DATA_DIR에 저장되므로 운영은 단일 인스턴스+영구 디스크를 사용하세요.
"""
import os, io, re, secrets, sqlite3, time
from pathlib import Path
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import Flask, request, session, jsonify, render_template_string, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from PIL import Image, ImageOps, UnidentifiedImageError

ROOT = Path(os.environ.get('DATA_DIR', './ansim_data')).resolve()
ROOT.mkdir(parents=True, exist_ok=True)
(ROOT / 'photos').mkdir(exist_ok=True)
keyfile = ROOT / '.session-key'
if not os.environ.get('SECRET_KEY') and not keyfile.exists():
    keyfile.write_text(secrets.token_hex(32))
    keyfile.chmod(0o600)
app = Flask(__name__)
app.config.update(SECRET_KEY=os.environ.get('SECRET_KEY') or keyfile.read_text(),
                  MAX_CONTENT_LENGTH=9 * 1024 * 1024, SESSION_COOKIE_HTTPONLY=True,
                  SESSION_COOKIE_SAMESITE='Lax', SESSION_COOKIE_SECURE=os.environ.get('COOKIE_SECURE') == '1',
                  PERMANENT_SESSION_LIFETIME=timedelta(days=7))
KST = timezone(timedelta(hours=9))

def now(): return datetime.now(KST).isoformat(timespec='seconds')
def today(): return datetime.now(KST).date().isoformat()
def db():
    c = sqlite3.connect(ROOT / 'travel.sqlite3', timeout=20)
    c.row_factory = sqlite3.Row
    c.execute('PRAGMA foreign_keys=ON')
    return c

def init_db():
    with db() as c:
        c.executescript('''
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, name TEXT NOT NULL, password TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS trips(id INTEGER PRIMARY KEY, title TEXT, start TEXT, end TEXT, code TEXT UNIQUE, owner INTEGER REFERENCES users(id));
        CREATE TABLE IF NOT EXISTS members(trip INTEGER REFERENCES trips(id), user INTEGER REFERENCES users(id), role TEXT, consent INTEGER DEFAULT 0, lat REAL, lon REAL, updated TEXT, PRIMARY KEY(trip,user));
        CREATE TABLE IF NOT EXISTS plans(id INTEGER PRIMARY KEY, trip INTEGER REFERENCES trips(id), title TEXT, at TEXT, status TEXT DEFAULT '예정');
        CREATE TABLE IF NOT EXISTS posts(id INTEGER PRIMARY KEY, trip INTEGER REFERENCES trips(id), user INTEGER REFERENCES users(id), body TEXT, photo TEXT, created TEXT);
        CREATE TABLE IF NOT EXISTS checks(id INTEGER PRIMARY KEY, trip INTEGER REFERENCES trips(id), sender INTEGER REFERENCES users(id), target INTEGER REFERENCES users(id), created TEXT, answered TEXT, response TEXT);
        CREATE TABLE IF NOT EXISTS missions(id INTEGER PRIMARY KEY, trip INTEGER REFERENCES trips(id), maker INTEGER REFERENCES users(id), target INTEGER REFERENCES users(id), title TEXT, amount INTEGER, status TEXT DEFAULT '제안', evidence INTEGER REFERENCES posts(id), created TEXT, paid_at TEXT, received INTEGER DEFAULT 0);
        CREATE TABLE IF NOT EXISTS attempts(ip TEXT PRIMARY KEY, count INTEGER, since REAL);
        ''')
init_db()

def fail(message, code=400): return jsonify(error=message), code

def auth(f):
    @wraps(f)
    def wrapped(*a, **kw):
        if not session.get('uid'): return fail('로그인이 필요합니다.', 401)
        return f(*a, **kw)
    return wrapped

@app.before_request
def csrf():
    if 'csrf' not in session: session['csrf'] = secrets.token_hex(24)
    if request.method == 'POST' and not secrets.compare_digest(request.headers.get('X-CSRF-Token', ''), session['csrf']):
        return fail('보안 토큰이 만료되었습니다. 새로고침해 주세요.', 403)

@app.after_request
def headers(r):
    r.headers['Cache-Control'] = 'no-store'
    r.headers['X-Content-Type-Options'] = 'nosniff'
    r.headers['X-Frame-Options'] = 'DENY'
    r.headers['Referrer-Policy'] = 'same-origin'
    r.headers['Permissions-Policy'] = 'geolocation=(self)'
    return r

@app.errorhandler(413)
def large(e): return fail('사진은 8MB 이하로 올려 주세요.', 413)

def text(d, k, maximum=500):
    v = str(d.get(k, '')).strip()
    if not v or len(v) > maximum: raise ValueError(f'{k}: 1~{maximum}자로 입력하세요.')
    return v

def member(c, tid):
    m = c.execute('SELECT * FROM members WHERE trip=? AND user=?', (tid, session['uid'])).fetchone()
    if not m: raise PermissionError('이 여행의 구성원이 아닙니다.')
    return m

def parent(m):
    if m['role'] != 'parent': raise PermissionError('부모만 사용할 수 있는 기능입니다.')

def child(c, tid, uid):
    if not c.execute("SELECT 1 FROM members WHERE trip=? AND user=? AND role='child'", (tid, uid)).fetchone():
        raise ValueError('자녀 구성원을 선택하세요.')

def trip_active(c, tid):
    t = c.execute('SELECT * FROM trips WHERE id=?', (tid,)).fetchone()
    return t and t['start'] <= today() <= t['end']

@app.errorhandler(ValueError)
def invalid(e): return fail(str(e))
@app.errorhandler(PermissionError)
def forbidden(e): return fail(str(e), 403)

@app.get('/')
def index(): return render_template_string(PAGE, token=session['csrf'])

@app.post('/api/account')
def account():
    d = request.get_json() or {}
    username = text(d, 'username', 40).lower()
    password = text(d, 'password', 200)
    if not re.fullmatch(r'[a-z0-9_.-]{3,40}', username): raise ValueError('아이디는 영문·숫자·_.- 3~40자입니다.')
    ip = request.remote_addr or 'unknown'
    with db() as c:
        a = c.execute('SELECT * FROM attempts WHERE ip=?', (ip,)).fetchone()
        if a and time.time() - a['since'] < 900 and a['count'] >= 20:
            return fail('시도가 너무 많습니다. 15분 뒤 다시 시도하세요.', 429)
        if not a or time.time() - a['since'] >= 900:
            c.execute('INSERT OR REPLACE INTO attempts VALUES(?,?,?)', (ip, 1, time.time()))
        else: c.execute('UPDATE attempts SET count=count+1 WHERE ip=?', (ip,))
    with db() as c:
        if d.get('mode') == 'signup':
            if len(password) < 10: raise ValueError('비밀번호는 10자 이상으로 입력하세요.')
            name = text(d, 'name', 30)
            try:
                uid = c.execute('INSERT INTO users(username,name,password) VALUES(?,?,?)',
                                (username, name, generate_password_hash(password))).lastrowid
            except sqlite3.IntegrityError: return fail('이미 사용 중인 아이디입니다.')
        else:
            u = c.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
            if not u or not check_password_hash(u['password'], password): return fail('아이디 또는 비밀번호가 맞지 않습니다.', 401)
            uid = u['id']
        c.execute('DELETE FROM attempts WHERE ip=?', (ip,))
    session.clear(); session['uid'] = uid; session['csrf'] = secrets.token_hex(24); session.permanent = True
    return jsonify(ok=True)

@app.post('/api/logout')
@auth
def logout():
    with db() as c:
        c.execute('UPDATE members SET consent=0,lat=NULL,lon=NULL,updated=NULL WHERE user=?', (session['uid'],))
    session.clear()
    return jsonify(ok=True)

@app.get('/api/state')
@auth
def state():
    uid = session['uid']
    with db() as c:
        # 여행 종료 후 서버에 남은 위치와 동의 상태도 제거합니다.
        c.execute('UPDATE members SET consent=0,lat=NULL,lon=NULL,updated=NULL WHERE trip IN (SELECT id FROM trips WHERE end<?)', (today(),))
        user = dict(c.execute('SELECT id,name,username FROM users WHERE id=?', (uid,)).fetchone())
        trips = [dict(x) for x in c.execute('SELECT t.*,m.role FROM trips t JOIN members m ON m.trip=t.id WHERE m.user=? ORDER BY t.id DESC', (uid,))]
        tid = request.args.get('trip', type=int)
        if not tid or not any(t['id'] == tid for t in trips): tid = trips[0]['id'] if trips else None
        out = dict(user=user, trips=trips, trip=tid, members=[], plans=[], posts=[], checks=[], missions=[])
        if tid:
            member(c, tid)
            for x in c.execute('SELECT m.*,u.name FROM members m JOIN users u ON u.id=m.user WHERE trip=?', (tid,)):
                m = dict(x)
                fresh = m['updated'] and (datetime.now(KST) - datetime.fromisoformat(m['updated'])).total_seconds() < 300
                if not (m['consent'] and trip_active(c, tid) and fresh): m['lat'] = m['lon'] = None
                out['members'].append(m)
            queries = {
                'plans': 'SELECT * FROM plans WHERE trip=? ORDER BY at,id',
                'posts': 'SELECT p.*,u.name FROM posts p JOIN users u ON u.id=p.user WHERE trip=? ORDER BY p.id DESC LIMIT 100',
                'checks': 'SELECT * FROM checks WHERE trip=? ORDER BY id DESC LIMIT 100',
                'missions': 'SELECT * FROM missions WHERE trip=? ORDER BY id DESC LIMIT 100'}
            for k, q in queries.items(): out[k] = [dict(x) for x in c.execute(q, (tid,))]
    return jsonify(out)

@app.post('/api/trips')
@auth
def trips():
    d = request.get_json() or {}
    with db() as c:
        if d.get('action') == 'join':
            t = c.execute('SELECT * FROM trips WHERE code=?', (text(d, 'code', 20).upper(),)).fetchone()
            if not t: return fail('초대 코드를 확인하세요.')
            c.execute("INSERT OR IGNORE INTO members(trip,user,role) VALUES(?,?,'child')", (t['id'], session['uid']))
            tid = t['id']
        else:
            title = text(d, 'title', 80)
            start, end = text(d, 'start', 10), text(d, 'end', 10)
            datetime.strptime(start, '%Y-%m-%d'); datetime.strptime(end, '%Y-%m-%d')
            if start > end: raise ValueError('종료일은 시작일 이후여야 합니다.')
            tid = c.execute('INSERT INTO trips(title,start,end,code,owner) VALUES(?,?,?,?,?)',
                            (title, start, end, secrets.token_hex(5).upper(), session['uid'])).lastrowid
            c.execute("INSERT INTO members(trip,user,role) VALUES(?,?,'parent')", (tid, session['uid']))
    return jsonify(ok=True, trip=tid)

@app.post('/api/action')
@auth
def action():
    d = request.get_json() or {}; tid = int(d.get('trip', 0)); uid = session['uid']; action = d.get('action')
    with db() as c:
        m = member(c, tid)
        if action == 'role':
            t = c.execute('SELECT * FROM trips WHERE id=?', (tid,)).fetchone()
            if t['owner'] != uid: raise PermissionError('그룹 생성자만 역할을 변경할 수 있습니다.')
            target = int(d['target']); role = d.get('role')
            if role not in ('parent', 'child') or target == uid: raise ValueError('역할 변경 대상을 확인하세요.')
            c.execute('UPDATE members SET role=? WHERE trip=? AND user=?', (role, tid, target))
        elif action == 'plan_add':
            title = text(d, 'title', 100); at = text(d, 'at', 20)
            datetime.fromisoformat(at)
            t = c.execute('SELECT * FROM trips WHERE id=?', (tid,)).fetchone()
            if not t['start'] <= at[:10] <= t['end']: raise ValueError('여행 기간 안의 일정을 입력하세요.')
            c.execute('INSERT INTO plans(trip,title,at) VALUES(?,?,?)', (tid, title, at))
        elif action == 'plan_status':
            status = d.get('status')
            if status not in ('예정', '진행 중', '완료'): raise ValueError('잘못된 일정 상태입니다.')
            c.execute('UPDATE plans SET status=? WHERE id=? AND trip=?', (status, int(d['id']), tid))
        elif action == 'consent':
            enabled = bool(d.get('enabled'))
            if enabled and not trip_active(c, tid): raise ValueError('위치 공유는 여행 기간에만 가능합니다. (한국 시간 기준)')
            c.execute('UPDATE members SET consent=?,lat=NULL,lon=NULL,updated=NULL WHERE trip=? AND user=?', (int(enabled), tid, uid))
        elif action == 'location':
            if not m['consent'] or not trip_active(c, tid): raise PermissionError('위치 공유 동의와 여행 기간을 확인하세요.')
            lat, lon = float(d['lat']), float(d['lon'])
            if not (-90 <= lat <= 90 and -180 <= lon <= 180): raise ValueError('잘못된 좌표입니다.')
            c.execute('UPDATE members SET lat=?,lon=?,updated=? WHERE trip=? AND user=?', (lat, lon, now(), tid, uid))
        elif action == 'check':
            parent(m); target = int(d['target']); child(c, tid, target)
            recent = c.execute('SELECT created FROM checks WHERE trip=? AND sender=? AND target=? ORDER BY id DESC LIMIT 1', (tid, uid, target)).fetchone()
            if recent and (datetime.now(KST)-datetime.fromisoformat(recent['created'])).total_seconds() < 600:
                raise ValueError('같은 자녀에게는 10분에 한 번 요청할 수 있습니다.')
            c.execute('INSERT INTO checks(trip,sender,target,created) VALUES(?,?,?,?)', (tid, uid, target, now()))
        elif action == 'well':
            if m['role'] != 'child': raise PermissionError('자녀가 응답할 수 있습니다.')
            c.execute("UPDATE checks SET answered=?,response='잘 지내요 💚' WHERE trip=? AND target=? AND answered IS NULL", (now(), tid, uid))
            c.execute('INSERT INTO posts(trip,user,body,created) VALUES(?,?,?,?)', (tid, uid, '잘 지내요 💚', now()))
        elif action == 'mission_add':
            parent(m); target = int(d['target']); child(c, tid, target)
            amount = int(d.get('amount', 0))
            if not 0 <= amount <= 1000000: raise ValueError('용돈은 0~1,000,000원으로 입력하세요.')
            c.execute('INSERT INTO missions(trip,maker,target,title,amount,created) VALUES(?,?,?,?,?,?)', (tid, uid, target, text(d, 'title', 200), amount, now()))
        elif action == 'mission':
            q = c.execute('SELECT * FROM missions WHERE id=? AND trip=?', (int(d['id']), tid)).fetchone()
            if not q: raise ValueError('미션을 찾을 수 없습니다.')
            move = d.get('move'); status = q['status']
            if move in ('수락', '거절'):
                if uid != q['target'] or status != '제안': raise PermissionError('미션 대상자만 수락 또는 거절할 수 있습니다.')
                c.execute('UPDATE missions SET status=? WHERE id=?', ('수행 중' if move == '수락' else '거절', q['id']))
            elif move == '수령 확인':
                if uid != q['target'] or status != '지급 기록 완료': raise PermissionError('지급 기록 후 대상자가 확인할 수 있습니다.')
                c.execute('UPDATE missions SET received=1 WHERE id=?', (q['id'],))
            else:
                parent(m)
                if uid != q['maker']: raise PermissionError('미션을 제안한 부모만 확인할 수 있습니다.')
                transitions = {('확인 대기', '승인'): '지급 대기', ('확인 대기', '재인증 요청'): '수행 중', ('지급 대기', '지급했어요'): '지급 기록 완료'}
                new = transitions.get((status, move))
                if not new: raise ValueError('현재 상태에서 할 수 없는 작업입니다.')
                c.execute('UPDATE missions SET status=?,paid_at=? WHERE id=?', (new, now() if new == '지급 기록 완료' else None, q['id']))
        elif action == 'delete_post':
            p = c.execute('SELECT * FROM posts WHERE id=? AND trip=?', (int(d['id']), tid)).fetchone()
            if not p or p['user'] != uid: raise PermissionError('본인 게시물만 삭제할 수 있습니다.')
            c.execute("UPDATE missions SET evidence=NULL,status=CASE WHEN status='확인 대기' THEN '수행 중' ELSE status END WHERE evidence=?", (p['id'],))
            c.execute('DELETE FROM posts WHERE id=?', (p['id'],))
            if p['photo']: (ROOT / 'photos' / p['photo']).unlink(missing_ok=True)
        else: raise ValueError('지원하지 않는 작업입니다.')
    return jsonify(ok=True)

@app.post('/api/post')
@auth
def post():
    tid = int(request.form.get('trip', 0)); uid = session['uid']
    body = request.form.get('body', '').strip(); filename = None
    if len(body) > 1000: raise ValueError('글은 1,000자 이하로 입력하세요.')
    upload = request.files.get('photo'); image_bytes = None
    if upload and upload.filename:
        data = upload.read(8*1024*1024+1)
        if len(data) > 8*1024*1024: raise ValueError('사진은 8MB 이하로 올려 주세요.')
        try:
            with Image.open(io.BytesIO(data)) as image:
                if image.width * image.height > 25000000: raise ValueError('사진 해상도가 너무 큽니다. 줄여서 올려 주세요.')
                image = ImageOps.exif_transpose(image).convert('RGB'); image.thumbnail((1600, 1600))
                buf = io.BytesIO(); image.save(buf, format='JPEG', quality=85); image_bytes = buf.getvalue()
        except (UnidentifiedImageError, OSError, Image.DecompressionBombError): raise ValueError('읽을 수 있는 사진 파일을 올려 주세요.')
        filename = secrets.token_hex(20) + '.jpg'  # 재인코딩하여 GPS 등 EXIF 제거
    if not body and not filename: raise ValueError('글이나 사진을 추가하세요.')
    try:
        with db() as c:
            m = member(c, tid)
            mission_id = request.form.get('mission')
            if mission_id:
                q = c.execute("SELECT * FROM missions WHERE id=? AND trip=? AND target=? AND status='수행 중'", (int(mission_id), tid, uid)).fetchone()
                if not q: raise PermissionError('수행 중인 본인 미션만 인증할 수 있습니다.')
            if filename: (ROOT / 'photos' / filename).write_bytes(image_bytes)
            pid = c.execute('INSERT INTO posts(trip,user,body,photo,created) VALUES(?,?,?,?,?)', (tid, uid, body, filename, now())).lastrowid
            if mission_id: c.execute("UPDATE missions SET status='확인 대기',evidence=? WHERE id=?", (pid, int(mission_id)))
            if m['role'] == 'child' and request.form.get('reply') == '1':
                c.execute("UPDATE checks SET answered=?,response='사진/글로 안부를 전했어요' WHERE trip=? AND target=? AND answered IS NULL", (now(), tid, uid))
    except Exception:
        if filename: (ROOT / 'photos' / filename).unlink(missing_ok=True)
        raise
    return jsonify(ok=True)

@app.get('/photo/<int:pid>')
@auth
def photo(pid):
    with db() as c:
        p = c.execute('SELECT * FROM posts WHERE id=?', (pid,)).fetchone()
        if not p or not p['photo']: return fail('사진이 없습니다.', 404)
        member(c, p['trip'])
        return send_file(ROOT / 'photos' / p['photo'], mimetype='image/jpeg')

PAGE = r'''<!doctype html><html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>안심여행</title><style>
:root{--green:#176c54;--ink:#1c3530;--muted:#586e67;--bg:#f3f7f4}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.6 system-ui,'Apple SD Gothic Neo',sans-serif}header{background:#fff;border-bottom:1px solid #dfebe4;padding:18px 5%;display:flex;justify-content:space-between;align-items:center;gap:12px}h1{font-size:23px;margin:0}h2{font-size:21px;margin:0 0 12px}h3{font-size:16px;margin:0 0 8px}p{margin:8px 0}.sub,small{color:var(--muted)}main{max-width:960px;margin:22px auto;padding:0 16px 90px}.card{background:#fff;border:1px solid #dfe9e2;border-radius:20px;padding:22px;margin:14px 0;box-shadow:0 5px 20px #173c2905}.hero{background:#e3f1e8}.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}.spread{justify-content:space-between}.grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}label{display:block;margin:12px 0 5px;font-size:14px}input,textarea,select,button{font:inherit;border-radius:11px;padding:11px 13px}input,textarea,select{width:100%;border:1px solid #c5d5cc;background:#fff;color:var(--ink)}textarea{min-height:90px}button{border:0;background:var(--green);color:#fff;cursor:pointer;min-height:44px}button:disabled{opacity:.5;cursor:wait}button.soft{background:#edf4ef;color:var(--green)}button.danger{background:#fff0ee;color:#9d3026}a{color:var(--green)}nav{display:flex;gap:7px;overflow:auto;padding:10px 0;position:sticky;top:0;background:var(--bg);z-index:2}nav button{white-space:nowrap;background:#e5eee8;color:#264e40}nav button.on{background:var(--green);color:#fff}.badge{display:inline-block;background:#e8f3ec;color:#235840;padding:3px 10px;border-radius:30px;font-size:12px}.item{padding:14px 0;border-top:1px solid #edf1ed}.photo{max-height:450px;width:100%;object-fit:contain;background:#f1f4f1;border-radius:12px;margin-top:10px}.track{height:9px;background:#dce8de;border-radius:8px;overflow:hidden}.track div{height:100%;background:#228463}.hidden{display:none!important}#toast{position:fixed;bottom:20px;left:50%;transform:translateX(-50%);background:#17392e;color:white;padding:12px 20px;border-radius:12px;z-index:20;max-width:92vw;white-space:pre-wrap}.note{font-size:13px;color:#586e67}.link{background:none;color:var(--green);padding:5px}.stat{font-size:32px;font-weight:750}.auth{max-width:440px;margin:32px auto}.empty{padding:25px;text-align:center;color:var(--muted)}input[type=checkbox]{width:auto}pre{white-space:pre-wrap}button:focus-visible,a:focus-visible,input:focus-visible{outline:3px solid #e0b441;outline-offset:2px}@media(max-width:650px){.grid{grid-template-columns:1fr;gap:0}.card{padding:18px}header{padding:14px 18px}h1{font-size:20px}main{margin-top:14px}.row>*{max-width:100%}}
</style></head><body><header><div><h1>🌿 안심여행</h1><small>걱정은 가볍게, 추억은 함께</small></div><div id="who"></div></header><main>
<section id="auth" class="card auth"><span class="badge">가족만의 여행 공간</span><h2 style="margin-top:15px">안심하고 떠나요 ✈️</h2><p class="sub">일정과 사진으로 안부를 전해요.</p><form id="loginForm"><label>아이디</label><input name="username" required minlength="3" maxlength="40" autocomplete="username" placeholder="영문·숫자 3자 이상"><label>비밀번호</label><input name="password" required type="password" maxlength="200" autocomplete="current-password"><div id="nameField" class="hidden"><label>가족에게 보일 이름</label><input name="name" maxlength="30" autocomplete="nickname"></div><button style="width:100%;margin-top:20px" id="loginButton">로그인</button></form><button class="link" id="toggleAuth">처음 오셨나요? 회원가입</button><p class="note">초대 코드는 믿을 수 있는 가족에게만 공유하세요.</p></section>
<section id="dashboard" class="hidden"><div class="row spread"><div style="flex:1"><label for="tripSelect">우리 가족 여행</label><select id="tripSelect"></select></div><button class="soft" id="openSetup">＋ 여행 만들기 / 참여</button></div>
<div id="setup" class="card hidden"><div class="grid"><form id="createForm"><h3>새 여행 만들기</h3><label>여행 이름</label><input name="title" required maxlength="80" placeholder="우리 가족 제주 여행"><label>시작일 (한국 시간 기준)</label><input name="start" type="date" required><label>종료일</label><input name="end" type="date" required><button style="margin-top:12px">여행 만들기</button><p class="note">생성자는 부모 역할이며 참여자 역할을 관리합니다.</p></form><form id="joinForm"><h3>초대 코드로 참여</h3><label>초대 코드</label><input name="code" required maxlength="20" placeholder="가족에게 받은 코드"><button style="margin-top:12px">참여하기</button><p class="note">참여자는 자녀 역할로 시작합니다.</p></form></div></div>
<div id="travelArea"><div class="card hero" id="summary"></div><nav id="tabs"></nav><section id="panel"></section></div>
</section></main><div id="toast" class="hidden" role="status" aria-live="polite"></div>
<script>
const CSRF={{ token|tojson }};
let S=null, tab='일정', signup=false, watch=null, locationTrip=null, timer=null, busy=false, lastLocation=0;
const $=id=>document.getElementById(id);
const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const stamp=v=>v?esc(v.replace('T',' ').replace('+09:00','')):'아직 없음';
const name=id=>S?.members.find(m=>m.user===id)?.name||'구성원';
const me=()=>S.members.find(m=>m.user===S.user.id);
const trip=()=>S.trips.find(t=>t.id===S.trip);
function toast(msg){$('toast').textContent=msg;$('toast').classList.remove('hidden');clearTimeout(timer);timer=setTimeout(()=>$('toast').classList.add('hidden'),5500)}
async function api(url,data){const opts=data===undefined?{}:{method:'POST',headers:{'X-CSRF-Token':CSRF},body:data instanceof FormData?data:JSON.stringify(data)};if(data!==undefined&&!(data instanceof FormData))opts.headers['Content-Type']='application/json';const r=await fetch(url,opts);let x;try{x=await r.json()}catch{throw Error('서버 응답을 확인할 수 없습니다. 다시 시도하세요.')}if(!r.ok)throw Error(x.error||'처리하지 못했습니다.');return x}
async function act(action,extra={}){await api('/api/action',{trip:S.trip,action,...extra});await refresh();}
function btn(label,action,extra={},cls='soft'){return `<button class="${cls}" data-action="${action}" data-extra="${esc(JSON.stringify(extra))}">${esc(label)}</button>`}
function children(){return S.members.filter(m=>m.role==='child').map(m=>`<option value="${m.user}">${esc(m.name)}</option>`).join('')}
function stopWatch(){if(watch!==null)navigator.geolocation.clearWatch(watch);watch=null;locationTrip=null;lastLocation=0}
async function refresh(){if(busy)return;S=await api('/api/state'+(S?.trip?'?trip='+S.trip:''));$('auth').classList.add('hidden');$('dashboard').classList.remove('hidden');render();const own=me();if(watch!==null&&(!own?.consent||locationTrip!==S.trip||!active()))stopWatch()}
function active(){if(!trip())return false;let day=new Intl.DateTimeFormat('sv-SE',{timeZone:'Asia/Seoul',year:'numeric',month:'2-digit',day:'2-digit'}).format(new Date());return trip().start<=day&&day<=trip().end}
function render(){
$('who').innerHTML=`<small>${esc(S.user.name)}님</small> <button class="soft" id="logout">로그아웃</button>`;
$('tripSelect').innerHTML=S.trips.length?S.trips.map(t=>`<option value="${t.id}" ${t.id===S.trip?'selected':''}>${esc(t.title)}</option>`).join(''):'<option>아직 여행이 없어요</option>';
$('travelArea').classList.toggle('hidden',!S.trip);if(!S.trip){$('setup').classList.remove('hidden');return}
const done=S.plans.filter(p=>p.status==='완료').length,total=S.plans.length,pct=total?Math.round(done/total*100):0;
$('summary').innerHTML=`<div class="row spread"><div><span class="badge">${me().role==='parent'?'부모':'자녀'} · ${active()?'여행 기간 중':'여행 기간 외'}</span><h2 style="margin-top:9px">${esc(trip().title)}</h2><small>${esc(trip().start)} ~ ${esc(trip().end)}</small></div><div><div class="stat">${pct}%</div><small>일정 ${done}/${total} 완료</small></div></div><div class="track" style="margin-top:16px"><div style="width:${pct}%"></div></div>`;
$('tabs').innerHTML=['일정','사진·안부','위치','미션·용돈','가족'].map(t=>`<button data-tab="${t}" class="${tab===t?'on':''}">${t}</button>`).join('');
let h='';
if(tab==='일정'){
h=`<div class="card"><h2>🧭 여행 일정</h2><p class="note">예정 시각과 실제 진행 상태는 별개입니다. 가족이 상태를 직접 변경해요.</p>${S.plans.map(p=>`<div class="item"><small>${stamp(p.at)}</small><h3>${esc(p.title)}</h3><div class="row">${['예정','진행 중','완료'].map(v=>btn((p.status===v?'✓ ':'')+v,'plan_status',{id:p.id,status:v},p.status===v?'':'soft')).join('')}</div></div>`).join('')||'<p class="empty">첫 일정을 추가해 보세요.</p>'}</div><form class="card" id="planForm"><h3>일정 추가</h3><label>할 일 / 방문 장소</label><input name="title" required maxlength="100"><label>예정 시각 (한국 시간)</label><input name="at" type="datetime-local" required min="${trip().start}T00:00" max="${trip().end}T23:59"><button style="margin-top:12px">일정 추가</button></form>`;
}else if(tab==='사진·안부'){
let pending=S.checks.filter(c=>c.target===S.user.id&&!c.answered);
h=`<div class="card hero"><h2>💚 부모가 걱정돼!</h2>${me().role==='child'?`<p>${pending.length?`안부 요청 ${pending.length}건이 기다려요.`:'사진이나 한 번의 터치로 안부를 전해요.'}</p>${btn('잘 지내요 💚','well',{},'')}`:`<p>안부 요청은 같은 자녀에게 10분에 한 번 보낼 수 있어요.</p><div class="row">${S.members.filter(m=>m.role==='child').map(m=>btn(m.name+'에게 안부 요청','check',{target:m.user})).join('')||'참여한 자녀가 아직 없어요.'}</div>`}<p class="note">미응답은 위험을 뜻하지 않습니다. 앱이 열려 있을 때 새 요청을 확인할 수 있어요.</p></div><form class="card" id="postForm" enctype="multipart/form-data"><h3>📸 오늘의 한 장</h3><label>짧은 이야기</label><textarea name="body" maxlength="1000" placeholder="오늘 바다에 도착했어요!"></textarea><label>사진 (8MB 이하)</label><input name="photo" type="file" accept="image/jpeg,image/png,image/webp"><label><input name="reply" type="checkbox" value="1" checked> 게시와 함께 내 미응답 안부 요청에 응답하기</label><button style="margin-top:12px">가족에게 공유</button><p class="note">가족 전용 피드입니다. 업로드 사진의 GPS 등 EXIF 정보는 제거합니다.</p></form><div class="card"><h3>안부 요청 기록</h3>${S.checks.slice(0,15).map(c=>`<div class="item">${esc(name(c.sender))} → ${esc(name(c.target))} <span class="badge">${c.answered?'응답 완료':'미확인'}</span><br><small>요청 ${stamp(c.created)}${c.answered?' · 응답 '+stamp(c.answered):''}</small><p>${esc(c.response||'')}</p></div>`).join('')||'<p class="sub">아직 안부 요청이 없어요.</p>'}</div>`;
h+=S.posts.map(p=>`<article class="card" id="post-${p.id}"><div class="row spread"><strong>${esc(p.name)}</strong><small>${stamp(p.created)}</small></div><p style="white-space:pre-wrap">${esc(p.body)}</p>${p.photo?`<img class="photo" loading="lazy" src="/photo/${p.id}" alt="${esc(p.name)}님의 여행 사진">`:''}${p.user===S.user.id?btn('게시물 삭제','delete_post',{id:p.id},'danger'):''}</article>`).join('');
}else if(tab==='위치'){
h=`<div class="card"><h2>📍 함께 안심하는 위치 공유</h2><p>동의한 여행 기간에만 위치를 공유해요. 중지하면 서버의 현재 좌표도 즉시 지워집니다.</p><p class="note">앱 화면을 열어 둔 동안만 갱신되며 5분 이상 갱신되지 않은 좌표는 가족에게 표시하지 않습니다. 백그라운드 추적은 하지 않습니다. 지도 링크를 누르면 해당 좌표가 외부 지도 서비스로 전달됩니다.</p><div class="row"><button id="gpsStart">동의하고 위치 공유 시작</button>${btn('위치 공유 중지','gps_stop',{},'danger')}</div><p class="note">내 공유 동의: ${me().consent?'켜짐':'꺼짐'} · 이 기기의 GPS: ${watch!==null?'갱신 중':'중지'}<br>GPS는 HTTPS 또는 localhost에서 사용할 수 있습니다.</p></div><div class="card">${S.members.map(m=>`<div class="item"><h3>${esc(m.name)} ${m.user===S.user.id?'(나)':''}</h3>${m.lat!==null?`<p>${Number(m.lat).toFixed(5)}, ${Number(m.lon).toFixed(5)}</p><a href="https://www.openstreetmap.org/?mlat=${m.lat}&mlon=${m.lon}#map=16/${m.lat}/${m.lon}" target="_blank" rel="noopener noreferrer">지도에서 보기 ↗</a><br><small>마지막 갱신 ${stamp(m.updated)}</small>`:'<p class="sub">공유 중이 아니거나 최근 위치가 없습니다.</p>'}</div>`).join('')}</div>`;
}else if(tab==='미션·용돈'){
h=`<div class="card hero"><h2>🎯 여행의 작은 미션</h2><p>제안 → 수락 → 인증 → 부모 확인 → 용돈 지급 기록</p><p class="note">미션은 거절할 수 있어요. 안전 연락이나 위치 공유를 보상의 조건으로 삼지 마세요.<br><strong>실제 송금 기능은 없습니다. 지급 기록은 부모의 입력이며 앱이 송금 여부를 확인하지 않습니다.</strong></p></div>`;
if(me().role==='parent')h+=`<form class="card" id="missionForm"><h3>미션 제안하기</h3><label>대상 자녀</label><select name="target" required>${children()}</select><label>미션 내용</label><input name="title" required maxlength="200" placeholder="현지 음식 사진 한 장 공유하기"><label>용돈 (원)</label><input name="amount" type="number" min="0" max="1000000" step="1" value="10000" required><button style="margin-top:12px">미션 제안</button></form>`;
h+=S.missions.map(q=>{let controls='';if(q.target===S.user.id){if(q.status==='제안')controls=btn('수락','mission',{id:q.id,move:'수락'},'')+' '+btn('거절','mission',{id:q.id,move:'거절'});if(q.status==='수행 중')controls=`<form class="evidence" data-id="${q.id}"><label>수행 인증 글</label><textarea name="body" maxlength="1000" placeholder="어떻게 수행했는지 적어 주세요"></textarea><label>인증 사진 (선택)</label><input name="photo" type="file" accept="image/jpeg,image/png,image/webp"><button style="margin-top:10px">인증 제출</button></form>`;if(q.status==='지급 기록 완료'&&!q.received)controls=btn('용돈 받았어요','mission',{id:q.id,move:'수령 확인'});}if(q.maker===S.user.id&&me().role==='parent'){if(q.status==='확인 대기')controls=btn('인증 승인','mission',{id:q.id,move:'승인'},'')+' '+btn('재인증 요청','mission',{id:q.id,move:'재인증 요청'});if(q.status==='지급 대기')controls=btn('외부에서 송금했어요 · 기록하기','mission',{id:q.id,move:'지급했어요'},'');}const ev=S.posts.find(p=>p.id===q.evidence);return `<article class="card"><span class="badge">${esc(q.status)}</span><h3 style="margin-top:10px">${esc(q.title)}</h3><p>${esc(name(q.maker))} → ${esc(name(q.target))} · <strong>${Number(q.amount).toLocaleString()}원</strong></p>${q.evidence?`<div class="item"><small>인증 게시물 #${q.evidence}</small>${ev?`<p style="white-space:pre-wrap">${esc(ev.body)}</p>`:''}<img class="photo" src="/photo/${q.evidence}" alt="사진이 없는 글 인증일 수 있습니다" onerror="this.hidden=true"></div>`:''}<div class="row">${controls}</div>${q.paid_at?`<p class="note">부모의 지급 기록: ${stamp(q.paid_at)}<br>자녀 수령 확인: ${q.received?'확인했어요':'아직 미확인'}</p>`:''}</article>`}).join('')||'<p class="empty">아직 미션이 없어요.</p>';
}else if(tab==='가족'){
h=`<div class="card"><h2>🏡 우리 여행 가족</h2><p>초대 코드 <strong style="letter-spacing:2px">${esc(trip().code)}</strong></p><p class="note">코드를 아는 사람은 그룹에 참여할 수 있습니다. 외부에 공개하지 마세요.</p>${S.members.map(m=>`<div class="item row spread"><div><strong>${esc(m.name)}</strong> <span class="badge">${m.role==='parent'?'부모':'자녀'}</span></div>${trip().owner===S.user.id&&m.user!==S.user.id?btn(m.role==='child'?'부모로 변경':'자녀로 변경','role',{target:m.user,role:m.role==='child'?'parent':'child'}):''}</div>`).join('')}<p class="note">그룹 생성자만 구성원의 역할을 바꿀 수 있습니다. 부모 역할은 믿을 수 있는 보호자에게만 부여하세요.</p></div>`;
}
$('panel').innerHTML=h;
}
async function gps(){if(!navigator.geolocation)throw Error('이 브라우저는 위치 기능을 지원하지 않습니다.');if(!window.isSecureContext)throw Error('위치 공유에는 HTTPS 연결이 필요합니다.');if(!confirm('여행 기간 동안 이 화면이 열려 있을 때 현재 위치를 가족에게 공유합니다. 언제든 중지할 수 있습니다. 동의하시나요?'))return;stopWatch();await act('consent',{enabled:true});locationTrip=S.trip;watch=navigator.geolocation.watchPosition(async pos=>{if(Date.now()-lastLocation<15000)return;lastLocation=Date.now();try{await api('/api/action',{trip:locationTrip,action:'location',lat:pos.coords.latitude,lon:pos.coords.longitude});if(tab==='위치')await refresh()}catch(e){stopWatch();toast(e.message)}},async e=>{stopWatch();try{await act('consent',{enabled:false})}catch{}toast('위치 확인 실패: 권한과 GPS 설정을 확인해 주세요. '+e.message)},{enableHighAccuracy:true,maximumAge:15000,timeout:20000});render();}
$('toggleAuth').onclick=()=>{signup=!signup;$('nameField').classList.toggle('hidden',!signup);$('loginButton').textContent=signup?'회원가입하고 시작':'로그인';$('toggleAuth').textContent=signup?'이미 계정이 있어요 · 로그인':'처음 오셨나요? 회원가입';$('loginForm').elements.name.required=signup};
$('loginForm').onsubmit=async e=>{e.preventDefault();let b=$('loginButton');b.disabled=true;try{await api('/api/account',{...Object.fromEntries(new FormData(e.target)),mode:signup?'signup':'login'});location.reload()}catch(e){toast(e.message)}finally{b.disabled=false}};
$('openSetup').onclick=()=>$('setup').classList.toggle('hidden');
$('tripSelect').onchange=async e=>{try{if(watch!==null){await api('/api/action',{trip:locationTrip,action:'consent',enabled:false});stopWatch()}S.trip=Number(e.target.value);await refresh()}catch(e){toast(e.message)}};
for(const id of ['createForm','joinForm'])$(id).onsubmit=async e=>{e.preventDefault();const b=e.target.querySelector('button');b.disabled=true;try{const r=await api('/api/trips',{...Object.fromEntries(new FormData(e.target)),action:id==='joinForm'?'join':'create'});if(S)S.trip=r.trip;await refresh();$('setup').classList.add('hidden');e.target.reset()}catch(e){toast(e.message)}finally{b.disabled=false}};
document.addEventListener('click',async e=>{const b=e.target.closest('button');if(!b)return;try{if(b.id==='logout'){stopWatch();await api('/api/logout',{});location.reload();return}if(b.dataset.tab){tab=b.dataset.tab;render();return}if(b.id==='gpsStart'){await gps();return}if(b.dataset.action){const a=b.dataset.action;if(a==='delete_post'&&!confirm('이 게시물과 사진을 삭제할까요? 연결된 인증은 해제됩니다.'))return;if(a==='role'&&!confirm('이 구성원의 역할을 바꿀까요? 부모는 미션 및 안부 요청 권한을 가집니다.'))return;b.disabled=true;if(a==='gps_stop'){stopWatch();await act('consent',{enabled:false});toast('위치 공유를 중지하고 좌표를 삭제했어요.')}else await act(a,JSON.parse(b.dataset.extra));}}catch(e){toast(e.message)}finally{b.disabled=false}});
document.addEventListener('submit',async e=>{const f=e.target;if(!['planForm','postForm','missionForm'].includes(f.id)&&!f.classList.contains('evidence'))return;e.preventDefault();const b=f.querySelector('button');b.disabled=true;busy=true;try{const fd=new FormData(f);if(f.id==='planForm')await api('/api/action',{trip:S.trip,action:'plan_add',...Object.fromEntries(fd)});else if(f.id==='missionForm')await api('/api/action',{trip:S.trip,action:'mission_add',...Object.fromEntries(fd)});else{fd.append('trip',S.trip);if(f.dataset.id)fd.append('mission',f.dataset.id);await api('/api/post',fd)}busy=false;await refresh();toast('저장했어요.')}catch(e){toast(e.message)}finally{busy=false;b.disabled=false}});
(async()=>{try{await refresh()}catch(e){if(!e.message.includes('로그인'))toast(e.message)}})();
setInterval(async()=>{if(S&&!document.hidden&&!busy&&!['INPUT','TEXTAREA','SELECT'].includes(document.activeElement.tagName)){try{await refresh()}catch(e){toast(e.message)}}},12000);
</script></body></html>'''

if __name__ == '__main__':
    from waitress import serve
    print('안심여행: http://localhost:' + os.environ.get('PORT', '8000'))
    serve(app, host='0.0.0.0', port=int(os.environ.get('PORT', '8000')), threads=6)
