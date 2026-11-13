"""안심여행 — Streamlit Cloud용 수정본
GitHub 저장소 루트에 app.py와 requirements.txt를 함께 올리세요.
Streamlit Cloud의 Main file path: app.py
로컬 실행: pip install -r requirements.txt && streamlit run app.py
Cloud 로컬 디스크는 영구 보관이 보장되지 않습니다.
위치 공유는 동의 후 버튼을 눌러 갱신하며 자동/백그라운드 추적은 하지 않습니다.
로그인 세션은 브라우저 새로고침 시 초기화될 수 있습니다.
"""
BACKEND_SOURCE = 'import os, io, re, secrets, sqlite3, time\nfrom pathlib import Path\nfrom datetime import datetime, timedelta, timezone\nfrom functools import wraps\nfrom flask import Flask, request, session, jsonify, render_template_string, send_file\nfrom werkzeug.security import generate_password_hash, check_password_hash\nfrom PIL import Image, ImageOps, UnidentifiedImageError\n\nROOT = Path(os.environ.get(\'DATA_DIR\', \'./ansim_data\')).resolve()\nROOT.mkdir(parents=True, exist_ok=True)\n(ROOT / \'photos\').mkdir(exist_ok=True)\nkeyfile = ROOT / \'.session-key\'\nif not os.environ.get(\'SECRET_KEY\') and not keyfile.exists():\n    keyfile.write_text(secrets.token_hex(32))\n    keyfile.chmod(0o600)\napp = Flask(__name__)\napp.config.update(SECRET_KEY=os.environ.get(\'SECRET_KEY\') or keyfile.read_text(),\n                  MAX_CONTENT_LENGTH=9 * 1024 * 1024, SESSION_COOKIE_HTTPONLY=True,\n                  SESSION_COOKIE_SAMESITE=\'Lax\', SESSION_COOKIE_SECURE=os.environ.get(\'COOKIE_SECURE\') == \'1\',\n                  PERMANENT_SESSION_LIFETIME=timedelta(days=7))\nKST = timezone(timedelta(hours=9))\n\ndef now(): return datetime.now(KST).isoformat(timespec=\'seconds\')\ndef today(): return datetime.now(KST).date().isoformat()\ndef db():\n    c = sqlite3.connect(ROOT / \'travel.sqlite3\', timeout=20)\n    c.row_factory = sqlite3.Row\n    c.execute(\'PRAGMA foreign_keys=ON\')\n    return c\n\ndef init_db():\n    with db() as c:\n        c.executescript(\'\'\'\n        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, name TEXT NOT NULL, password TEXT NOT NULL);\n        CREATE TABLE IF NOT EXISTS trips(id INTEGER PRIMARY KEY, title TEXT, start TEXT, end TEXT, code TEXT UNIQUE, owner INTEGER REFERENCES users(id));\n        CREATE TABLE IF NOT EXISTS members(trip INTEGER REFERENCES trips(id), user INTEGER REFERENCES users(id), role TEXT, consent INTEGER DEFAULT 0, lat REAL, lon REAL, updated TEXT, PRIMARY KEY(trip,user));\n        CREATE TABLE IF NOT EXISTS plans(id INTEGER PRIMARY KEY, trip INTEGER REFERENCES trips(id), title TEXT, at TEXT, status TEXT DEFAULT \'예정\');\n        CREATE TABLE IF NOT EXISTS posts(id INTEGER PRIMARY KEY, trip INTEGER REFERENCES trips(id), user INTEGER REFERENCES users(id), body TEXT, photo TEXT, created TEXT);\n        CREATE TABLE IF NOT EXISTS checks(id INTEGER PRIMARY KEY, trip INTEGER REFERENCES trips(id), sender INTEGER REFERENCES users(id), target INTEGER REFERENCES users(id), created TEXT, answered TEXT, response TEXT);\n        CREATE TABLE IF NOT EXISTS missions(id INTEGER PRIMARY KEY, trip INTEGER REFERENCES trips(id), maker INTEGER REFERENCES users(id), target INTEGER REFERENCES users(id), title TEXT, amount INTEGER, status TEXT DEFAULT \'제안\', evidence INTEGER REFERENCES posts(id), created TEXT, paid_at TEXT, received INTEGER DEFAULT 0);\n        CREATE TABLE IF NOT EXISTS attempts(ip TEXT PRIMARY KEY, count INTEGER, since REAL);\n        \'\'\')\ninit_db()\n\ndef fail(message, code=400): return jsonify(error=message), code\n\ndef auth(f):\n    @wraps(f)\n    def wrapped(*a, **kw):\n        if not session.get(\'uid\'): return fail(\'로그인이 필요합니다.\', 401)\n        return f(*a, **kw)\n    return wrapped\n\n@app.before_request\ndef csrf():\n    if \'csrf\' not in session: session[\'csrf\'] = secrets.token_hex(24)\n    if request.method == \'POST\' and not secrets.compare_digest(request.headers.get(\'X-CSRF-Token\', \'\'), session[\'csrf\']):\n        return fail(\'보안 토큰이 만료되었습니다. 새로고침해 주세요.\', 403)\n\n@app.after_request\ndef headers(r):\n    r.headers[\'Cache-Control\'] = \'no-store\'\n    r.headers[\'X-Content-Type-Options\'] = \'nosniff\'\n    r.headers[\'X-Frame-Options\'] = \'DENY\'\n    r.headers[\'Referrer-Policy\'] = \'same-origin\'\n    r.headers[\'Permissions-Policy\'] = \'geolocation=(self)\'\n    return r\n\n@app.errorhandler(413)\ndef large(e): return fail(\'사진은 8MB 이하로 올려 주세요.\', 413)\n\ndef text(d, k, maximum=500):\n    v = str(d.get(k, \'\')).strip()\n    if not v or len(v) > maximum: raise ValueError(f\'{k}: 1~{maximum}자로 입력하세요.\')\n    return v\n\ndef member(c, tid):\n    m = c.execute(\'SELECT * FROM members WHERE trip=? AND user=?\', (tid, session[\'uid\'])).fetchone()\n    if not m: raise PermissionError(\'이 여행의 구성원이 아닙니다.\')\n    return m\n\ndef parent(m):\n    if m[\'role\'] != \'parent\': raise PermissionError(\'부모만 사용할 수 있는 기능입니다.\')\n\ndef child(c, tid, uid):\n    if not c.execute("SELECT 1 FROM members WHERE trip=? AND user=? AND role=\'child\'", (tid, uid)).fetchone():\n        raise ValueError(\'자녀 구성원을 선택하세요.\')\n\ndef trip_active(c, tid):\n    t = c.execute(\'SELECT * FROM trips WHERE id=?\', (tid,)).fetchone()\n    return t and t[\'start\'] <= today() <= t[\'end\']\n\n@app.errorhandler(ValueError)\ndef invalid(e): return fail(str(e))\n@app.errorhandler(PermissionError)\ndef forbidden(e): return fail(str(e), 403)\n\n@app.get(\'/\')\ndef index(): return \'안심여행 API\'\n\n@app.post(\'/api/account\')\ndef account():\n    d = request.get_json() or {}\n    username = text(d, \'username\', 40).lower()\n    password = text(d, \'password\', 200)\n    if not re.fullmatch(r\'[a-z0-9_.-]{3,40}\', username): raise ValueError(\'아이디는 영문·숫자·_.- 3~40자입니다.\')\n    ip = request.remote_addr or \'unknown\'\n    with db() as c:\n        a = c.execute(\'SELECT * FROM attempts WHERE ip=?\', (ip,)).fetchone()\n        if a and time.time() - a[\'since\'] < 900 and a[\'count\'] >= 20:\n            return fail(\'시도가 너무 많습니다. 15분 뒤 다시 시도하세요.\', 429)\n        if not a or time.time() - a[\'since\'] >= 900:\n            c.execute(\'INSERT OR REPLACE INTO attempts VALUES(?,?,?)\', (ip, 1, time.time()))\n        else: c.execute(\'UPDATE attempts SET count=count+1 WHERE ip=?\', (ip,))\n    with db() as c:\n        if d.get(\'mode\') == \'signup\':\n            if len(password) < 10: raise ValueError(\'비밀번호는 10자 이상으로 입력하세요.\')\n            name = text(d, \'name\', 30)\n            try:\n                uid = c.execute(\'INSERT INTO users(username,name,password) VALUES(?,?,?)\',\n                                (username, name, generate_password_hash(password))).lastrowid\n            except sqlite3.IntegrityError: return fail(\'이미 사용 중인 아이디입니다.\')\n        else:\n            u = c.execute(\'SELECT * FROM users WHERE username=?\', (username,)).fetchone()\n            if not u or not check_password_hash(u[\'password\'], password): return fail(\'아이디 또는 비밀번호가 맞지 않습니다.\', 401)\n            uid = u[\'id\']\n        c.execute(\'DELETE FROM attempts WHERE ip=?\', (ip,))\n    session.clear(); session[\'uid\'] = uid; session[\'csrf\'] = secrets.token_hex(24); session.permanent = True\n    return jsonify(ok=True)\n\n@app.post(\'/api/logout\')\n@auth\ndef logout():\n    with db() as c:\n        c.execute(\'UPDATE members SET consent=0,lat=NULL,lon=NULL,updated=NULL WHERE user=?\', (session[\'uid\'],))\n    session.clear()\n    return jsonify(ok=True)\n\n@app.get(\'/api/state\')\n@auth\ndef state():\n    uid = session[\'uid\']\n    with db() as c:\n        # 여행 종료 후 서버에 남은 위치와 동의 상태도 제거합니다.\n        c.execute(\'UPDATE members SET consent=0,lat=NULL,lon=NULL,updated=NULL WHERE trip IN (SELECT id FROM trips WHERE end<?)\', (today(),))\n        user = dict(c.execute(\'SELECT id,name,username FROM users WHERE id=?\', (uid,)).fetchone())\n        trips = [dict(x) for x in c.execute(\'SELECT t.*,m.role FROM trips t JOIN members m ON m.trip=t.id WHERE m.user=? ORDER BY t.id DESC\', (uid,))]\n        tid = request.args.get(\'trip\', type=int)\n        if not tid or not any(t[\'id\'] == tid for t in trips): tid = trips[0][\'id\'] if trips else None\n        out = dict(user=user, trips=trips, trip=tid, members=[], plans=[], posts=[], checks=[], missions=[])\n        if tid:\n            member(c, tid)\n            for x in c.execute(\'SELECT m.*,u.name FROM members m JOIN users u ON u.id=m.user WHERE trip=?\', (tid,)):\n                m = dict(x)\n                fresh = m[\'updated\'] and (datetime.now(KST) - datetime.fromisoformat(m[\'updated\'])).total_seconds() < 300\n                if not (m[\'consent\'] and trip_active(c, tid) and fresh): m[\'lat\'] = m[\'lon\'] = None\n                out[\'members\'].append(m)\n            queries = {\n                \'plans\': \'SELECT * FROM plans WHERE trip=? ORDER BY at,id\',\n                \'posts\': \'SELECT p.*,u.name FROM posts p JOIN users u ON u.id=p.user WHERE trip=? ORDER BY p.id DESC LIMIT 100\',\n                \'checks\': \'SELECT * FROM checks WHERE trip=? ORDER BY id DESC LIMIT 100\',\n                \'missions\': \'SELECT * FROM missions WHERE trip=? ORDER BY id DESC LIMIT 100\'}\n            for k, q in queries.items(): out[k] = [dict(x) for x in c.execute(q, (tid,))]\n    return jsonify(out)\n\n@app.post(\'/api/trips\')\n@auth\ndef trips():\n    d = request.get_json() or {}\n    with db() as c:\n        if d.get(\'action\') == \'join\':\n            t = c.execute(\'SELECT * FROM trips WHERE code=?\', (text(d, \'code\', 20).upper(),)).fetchone()\n            if not t: return fail(\'초대 코드를 확인하세요.\')\n            c.execute("INSERT OR IGNORE INTO members(trip,user,role) VALUES(?,?,\'child\')", (t[\'id\'], session[\'uid\']))\n            tid = t[\'id\']\n        else:\n            title = text(d, \'title\', 80)\n            start, end = text(d, \'start\', 10), text(d, \'end\', 10)\n            datetime.strptime(start, \'%Y-%m-%d\'); datetime.strptime(end, \'%Y-%m-%d\')\n            if start > end: raise ValueError(\'종료일은 시작일 이후여야 합니다.\')\n            tid = c.execute(\'INSERT INTO trips(title,start,end,code,owner) VALUES(?,?,?,?,?)\',\n                            (title, start, end, secrets.token_hex(5).upper(), session[\'uid\'])).lastrowid\n            c.execute("INSERT INTO members(trip,user,role) VALUES(?,?,\'parent\')", (tid, session[\'uid\']))\n    return jsonify(ok=True, trip=tid)\n\n@app.post(\'/api/action\')\n@auth\ndef action():\n    d = request.get_json() or {}; tid = int(d.get(\'trip\', 0)); uid = session[\'uid\']; action = d.get(\'action\')\n    with db() as c:\n        m = member(c, tid)\n        if action == \'role\':\n            t = c.execute(\'SELECT * FROM trips WHERE id=?\', (tid,)).fetchone()\n            if t[\'owner\'] != uid: raise PermissionError(\'그룹 생성자만 역할을 변경할 수 있습니다.\')\n            target = int(d[\'target\']); role = d.get(\'role\')\n            if role not in (\'parent\', \'child\') or target == uid: raise ValueError(\'역할 변경 대상을 확인하세요.\')\n            c.execute(\'UPDATE members SET role=? WHERE trip=? AND user=?\', (role, tid, target))\n        elif action == \'plan_add\':\n            title = text(d, \'title\', 100); at = text(d, \'at\', 20)\n            datetime.fromisoformat(at)\n            t = c.execute(\'SELECT * FROM trips WHERE id=?\', (tid,)).fetchone()\n            if not t[\'start\'] <= at[:10] <= t[\'end\']: raise ValueError(\'여행 기간 안의 일정을 입력하세요.\')\n            c.execute(\'INSERT INTO plans(trip,title,at) VALUES(?,?,?)\', (tid, title, at))\n        elif action == \'plan_status\':\n            status = d.get(\'status\')\n            if status not in (\'예정\', \'진행 중\', \'완료\'): raise ValueError(\'잘못된 일정 상태입니다.\')\n            c.execute(\'UPDATE plans SET status=? WHERE id=? AND trip=?\', (status, int(d[\'id\']), tid))\n        elif action == \'consent\':\n            enabled = bool(d.get(\'enabled\'))\n            if enabled and not trip_active(c, tid): raise ValueError(\'위치 공유는 여행 기간에만 가능합니다. (한국 시간 기준)\')\n            c.execute(\'UPDATE members SET consent=?,lat=NULL,lon=NULL,updated=NULL WHERE trip=? AND user=?\', (int(enabled), tid, uid))\n        elif action == \'location\':\n            if not m[\'consent\'] or not trip_active(c, tid): raise PermissionError(\'위치 공유 동의와 여행 기간을 확인하세요.\')\n            lat, lon = float(d[\'lat\']), float(d[\'lon\'])\n            if not (-90 <= lat <= 90 and -180 <= lon <= 180): raise ValueError(\'잘못된 좌표입니다.\')\n            c.execute(\'UPDATE members SET lat=?,lon=?,updated=? WHERE trip=? AND user=?\', (lat, lon, now(), tid, uid))\n        elif action == \'check\':\n            parent(m); target = int(d[\'target\']); child(c, tid, target)\n            recent = c.execute(\'SELECT created FROM checks WHERE trip=? AND sender=? AND target=? ORDER BY id DESC LIMIT 1\', (tid, uid, target)).fetchone()\n            if recent and (datetime.now(KST)-datetime.fromisoformat(recent[\'created\'])).total_seconds() < 600:\n                raise ValueError(\'같은 자녀에게는 10분에 한 번 요청할 수 있습니다.\')\n            c.execute(\'INSERT INTO checks(trip,sender,target,created) VALUES(?,?,?,?)\', (tid, uid, target, now()))\n        elif action == \'well\':\n            if m[\'role\'] != \'child\': raise PermissionError(\'자녀가 응답할 수 있습니다.\')\n            c.execute("UPDATE checks SET answered=?,response=\'잘 지내요 💚\' WHERE trip=? AND target=? AND answered IS NULL", (now(), tid, uid))\n            c.execute(\'INSERT INTO posts(trip,user,body,created) VALUES(?,?,?,?)\', (tid, uid, \'잘 지내요 💚\', now()))\n        elif action == \'mission_add\':\n            parent(m); target = int(d[\'target\']); child(c, tid, target)\n            amount = int(d.get(\'amount\', 0))\n            if not 0 <= amount <= 1000000: raise ValueError(\'용돈은 0~1,000,000원으로 입력하세요.\')\n            c.execute(\'INSERT INTO missions(trip,maker,target,title,amount,created) VALUES(?,?,?,?,?,?)\', (tid, uid, target, text(d, \'title\', 200), amount, now()))\n        elif action == \'mission\':\n            q = c.execute(\'SELECT * FROM missions WHERE id=? AND trip=?\', (int(d[\'id\']), tid)).fetchone()\n            if not q: raise ValueError(\'미션을 찾을 수 없습니다.\')\n            move = d.get(\'move\'); status = q[\'status\']\n            if move in (\'수락\', \'거절\'):\n                if uid != q[\'target\'] or status != \'제안\': raise PermissionError(\'미션 대상자만 수락 또는 거절할 수 있습니다.\')\n                c.execute(\'UPDATE missions SET status=? WHERE id=?\', (\'수행 중\' if move == \'수락\' else \'거절\', q[\'id\']))\n            elif move == \'수령 확인\':\n                if uid != q[\'target\'] or status != \'지급 기록 완료\': raise PermissionError(\'지급 기록 후 대상자가 확인할 수 있습니다.\')\n                c.execute(\'UPDATE missions SET received=1 WHERE id=?\', (q[\'id\'],))\n            else:\n                parent(m)\n                if uid != q[\'maker\']: raise PermissionError(\'미션을 제안한 부모만 확인할 수 있습니다.\')\n                transitions = {(\'확인 대기\', \'승인\'): \'지급 대기\', (\'확인 대기\', \'재인증 요청\'): \'수행 중\', (\'지급 대기\', \'지급했어요\'): \'지급 기록 완료\'}\n                new = transitions.get((status, move))\n                if not new: raise ValueError(\'현재 상태에서 할 수 없는 작업입니다.\')\n                c.execute(\'UPDATE missions SET status=?,paid_at=? WHERE id=?\', (new, now() if new == \'지급 기록 완료\' else None, q[\'id\']))\n        elif action == \'delete_post\':\n            p = c.execute(\'SELECT * FROM posts WHERE id=? AND trip=?\', (int(d[\'id\']), tid)).fetchone()\n            if not p or p[\'user\'] != uid: raise PermissionError(\'본인 게시물만 삭제할 수 있습니다.\')\n            c.execute("UPDATE missions SET evidence=NULL,status=CASE WHEN status=\'확인 대기\' THEN \'수행 중\' ELSE status END WHERE evidence=?", (p[\'id\'],))\n            c.execute(\'DELETE FROM posts WHERE id=?\', (p[\'id\'],))\n            if p[\'photo\']: (ROOT / \'photos\' / p[\'photo\']).unlink(missing_ok=True)\n        else: raise ValueError(\'지원하지 않는 작업입니다.\')\n    return jsonify(ok=True)\n\n@app.post(\'/api/post\')\n@auth\ndef post():\n    tid = int(request.form.get(\'trip\', 0)); uid = session[\'uid\']\n    body = request.form.get(\'body\', \'\').strip(); filename = None\n    if len(body) > 1000: raise ValueError(\'글은 1,000자 이하로 입력하세요.\')\n    upload = request.files.get(\'photo\'); image_bytes = None\n    if upload and upload.filename:\n        data = upload.read(8*1024*1024+1)\n        if len(data) > 8*1024*1024: raise ValueError(\'사진은 8MB 이하로 올려 주세요.\')\n        try:\n            with Image.open(io.BytesIO(data)) as image:\n                if image.width * image.height > 25000000: raise ValueError(\'사진 해상도가 너무 큽니다. 줄여서 올려 주세요.\')\n                image = ImageOps.exif_transpose(image).convert(\'RGB\'); image.thumbnail((1600, 1600))\n                buf = io.BytesIO(); image.save(buf, format=\'JPEG\', quality=85); image_bytes = buf.getvalue()\n        except (UnidentifiedImageError, OSError, Image.DecompressionBombError): raise ValueError(\'읽을 수 있는 사진 파일을 올려 주세요.\')\n        filename = secrets.token_hex(20) + \'.jpg\'  # 재인코딩하여 GPS 등 EXIF 제거\n    if not body and not filename: raise ValueError(\'글이나 사진을 추가하세요.\')\n    try:\n        with db() as c:\n            m = member(c, tid)\n            mission_id = request.form.get(\'mission\')\n            if mission_id:\n                q = c.execute("SELECT * FROM missions WHERE id=? AND trip=? AND target=? AND status=\'수행 중\'", (int(mission_id), tid, uid)).fetchone()\n                if not q: raise PermissionError(\'수행 중인 본인 미션만 인증할 수 있습니다.\')\n            if filename: (ROOT / \'photos\' / filename).write_bytes(image_bytes)\n            pid = c.execute(\'INSERT INTO posts(trip,user,body,photo,created) VALUES(?,?,?,?,?)\', (tid, uid, body, filename, now())).lastrowid\n            if mission_id: c.execute("UPDATE missions SET status=\'확인 대기\',evidence=? WHERE id=?", (pid, int(mission_id)))\n            if m[\'role\'] == \'child\' and request.form.get(\'reply\') == \'1\':\n                c.execute("UPDATE checks SET answered=?,response=\'사진/글로 안부를 전했어요\' WHERE trip=? AND target=? AND answered IS NULL", (now(), tid, uid))\n    except Exception:\n        if filename: (ROOT / \'photos\' / filename).unlink(missing_ok=True)\n        raise\n    return jsonify(ok=True)\n\n@app.get(\'/photo/<int:pid>\')\n@auth\ndef photo(pid):\n    with db() as c:\n        p = c.execute(\'SELECT * FROM posts WHERE id=?\', (pid,)).fetchone()\n        if not p or not p[\'photo\']: return fail(\'사진이 없습니다.\', 404)\n        member(c, p[\'trip\'])\n        return send_file(ROOT / \'photos\' / p[\'photo\'], mimetype=\'image/jpeg\')\n\n'

import streamlit as st
from datetime import date
import io

st.set_page_config(page_title='안심여행', page_icon='🌿', layout='centered')
st.markdown('''<style>.stApp{background:#f3f7f4} .block-container{max-width:850px;padding-top:2rem}h1,h2,h3{color:#176c54}div.stButton>button{border-radius:12px;min-height:44px} [data-testid="stForm"]{background:white;border-radius:18px;padding:18px}</style>''', unsafe_allow_html=True)

@st.cache_resource
def backend():
    scope={'__name__':'__main__'}
    exec(BACKEND_SOURCE,scope)
    return scope['app']

server=backend()
if 'client' not in st.session_state:
    st.session_state.client=server.test_client()
client=st.session_state.client

def token():
    with client.session_transaction() as sess:
        val=sess.get('csrf')
    if not val:
        client.get('/')
        with client.session_transaction() as sess: val=sess['csrf']
    return val

def call(path,data=None,form=None):
    if data is None and form is None: r=client.get(path)
    elif form is not None: r=client.post(path,data=form,headers={'X-CSRF-Token':token()})
    else: r=client.post(path,json=data,headers={'X-CSRF-Token':token()})
    out=r.get_json()
    if r.status_code>=400: raise ValueError((out or {}).get('error','요청을 처리하지 못했습니다.'))
    return out

def run(path,data=None,form=None):
    try:
        result=call(path,data,form)
        st.session_state.notice='저장했어요.'
        st.rerun()
        return result
    except ValueError as e: st.error(str(e))

st.title('🌿 안심여행')
st.caption('걱정은 가볍게, 추억은 함께 · 가족 전용 여행 공간')
if st.session_state.pop('notice',None): st.success('저장했어요.')
try: state=call('/api/state'+('?trip='+str(st.session_state.trip_id) if st.session_state.get('trip_id') else ''))
except ValueError: state=None
if not state:
    mode=st.radio('시작하기',['로그인','회원가입'],horizontal=True)
    with st.form('account'):
        username=st.text_input('아이디 · 영문/숫자/_.- 3~40자',max_chars=40)
        password=st.text_input('비밀번호 · 가입 시 10자 이상',type='password',max_chars=200)
        name=st.text_input('가족에게 보일 이름',max_chars=30) if mode=='회원가입' else ''
        if st.form_submit_button(mode,use_container_width=True):
            run('/api/account',dict(mode='signup' if mode=='회원가입' else 'login',username=username,password=password,name=name))
    st.info('가족끼리 여행을 공유하세요. 초대 코드는 믿을 수 있는 가족에게만 전달하세요.')
    st.stop()

uid=state['user']['id']
with st.sidebar:
    st.write('**'+state['user']['name']+'님**')
    if st.button('로그아웃'): run('/api/logout',{})
    st.caption('Streamlit Cloud 재시작/재배포 시 로컬 데이터가 사라질 수 있습니다. 장기 운영에는 영구 저장소가 필요합니다.')

with st.expander('＋ 여행 만들기 / 초대 코드로 참여',expanded=not state['trips']):
    with st.form('create'):
        title=st.text_input('새 여행 이름',max_chars=80)
        start=st.date_input('시작일 · 한국 시간 기준',value=date.today())
        end=st.date_input('종료일',value=date.today())
        if st.form_submit_button('여행 만들기'):
            try:
                r=call('/api/trips',dict(title=title,start=str(start),end=str(end)))
                st.session_state.trip_id=r['trip'];st.rerun()
            except ValueError as e: st.error(str(e))
    with st.form('join'):
        code=st.text_input('가족에게 받은 초대 코드',max_chars=20)
        if st.form_submit_button('초대 코드로 참여'):
            try:
                r=call('/api/trips',dict(action='join',code=code))
                st.session_state.trip_id=r['trip'];st.rerun()
            except ValueError as e: st.error(str(e))
if not state['trips']: st.stop()
ids=[t['id'] for t in state['trips']]
selected=st.selectbox('우리 가족 여행',ids,index=ids.index(state['trip']),format_func=lambda x:next(t['title'] for t in state['trips'] if t['id']==x))
if selected!=state['trip']:
    st.session_state.trip_id=selected;st.rerun()
st.session_state.trip_id=selected
trip=next(t for t in state['trips'] if t['id']==selected)
me=next(m for m in state['members'] if m['user']==uid)
is_parent=me['role']=='parent'

def act(action,**kwargs): run('/api/action',dict(trip=selected,action=action,**kwargs))
def who(user): return next((m['name'] for m in state['members'] if m['user']==user),'구성원')
def target_select(key):
    children=[m['user'] for m in state['members'] if m['role']=='child']
    return st.selectbox('대상 자녀',children,format_func=who,key=key) if children else None

def upload_form(key,mission=None):
    with st.form(key,clear_on_submit=True):
        body=st.text_area('인증 내용' if mission else '짧은 이야기',max_chars=1000)
        photo=st.file_uploader('사진 · 8MB 이하',type=['png','jpg','jpeg','webp'])
        reply=st.checkbox('내 미응답 안부 요청에도 응답하기',value=True) if not mission else False
        if st.form_submit_button('인증 제출' if mission else '가족에게 공유'):
            data={'trip':str(selected),'body':body,'reply':'1' if reply else '0'}
            if mission: data['mission']=str(mission)
            if photo: data['photo']=(io.BytesIO(photo.getvalue()),photo.name)
            run('/api/post',form=data)

def show_post(p,delete=False):
    st.write('**'+p['name']+'** · '+p['created'].replace('T',' '))
    st.text(p['body'] or '')
    if p['photo']:
        r=client.get('/photo/'+str(p['id']))
        if r.status_code==200: st.image(r.data,use_container_width=True)
    if delete and p['user']==uid:
        if st.checkbox('삭제 확인',key='confirm'+str(p['id'])):
            if st.button('게시물 삭제',key='delete'+str(p['id'])): act('delete_post',id=p['id'])

@st.fragment(run_every='12s')
def live_overview():
    try:
        fresh=call('/api/state?trip='+str(selected))
        done=sum(p['status']=='완료' for p in fresh['plans']);total=len(fresh['plans'])
        st.progress(done/total if total else 0,text=f'여행 진척도 · {done}/{total} 일정 완료')
        pending=sum(c['target']==uid and not c['answered'] for c in fresh['checks'])
        if pending: st.warning(f'안부 요청 {pending}건이 기다려요. 사진·안부 탭에서 응답해 주세요.')
    except ValueError: st.caption('정보를 갱신하려면 다시 로그인해 주세요.')

st.subheader(trip['title'])
st.caption(f"{trip['start']} ~ {trip['end']} · {'부모' if is_parent else '자녀'}")
live_overview()
st.caption('상단 진척도·안부 알림은 화면을 열어 둔 동안 12초 주기로 갱신됩니다. 아래 목록은 새로고침으로 갱신하세요.')
if st.button('↻ 최신 내용 새로고침'): st.rerun()
page=st.radio('메뉴',['일정','사진·안부','위치','미션·용돈','가족'],horizontal=True,label_visibility='collapsed')
if page=='일정':
    st.info('진행 상태는 실제 도착 여부를 자동 판정하지 않습니다. 가족이 직접 변경하세요.')
    for p in state['plans']:
        with st.container(border=True):
            st.write('**'+p['title']+'**');st.caption(p['at'].replace('T',' ')+' · '+p['status'])
            cols=st.columns(3)
            for col,status in zip(cols,['예정','진행 중','완료']):
                if col.button(status,key=f"plan{p['id']}{status}",use_container_width=True): act('plan_status',id=p['id'],status=status)
    with st.form('plan'):
        title=st.text_input('새 일정',max_chars=100)
        day=st.date_input('날짜 · 한국 시간',value=date.fromisoformat(trip['start']))
        at=st.time_input('예정 시각')
        if st.form_submit_button('일정 추가'): act('plan_add',title=title,at=f'{day}T{at:%H:%M}')
elif page=='사진·안부':
    st.subheader('💚 부모가 걱정돼!')
    if is_parent:
        target=target_select('check-target')
        if target and st.button('안부 확인 요청'): act('check',target=target)
        st.caption('같은 자녀에게 10분에 한 번 요청할 수 있어요.')
    elif st.button('잘 지내요 💚',type='primary'): act('well')
    st.caption('미응답은 위험을 뜻하지 않습니다. 앱 외부 푸시 알림은 제공하지 않습니다.')
    upload_form('newpost')
    with st.expander('안부 요청 기록'):
        for q in state['checks']:
            st.write(f"{who(q['sender'])} → {who(q['target'])} · {'응답 완료' if q['answered'] else '미확인'}")
            st.caption(q['created']+(' / '+q['response'] if q['answered'] else ''))
    for p in state['posts']:
        with st.container(border=True): show_post(p,True)
elif page=='위치':
    st.subheader('📍 동의하고 위치 공유')
    st.info('여행 기간에만 공유할 수 있고 중지하면 좌표가 삭제됩니다. 자동/백그라운드 추적은 하지 않으며 아래 버튼으로 현재 위치를 직접 갱신합니다. 최근 5분 내 좌표만 표시됩니다.')
    st.caption('위치 권한에는 HTTPS가 필요합니다. 브라우저에서 위치 접근을 허용해 주세요. 지도 링크를 열면 좌표가 외부 지도 서비스에 전달됩니다.')
    consent=st.checkbox('현재 위치를 가족에게 공유하는 데 동의합니다.',value=bool(me['consent']))
    if consent and not me['consent']:
        if st.button('위치 공유 동의 저장'): act('consent',enabled=True)
    if me['consent']:
        from streamlit_geolocation import streamlit_geolocation
        loc=streamlit_geolocation()
        if loc and loc.get('latitude') is not None:
            if st.button('이 위치를 가족에게 공유'):
                act('location',lat=loc['latitude'],lon=loc['longitude'])
    if st.button('공유 중지 · 내 좌표 삭제'): act('consent',enabled=False)
    for m in state['members']:
        with st.container(border=True):
            st.write('**'+m['name']+'**')
            if m['lat'] is not None:
                st.write(f"{m['lat']:.5f}, {m['lon']:.5f}")
                st.link_button('지도에서 보기 ↗',f"https://www.openstreetmap.org/?mlat={m['lat']}&mlon={m['lon']}#map=16/{m['lat']}/{m['lon']}")
                st.caption('마지막 갱신 '+m['updated'])
            else: st.caption('공유 중이 아니거나 최근 위치가 없습니다.')
elif page=='미션·용돈':
    st.info('실제 송금은 하지 않습니다. 부모의 지급 기록과 자녀의 수령 확인만 저장합니다. 안전 연락과 위치 공유를 용돈의 조건으로 삼지 마세요.')
    if is_parent:
        with st.form('mission'):
            target=target_select('mission-target')
            title=st.text_input('미션 내용',max_chars=200)
            amount=st.number_input('용돈 (원)',min_value=0,max_value=1000000,value=10000,step=1000)
            if st.form_submit_button('미션 제안'):
                if target: act('mission_add',target=target,title=title,amount=amount)
                else: st.error('먼저 자녀를 초대하세요.')
    for q in state['missions']:
        with st.container(border=True):
            st.subheader(q['title']);st.write(f"{who(q['maker'])} → {who(q['target'])} · {q['amount']:,}원")
            st.caption('상태: '+q['status'])
            if q['evidence']:
                p=next((p for p in state['posts'] if p['id']==q['evidence']),None)
                if p: show_post(p)
                else: st.caption('인증 게시물이 최신 100건 범위에 없습니다.')
            moves=[]
            if q['target']==uid:
                if q['status']=='제안': moves=['수락','거절']
                if q['status']=='수행 중': upload_form('evidence'+str(q['id']),q['id'])
                if q['status']=='지급 기록 완료' and not q['received']: moves=['수령 확인']
            if is_parent and q['maker']==uid:
                if q['status']=='확인 대기': moves=['승인','재인증 요청']
                if q['status']=='지급 대기':
                    if st.checkbox('외부에서 송금한 것을 확인했어요.',key='paidconfirm'+str(q['id'])): moves=['지급했어요']
            for move in moves:
                if st.button(move,key=f"mission{q['id']}{move}"): act('mission',id=q['id'],move=move)
            if q['paid_at']: st.caption('부모 지급 기록: '+q['paid_at']+' · 자녀 수령 '+('확인' if q['received'] else '미확인'))
elif page=='가족':
    st.subheader('🏡 우리 가족')
    st.code(trip['code'],language=None)
    st.caption('초대 코드를 외부에 공개하지 마세요. 참여자는 자녀 역할로 시작합니다.')
    for m in state['members']:
        with st.container(border=True):
            st.write(m['name']+' · '+('부모' if m['role']=='parent' else '자녀'))
            if trip['owner']==uid and m['user']!=uid:
                role='parent' if m['role']=='child' else 'child'
                if st.checkbox('역할 변경 확인',key='rolecheck'+str(m['user'])):
                    if st.button('부모로 변경' if role=='parent' else '자녀로 변경',key='role'+str(m['user'])): act('role',target=m['user'],role=role)
st.caption('사진의 GPS 등 EXIF 정보는 업로드 시 제거됩니다. 상용 운영 전 개인정보 처리방침·보호자 동의·보관 및 삭제 정책과 보안 검토가 필요합니다.')
