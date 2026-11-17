"""안심여행 — 귀여운 버튼형 Streamlit 버전
두 파일(app.py, requirements.txt)을 GitHub 저장소 루트에 업로드하세요.
Streamlit Cloud main file: app.py
로컬: pip install -r requirements.txt / streamlit run app.py
기존 SQLite 스키마 유지. DATA_DIR 기본 ./ansim_data.
Cloud 재시작 시 로컬 데이터 보존은 보장되지 않습니다.
위치는 동의 후 수동 갱신. 실제 송금 없음. 운영 전 개인정보·보안 검토 필요.
"""
BACKEND_SOURCE = 'import os, io, re, secrets, sqlite3, time\nfrom pathlib import Path\nfrom datetime import datetime, timedelta, timezone\nfrom functools import wraps\nfrom flask import Flask, request, session, jsonify, render_template_string, send_file\nfrom werkzeug.security import generate_password_hash, check_password_hash\nfrom PIL import Image, ImageOps, UnidentifiedImageError\n\nROOT = Path(os.environ.get(\'DATA_DIR\', \'./ansim_data\')).resolve()\nROOT.mkdir(parents=True, exist_ok=True)\n(ROOT / \'photos\').mkdir(exist_ok=True)\nkeyfile = ROOT / \'.session-key\'\nif not os.environ.get(\'SECRET_KEY\') and not keyfile.exists():\n    keyfile.write_text(secrets.token_hex(32))\n    keyfile.chmod(0o600)\napp = Flask(__name__)\napp.config.update(SECRET_KEY=os.environ.get(\'SECRET_KEY\') or keyfile.read_text(),\n                  MAX_CONTENT_LENGTH=9 * 1024 * 1024, SESSION_COOKIE_HTTPONLY=True,\n                  SESSION_COOKIE_SAMESITE=\'Lax\', SESSION_COOKIE_SECURE=os.environ.get(\'COOKIE_SECURE\') == \'1\',\n                  PERMANENT_SESSION_LIFETIME=timedelta(days=7))\nKST = timezone(timedelta(hours=9))\n\ndef now(): return datetime.now(KST).isoformat(timespec=\'seconds\')\ndef today(): return datetime.now(KST).date().isoformat()\ndef db():\n    c = sqlite3.connect(ROOT / \'travel.sqlite3\', timeout=20)\n    c.row_factory = sqlite3.Row\n    c.execute(\'PRAGMA foreign_keys=ON\')\n    return c\n\ndef init_db():\n    with db() as c:\n        c.executescript(\'\'\'\n        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, name TEXT NOT NULL, password TEXT NOT NULL);\n        CREATE TABLE IF NOT EXISTS trips(id INTEGER PRIMARY KEY, title TEXT, start TEXT, end TEXT, code TEXT UNIQUE, owner INTEGER REFERENCES users(id));\n        CREATE TABLE IF NOT EXISTS members(trip INTEGER REFERENCES trips(id), user INTEGER REFERENCES users(id), role TEXT, consent INTEGER DEFAULT 0, lat REAL, lon REAL, updated TEXT, PRIMARY KEY(trip,user));\n        CREATE TABLE IF NOT EXISTS plans(id INTEGER PRIMARY KEY, trip INTEGER REFERENCES trips(id), title TEXT, at TEXT, status TEXT DEFAULT \'예정\');\n        CREATE TABLE IF NOT EXISTS posts(id INTEGER PRIMARY KEY, trip INTEGER REFERENCES trips(id), user INTEGER REFERENCES users(id), body TEXT, photo TEXT, created TEXT);\n        CREATE TABLE IF NOT EXISTS checks(id INTEGER PRIMARY KEY, trip INTEGER REFERENCES trips(id), sender INTEGER REFERENCES users(id), target INTEGER REFERENCES users(id), created TEXT, answered TEXT, response TEXT);\n        CREATE TABLE IF NOT EXISTS missions(id INTEGER PRIMARY KEY, trip INTEGER REFERENCES trips(id), maker INTEGER REFERENCES users(id), target INTEGER REFERENCES users(id), title TEXT, amount INTEGER, status TEXT DEFAULT \'제안\', evidence INTEGER REFERENCES posts(id), created TEXT, paid_at TEXT, received INTEGER DEFAULT 0);\n        CREATE TABLE IF NOT EXISTS attempts(ip TEXT PRIMARY KEY, count INTEGER, since REAL);\n        \'\'\')\ninit_db()\nwith db() as c:\n    if \'app_role\' not in [x[1] for x in c.execute(\'PRAGMA table_info(users)\')]:\n        c.execute(\'ALTER TABLE users ADD COLUMN app_role TEXT\')\n    c.execute("CREATE TABLE IF NOT EXISTS emergencies(id INTEGER PRIMARY KEY,trip INTEGER,user INTEGER,created TEXT,resolved INTEGER DEFAULT 0)")\n\nwith db() as c:\n    for name,kind in [(\'place_lat\',\'REAL\'),(\'place_lon\',\'REAL\'),(\'radius_m\',\'INTEGER DEFAULT 200\'),(\'plan_user\',\'INTEGER\')]:\n        if name not in [x[1] for x in c.execute(\'PRAGMA table_info(plans)\')]:\n            c.execute(\'ALTER TABLE plans ADD COLUMN \'+name+\' \'+kind)\n    c.execute(\'CREATE TABLE IF NOT EXISTS arrivals(id INTEGER PRIMARY KEY,trip INTEGER,plan INTEGER,user INTEGER,created TEXT,distance REAL,UNIQUE(plan,user))\')\n\ndef distance_m(a,b,c,d):\n    from math import radians,sin,cos,atan2,sqrt\n    x=sin(radians(c-a)/2)**2+cos(radians(a))*cos(radians(c))*sin(radians(d-b)/2)**2\n    x=max(0,min(1,x))\n    return 6371000*2*atan2(sqrt(x),sqrt(1-x))\n\ndef fail(message, code=400): return jsonify(error=message), code\n\ndef auth(f):\n    @wraps(f)\n    def wrapped(*a, **kw):\n        if not session.get(\'uid\'): return fail(\'로그인이 필요합니다.\', 401)\n        return f(*a, **kw)\n    return wrapped\n\n@app.before_request\ndef csrf():\n    if \'csrf\' not in session: session[\'csrf\'] = secrets.token_hex(24)\n    if request.method == \'POST\' and not secrets.compare_digest(request.headers.get(\'X-CSRF-Token\', \'\'), session[\'csrf\']):\n        return fail(\'보안 토큰이 만료되었습니다. 새로고침해 주세요.\', 403)\n\n@app.after_request\ndef headers(r):\n    r.headers[\'Cache-Control\'] = \'no-store\'\n    r.headers[\'X-Content-Type-Options\'] = \'nosniff\'\n    r.headers[\'X-Frame-Options\'] = \'DENY\'\n    r.headers[\'Referrer-Policy\'] = \'same-origin\'\n    r.headers[\'Permissions-Policy\'] = \'geolocation=(self)\'\n    return r\n\n@app.errorhandler(413)\ndef large(e): return fail(\'사진은 8MB 이하로 올려 주세요.\', 413)\n\ndef text(d, k, maximum=500):\n    v = str(d.get(k, \'\')).strip()\n    if not v or len(v) > maximum: raise ValueError(f\'{k}: 1~{maximum}자로 입력하세요.\')\n    return v\n\ndef member(c, tid):\n    m = c.execute(\'SELECT * FROM members WHERE trip=? AND user=?\', (tid, session[\'uid\'])).fetchone()\n    if not m: raise PermissionError(\'이 여행의 구성원이 아닙니다.\')\n    return m\n\ndef parent(m):\n    if m[\'role\'] != \'parent\': raise PermissionError(\'부모만 사용할 수 있는 기능입니다.\')\n\ndef child(c, tid, uid):\n    if not c.execute("SELECT 1 FROM members WHERE trip=? AND user=? AND role=\'child\'", (tid, uid)).fetchone():\n        raise ValueError(\'자녀 구성원을 선택하세요.\')\n\ndef trip_active(c, tid):\n    t = c.execute(\'SELECT * FROM trips WHERE id=?\', (tid,)).fetchone()\n    return t and t[\'start\'] <= today() <= t[\'end\']\n\n@app.errorhandler(ValueError)\ndef invalid(e): return fail(str(e))\n@app.errorhandler(PermissionError)\ndef forbidden(e): return fail(str(e), 403)\n\n@app.get(\'/\')\ndef index(): return \'안심여행 API\'\n\n@app.post(\'/api/account\')\ndef account():\n    d = request.get_json() or {}\n    chosen = d.get(\'role\')\n    if chosen not in (\'parent\',\'child\'): raise ValueError(\'부모 또는 자녀를 선택하세요.\')\n    username = text(d, \'username\', 40).lower()\n    password = text(d, \'password\', 200)\n    if not re.fullmatch(r\'[a-z0-9_.-]{3,40}\', username): raise ValueError(\'아이디는 영문·숫자·_.- 3~40자입니다.\')\n    ip = request.remote_addr or \'unknown\'\n    with db() as c:\n        a = c.execute(\'SELECT * FROM attempts WHERE ip=?\', (ip,)).fetchone()\n        if a and time.time() - a[\'since\'] < 900 and a[\'count\'] >= 20:\n            return fail(\'시도가 너무 많습니다. 15분 뒤 다시 시도하세요.\', 429)\n        if not a or time.time() - a[\'since\'] >= 900:\n            c.execute(\'INSERT OR REPLACE INTO attempts VALUES(?,?,?)\', (ip, 1, time.time()))\n        else: c.execute(\'UPDATE attempts SET count=count+1 WHERE ip=?\', (ip,))\n    with db() as c:\n        if d.get(\'mode\') == \'signup\':\n            if len(password) < 10: raise ValueError(\'비밀번호는 10자 이상으로 입력하세요.\')\n            name = text(d, \'name\', 30)\n            try:\n                uid = c.execute(\'INSERT INTO users(username,name,password) VALUES(?,?,?)\',\n                                (username, name, generate_password_hash(password))).lastrowid\n            except sqlite3.IntegrityError: return fail(\'이미 사용 중인 아이디입니다.\')\n        else:\n            u = c.execute(\'SELECT * FROM users WHERE username=?\', (username,)).fetchone()\n            if not u or not check_password_hash(u[\'password\'], password): return fail(\'아이디 또는 비밀번호가 맞지 않습니다.\', 401)\n            uid = u[\'id\']\n        existing = c.execute(\'SELECT app_role FROM users WHERE id=?\',(uid,)).fetchone()[\'app_role\']\n        if existing and existing != chosen: return fail(\'이 계정은 \'+(\'부모\' if existing==\'parent\' else \'자녀\')+\' 계정입니다. 역할을 다시 선택하세요.\')\n        if not existing:\n            c.execute(\'UPDATE users SET app_role=? WHERE id=?\',(chosen,uid))\n            c.execute(\'UPDATE members SET role=? WHERE user=?\',(chosen,uid))\n        c.execute(\'DELETE FROM attempts WHERE ip=?\', (ip,))\n    session.clear(); session[\'uid\'] = uid; session[\'csrf\'] = secrets.token_hex(24); session.permanent = True\n    return jsonify(ok=True)\n\n@app.post(\'/api/logout\')\n@auth\ndef logout():\n    with db() as c:\n        c.execute(\'UPDATE members SET consent=0,lat=NULL,lon=NULL,updated=NULL WHERE user=?\', (session[\'uid\'],))\n    session.clear()\n    return jsonify(ok=True)\n\n@app.get(\'/api/state\')\n@auth\ndef state():\n    uid = session[\'uid\']\n    with db() as c:\n        # 여행 종료 후 서버에 남은 위치와 동의 상태도 제거합니다.\n        c.execute(\'UPDATE members SET consent=0,lat=NULL,lon=NULL,updated=NULL WHERE trip IN (SELECT id FROM trips WHERE end<?)\', (today(),))\n        user = dict(c.execute(\'SELECT id,name,username,app_role FROM users WHERE id=?\', (uid,)).fetchone())\n        trips = [dict(x) for x in c.execute(\'SELECT t.*,m.role FROM trips t JOIN members m ON m.trip=t.id WHERE m.user=? ORDER BY t.id DESC\', (uid,))]\n        tid = request.args.get(\'trip\', type=int)\n        if not tid or not any(t[\'id\'] == tid for t in trips): tid = trips[0][\'id\'] if trips else None\n        out = dict(user=user, trips=trips, trip=tid, members=[], plans=[], posts=[], checks=[], missions=[])\n        if tid:\n            member(c, tid)\n            for x in c.execute(\'SELECT m.*,u.name FROM members m JOIN users u ON u.id=m.user WHERE trip=?\', (tid,)):\n                m = dict(x)\n                fresh = m[\'updated\'] and (datetime.now(KST) - datetime.fromisoformat(m[\'updated\'])).total_seconds() < 300\n                if not (m[\'consent\'] and trip_active(c, tid) and fresh): m[\'lat\'] = m[\'lon\'] = None\n                out[\'members\'].append(m)\n            queries = {\n                \'arrivals\': \'SELECT a.*,p.title FROM arrivals a JOIN plans p ON p.id=a.plan WHERE a.trip=? ORDER BY a.id DESC LIMIT 100\',\n                \'emergencies\': \'SELECT * FROM emergencies WHERE trip=? ORDER BY id DESC LIMIT 100\',\n                \'plans\': \'SELECT * FROM plans WHERE trip=? ORDER BY at,id\',\n                \'posts\': \'SELECT p.*,u.name FROM posts p JOIN users u ON u.id=p.user WHERE trip=? ORDER BY p.id DESC LIMIT 100\',\n                \'checks\': \'SELECT * FROM checks WHERE trip=? ORDER BY id DESC LIMIT 100\',\n                \'missions\': \'SELECT * FROM missions WHERE trip=? ORDER BY id DESC LIMIT 100\'}\n            for k, q in queries.items(): out[k] = [dict(x) for x in c.execute(q, (tid,))]\n    return jsonify(out)\n\n@app.post(\'/api/trips\')\n@auth\ndef trips():\n    d = request.get_json() or {}\n    with db() as c:\n        if d.get(\'action\') == \'join\':\n            t = c.execute(\'SELECT * FROM trips WHERE code=?\', (text(d, \'code\', 20).upper(),)).fetchone()\n            if not t: return fail(\'초대 코드를 확인하세요.\')\n            c.execute("INSERT OR IGNORE INTO members(trip,user,role) VALUES(?,?,?)", (t[\'id\'], session[\'uid\'], c.execute(\'SELECT app_role FROM users WHERE id=?\',(session[\'uid\'],)).fetchone()[0]))\n            tid = t[\'id\']\n        else:\n            title = text(d, \'title\', 80)\n            start, end = text(d, \'start\', 10), text(d, \'end\', 10)\n            datetime.strptime(start, \'%Y-%m-%d\'); datetime.strptime(end, \'%Y-%m-%d\')\n            if start > end: raise ValueError(\'종료일은 시작일 이후여야 합니다.\')\n            tid = c.execute(\'INSERT INTO trips(title,start,end,code,owner) VALUES(?,?,?,?,?)\',\n                            (title, start, end, secrets.token_hex(5).upper(), session[\'uid\'])).lastrowid\n            c.execute("INSERT INTO members(trip,user,role) VALUES(?,?,?)", (tid, session[\'uid\'], c.execute(\'SELECT app_role FROM users WHERE id=?\',(session[\'uid\'],)).fetchone()[0]))\n    return jsonify(ok=True, trip=tid)\n\n@app.post(\'/api/action\')\n@auth\ndef action():\n    d = request.get_json() or {}; tid = int(d.get(\'trip\', 0)); uid = session[\'uid\']; action = d.get(\'action\')\n    with db() as c:\n        m = member(c, tid)\n        if m[\'role\']==\'parent\': raise PermissionError(\'부모 계정은 조회 전용입니다.\')\n        if action in (\'mission_add\',\'mission\',\'check\',\'role\'): raise PermissionError(\'이 버전에서는 조회만 가능합니다.\')\n        if action == \'role\':\n            raise PermissionError(\'역할은 계정에 연결되어 앱에서 변경할 수 없습니다.\')\n        elif action == \'sos\':\n            if m[\'role\']!=\'child\': raise PermissionError(\'자녀 계정에서 요청하세요.\')\n            if not c.execute(\'SELECT 1 FROM emergencies WHERE trip=? AND user=? AND resolved=0\',(tid,uid)).fetchone():\n                c.execute(\'INSERT INTO emergencies(trip,user,created) VALUES(?,?,?)\',(tid,uid,now()))\n        elif action == \'sos_resolve\':\n            parent(m)\n            c.execute(\'UPDATE emergencies SET resolved=1 WHERE id=? AND trip=?\',(int(d[\'id\']),tid))\n        elif action == \'plan_add\':\n            title = text(d, \'title\', 100); at = text(d, \'at\', 20)\n            datetime.fromisoformat(at)\n            t = c.execute(\'SELECT * FROM trips WHERE id=?\', (tid,)).fetchone()\n            if not t[\'start\'] <= at[:10] <= t[\'end\']: raise ValueError(\'여행 기간 안의 일정을 입력하세요.\')\n            plat,plon=d.get(\'place_lat\'),d.get(\'place_lon\')\n            if plat is None or plon is None: raise ValueError(\'도착 감지용 장소 좌표가 필요합니다.\')\n            plat,plon=float(plat),float(plon)\n            if not (-90<=plat<=90 and -180<=plon<=180): raise ValueError(\'장소 좌표를 확인하세요.\')\n            radius=int(d.get(\'radius_m\',200))\n            if not 50<=radius<=1000: raise ValueError(\'도착 반경은 50~1000m입니다.\')\n            c.execute(\'INSERT INTO plans(trip,title,at,place_lat,place_lon,radius_m,plan_user) VALUES(?,?,?,?,?,?,?)\',(tid,title,at,plat,plon,radius,uid))\n        elif action == \'plan_status\':\n            owned=c.execute(\'SELECT plan_user FROM plans WHERE id=? AND trip=?\',(int(d[\'id\']),tid)).fetchone()\n            if not owned or owned[\'plan_user\']!=uid: raise PermissionError(\'본인이 등록한 일정만 변경할 수 있습니다.\')\n            status = d.get(\'status\')\n            if status not in (\'예정\', \'진행 중\', \'완료\'): raise ValueError(\'잘못된 일정 상태입니다.\')\n            c.execute(\'UPDATE plans SET status=? WHERE id=? AND trip=?\', (status, int(d[\'id\']), tid))\n        elif action == \'consent\':\n            enabled = bool(d.get(\'enabled\'))\n            if enabled and not trip_active(c, tid): raise ValueError(\'위치 공유는 여행 기간에만 가능합니다. (한국 시간 기준)\')\n            c.execute(\'UPDATE members SET consent=?,lat=NULL,lon=NULL,updated=NULL WHERE trip=? AND user=?\', (int(enabled), tid, uid))\n        elif action == \'location\':\n            if not m[\'consent\'] or not trip_active(c, tid): raise PermissionError(\'위치 공유 동의와 여행 기간을 확인하세요.\')\n            lat, lon = float(d[\'lat\']), float(d[\'lon\'])\n            if not (-90 <= lat <= 90 and -180 <= lon <= 180): raise ValueError(\'잘못된 좌표입니다.\')\n            c.execute(\'UPDATE members SET lat=?,lon=?,updated=? WHERE trip=? AND user=?\', (lat, lon, now(), tid, uid))\n            for plan in c.execute(\'SELECT * FROM plans WHERE trip=? AND plan_user=? AND substr(at,1,10)=? AND place_lat IS NOT NULL AND place_lon IS NOT NULL\',(tid,uid,today())).fetchall():\n                meters=distance_m(lat,lon,plan[\'place_lat\'],plan[\'place_lon\'])\n                if meters<=plan[\'radius_m\']:\n                    c.execute(\'INSERT OR IGNORE INTO arrivals(trip,plan,user,created,distance) VALUES(?,?,?,?,?)\',(tid,plan[\'id\'],uid,now(),meters))\n                    c.execute("UPDATE plans SET status=\'완료\' WHERE id=?",(plan[\'id\'],))\n\n        elif action == \'check\':\n            parent(m); target = int(d[\'target\']); child(c, tid, target)\n            recent = c.execute(\'SELECT created FROM checks WHERE trip=? AND sender=? AND target=? ORDER BY id DESC LIMIT 1\', (tid, uid, target)).fetchone()\n            if recent and (datetime.now(KST)-datetime.fromisoformat(recent[\'created\'])).total_seconds() < 600:\n                raise ValueError(\'같은 자녀에게는 10분에 한 번 요청할 수 있습니다.\')\n            c.execute(\'INSERT INTO checks(trip,sender,target,created) VALUES(?,?,?,?)\', (tid, uid, target, now()))\n        elif action == \'well\':\n            if m[\'role\'] != \'child\': raise PermissionError(\'자녀가 응답할 수 있습니다.\')\n            c.execute("UPDATE checks SET answered=?,response=\'잘 지내요 💚\' WHERE trip=? AND target=? AND answered IS NULL", (now(), tid, uid))\n            c.execute(\'INSERT INTO posts(trip,user,body,created) VALUES(?,?,?,?)\', (tid, uid, \'잘 지내요 💚\', now()))\n        elif action == \'mission_add\':\n            parent(m); target = int(d[\'target\']); child(c, tid, target)\n            amount = int(d.get(\'amount\', 0))\n            if not 0 <= amount <= 1000000: raise ValueError(\'용돈은 0~1,000,000원으로 입력하세요.\')\n            c.execute(\'INSERT INTO missions(trip,maker,target,title,amount,created) VALUES(?,?,?,?,?,?)\', (tid, uid, target, text(d, \'title\', 200), amount, now()))\n        elif action == \'mission\':\n            q = c.execute(\'SELECT * FROM missions WHERE id=? AND trip=?\', (int(d[\'id\']), tid)).fetchone()\n            if not q: raise ValueError(\'미션을 찾을 수 없습니다.\')\n            move = d.get(\'move\'); status = q[\'status\']\n            if move in (\'수락\', \'거절\'):\n                if uid != q[\'target\'] or status != \'제안\': raise PermissionError(\'미션 대상자만 수락 또는 거절할 수 있습니다.\')\n                c.execute(\'UPDATE missions SET status=? WHERE id=?\', (\'수행 중\' if move == \'수락\' else \'거절\', q[\'id\']))\n            elif move == \'수령 확인\':\n                if uid != q[\'target\'] or status != \'지급 기록 완료\': raise PermissionError(\'지급 기록 후 대상자가 확인할 수 있습니다.\')\n                c.execute(\'UPDATE missions SET received=1 WHERE id=?\', (q[\'id\'],))\n            else:\n                parent(m)\n                if uid != q[\'maker\']: raise PermissionError(\'미션을 제안한 부모만 확인할 수 있습니다.\')\n                transitions = {(\'확인 대기\', \'승인\'): \'지급 대기\', (\'확인 대기\', \'재인증 요청\'): \'수행 중\', (\'지급 대기\', \'지급했어요\'): \'지급 기록 완료\'}\n                new = transitions.get((status, move))\n                if not new: raise ValueError(\'현재 상태에서 할 수 없는 작업입니다.\')\n                c.execute(\'UPDATE missions SET status=?,paid_at=? WHERE id=?\', (new, now() if new == \'지급 기록 완료\' else None, q[\'id\']))\n        elif action == \'delete_post\':\n            p = c.execute(\'SELECT * FROM posts WHERE id=? AND trip=?\', (int(d[\'id\']), tid)).fetchone()\n            if not p or p[\'user\'] != uid: raise PermissionError(\'본인 게시물만 삭제할 수 있습니다.\')\n            c.execute("UPDATE missions SET evidence=NULL,status=CASE WHEN status=\'확인 대기\' THEN \'수행 중\' ELSE status END WHERE evidence=?", (p[\'id\'],))\n            c.execute(\'DELETE FROM posts WHERE id=?\', (p[\'id\'],))\n            if p[\'photo\']: (ROOT / \'photos\' / p[\'photo\']).unlink(missing_ok=True)\n        else: raise ValueError(\'지원하지 않는 작업입니다.\')\n    return jsonify(ok=True)\n\n@app.post(\'/api/post\')\n@auth\ndef post():\n    tid = int(request.form.get(\'trip\', 0)); uid = session[\'uid\']\n    with db() as c:\n        if member(c,tid)[\'role\']!=\'child\': raise PermissionError(\'부모 계정은 사진과 소식을 조회만 할 수 있습니다.\')\n    if request.form.get(\'mission\'): raise PermissionError(\'기존 미션은 조회 전용입니다.\')\n    body = request.form.get(\'body\', \'\').strip(); filename = None\n    if len(body) > 1000: raise ValueError(\'글은 1,000자 이하로 입력하세요.\')\n    upload = request.files.get(\'photo\'); image_bytes = None\n    if upload and upload.filename:\n        data = upload.read(8*1024*1024+1)\n        if len(data) > 8*1024*1024: raise ValueError(\'사진은 8MB 이하로 올려 주세요.\')\n        try:\n            with Image.open(io.BytesIO(data)) as image:\n                if image.width * image.height > 25000000: raise ValueError(\'사진 해상도가 너무 큽니다. 줄여서 올려 주세요.\')\n                image = ImageOps.exif_transpose(image).convert(\'RGB\'); image.thumbnail((1600, 1600))\n                buf = io.BytesIO(); image.save(buf, format=\'JPEG\', quality=85); image_bytes = buf.getvalue()\n        except (UnidentifiedImageError, OSError, Image.DecompressionBombError): raise ValueError(\'읽을 수 있는 사진 파일을 올려 주세요.\')\n        filename = secrets.token_hex(20) + \'.jpg\'  # 재인코딩하여 GPS 등 EXIF 제거\n    if not body and not filename: raise ValueError(\'글이나 사진을 추가하세요.\')\n    try:\n        with db() as c:\n            m = member(c, tid)\n            mission_id = request.form.get(\'mission\')\n            if mission_id:\n                q = c.execute("SELECT * FROM missions WHERE id=? AND trip=? AND target=? AND status=\'수행 중\'", (int(mission_id), tid, uid)).fetchone()\n                if not q: raise PermissionError(\'수행 중인 본인 미션만 인증할 수 있습니다.\')\n            if filename: (ROOT / \'photos\' / filename).write_bytes(image_bytes)\n            pid = c.execute(\'INSERT INTO posts(trip,user,body,photo,created) VALUES(?,?,?,?,?)\', (tid, uid, body, filename, now())).lastrowid\n            if mission_id: c.execute("UPDATE missions SET status=\'확인 대기\',evidence=? WHERE id=?", (pid, int(mission_id)))\n            if m[\'role\'] == \'child\' and request.form.get(\'reply\') == \'1\':\n                c.execute("UPDATE checks SET answered=?,response=\'사진/글로 안부를 전했어요\' WHERE trip=? AND target=? AND answered IS NULL", (now(), tid, uid))\n    except Exception:\n        if filename: (ROOT / \'photos\' / filename).unlink(missing_ok=True)\n        raise\n    return jsonify(ok=True)\n\n@app.get(\'/photo/<int:pid>\')\n@auth\ndef photo(pid):\n    with db() as c:\n        p = c.execute(\'SELECT * FROM posts WHERE id=?\', (pid,)).fetchone()\n        if not p or not p[\'photo\']: return fail(\'사진이 없습니다.\', 404)\n        member(c, p[\'trip\'])\n        return send_file(ROOT / \'photos\' / p[\'photo\'], mimetype=\'image/jpeg\')\n\n'

import streamlit as st
from datetime import date
import io

st.set_page_config(page_title='안심여행 · 우리 가족 여행 메이트', page_icon='🐰', layout='centered',initial_sidebar_state='collapsed')

st.markdown('<style>\n:root{color-scheme:light}\n.stApp,[data-testid="stAppViewContainer"], [data-testid="stHeader"]{background:#fff9f2!important;color:#352d4b!important}\n.block-container{max-width:820px;padding-top:2rem;padding-bottom:5rem}\n[data-testid="stSidebar"]{background:#f1eaff!important}\n[data-testid="stMarkdownContainer"], [data-testid="stMarkdownContainer"] p,label,[data-testid="stWidgetLabel"] p,h1,h2,h3{color:#352d4b!important}\n[data-testid="stCaptionContainer"], [data-testid="stCaptionContainer"] p{color:#645c73!important}\n[data-testid="stForm"],[data-testid="stVerticalBlockBorderWrapper"]>div{border-radius:22px!important}\n[data-testid="stForm"]{background:#ffffff!important;border:1px solid #e2d8ed!important;padding:20px!important}\ninput,textarea,[data-baseweb="input"],[data-baseweb="textarea"], [data-baseweb="select"]>div{background:#fff!important;color:#352d4b!important;-webkit-text-fill-color:#352d4b!important;border-color:#b4a4c6!important;caret-color:#352d4b}\n[data-testid="stCode"], [data-testid="stCode"] pre, [data-testid="stCode"] code{background:#f0eafa!important;color:#352d4b!important}\ninput::placeholder,textarea::placeholder{color:#746c80!important;-webkit-text-fill-color:#746c80!important}\n[data-baseweb="popover"],[data-baseweb="menu"], [role="listbox"],[role="option"]{background:#fff!important;color:#352d4b!important}\nbutton{border-radius:16px!important;min-height:48px!important;font-weight:650!important}\nbutton[kind="secondary"],button[kind="tertiary"],button[data-testid="stBaseButton-secondaryFormSubmit"]{background:#fff!important;color:#49385f!important;border:1px solid #cfc0e0!important}\nbutton[kind="secondary"] p,button[kind="tertiary"] p{color:#49385f!important}\nbutton[kind="primary"],button[data-testid="stBaseButton-primaryFormSubmit"]{background:#69449b!important;border-color:#69449b!important;color:#fff!important}\nbutton[kind="primary"] p,button[data-testid="stBaseButton-primaryFormSubmit"] p{color:#fff!important}\nbutton:hover{filter:brightness(.96)}button:focus-visible{outline:3px solid #a6602d!important}\n[data-testid="stAlert"]{background:#f0eafa!important;color:#352d4b!important}\n.hero{background:linear-gradient(130deg,#eee3ff,#ffe9db);padding:30px 26px;border-radius:30px;border:1px solid #e4d3ec;margin-bottom:22px;color:#352d4b}\n.hero .mascot{font-size:58px;letter-spacing:9px}.hero h1{font-size:34px;line-height:1.3;margin:10px 0}.hero p{color:#51445f!important;font-size:16px}\n.pill{display:inline-block;background:#fff8fd;color:#62408a;padding:5px 12px;border-radius:30px;font-size:13px;font-weight:700}\n.feature{background:#fff;border:1px solid #e9dfee;border-radius:20px;padding:20px;margin:10px 0;color:#352d4b}.feature strong{font-size:18px}\n@media(max-width:640px){.block-container{padding:1.2rem 1rem 4rem}.hero{padding:25px 20px}.hero h1{font-size:29px}.hero .mascot{font-size:48px}}\n</style>',unsafe_allow_html=True)

@st.cache_resource
def backend_scope():
    scope={'__name__':'__main__'}
    exec(BACKEND_SOURCE,scope)
    return scope

def backend():
    return backend_scope()['app']

server=backend()
if 'client' not in st.session_state:
    st.session_state.client=server.test_client()
client=st.session_state.client

st.markdown('<style>\n.stApp,[data-testid="stAppViewContainer"]{background-color:#eff9f4!important;background-image:radial-gradient(ellipse at 12% 8%,#ffffff 0 7%,transparent 7.3%),radial-gradient(ellipse at 90% 20%,#ffffff 0 9%,transparent 9.3%),radial-gradient(ellipse at 10% 100%,#cfe9c9 0 25%,transparent 25.3%),radial-gradient(ellipse at 90% 100%,#dcefc5 0 30%,transparent 30.3%)!important;background-attachment:fixed!important;color:#263d38!important}\n.block-container{max-width:860px;padding-top:1.5rem}\n[data-testid="stHeader"]{background:transparent!important}\nh1,h2,h3{color:#284d43!important}\n.hero{background:#fffdf3!important;border:2px solid #d5e9ce!important;border-radius:30px!important;padding:22px!important;box-shadow:0 6px 0 #deebd3}\n.hero .mascot{font-size:42px!important}.hero h1{font-size:32px!important}\n[data-testid="stVerticalBlockBorderWrapper"]{background:#ffffffdc;border-radius:22px!important}\ndiv.stButton>button{border-radius:18px!important;border:1px solid #ccdfd5!important;background:#fffdf8!important;color:#264c40!important;font-weight:700!important;min-height:48px}\ndiv.stButton>button[kind="primary"],div.stFormSubmitButton>button{background:#2e705b!important;color:white!important;border-color:#2e705b!important}\n[data-testid="stSidebar"]{background:#e3f0df!important}\ninput,textarea,[data-baseweb="select"]>div{background:white!important;color:#263d38!important}\n[data-testid="stMarkdownContainer"] p,[data-testid="stWidgetLabel"] p{color:#263d38}\n[data-testid="stCode"] pre,[data-testid="stCode"] code{background:#fff4ca!important;color:#294b40!important}\n</style>',unsafe_allow_html=True)

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


st.markdown("""<style>
:root {color-scheme:light!important}
.stApp,[data-testid="stAppViewContainer"]{color:#162c25!important}
.stApp p,.stApp label,.stApp h1,.stApp h2,.stApp h3,.stApp h4,.stApp small,.stApp summary{color:#162c25!important;opacity:1!important}
input,textarea,[data-baseweb="input"],[data-baseweb="base-input"],[data-baseweb="textarea"],[data-baseweb="select"]>div{background:#fff!important;color:#162c25!important;-webkit-text-fill-color:#162c25!important;border-color:#718a7c!important}
input::placeholder,textarea::placeholder{color:#52665d!important;opacity:1!important;-webkit-text-fill-color:#52665d!important}
[data-testid="stForm"],[data-testid="stExpander"],details,[data-testid="stVerticalBlockBorderWrapper"],[data-testid="stAlert"]{background:#fffefa!important;color:#162c25!important;border-color:#92ab9c!important;border-radius:18px}
[data-baseweb="popover"],[role="listbox"],[role="option"],[data-baseweb="calendar"],[data-baseweb="calendar"] *{background:#fff!important;color:#162c25!important}
button{background:#fff!important;color:#163f30!important;border-color:#718a7c!important}
button p,button span{color:inherit!important}
button[kind="primary"], [data-testid="stFormSubmitButton"] button{background:#215c46!important;color:#fff!important}
button[kind="primary"] p,[data-testid="stFormSubmitButton"] button p{color:#fff!important}
[data-testid="stSidebar"]{background:#edf5e9!important}
[data-testid="stCode"],[data-testid="stCode"] pre,[data-testid="stCode"] code{background:#fff3ce!important;color:#162c25!important}
.entry-logo{text-align:center;padding:55px 14px 38px;background:linear-gradient(160deg,#fffefa,#dcefd7);border:2px solid #a9c8aa;border-radius:32px;margin:20px 0 26px;box-shadow:0 8px 0 #d9e7ce}
.entry-logo h1{font-size:40px!important;letter-spacing:-1.5px}
</style>""",unsafe_allow_html=True)


st.markdown("""<style>
/* Explicit background and foreground together, including Streamlit dark alert variants. */
[data-testid="stAlert"], [data-testid="stAlertContainer"], [data-testid="stNotification"], [data-testid="stAlert"]>div {background:#fff9df!important;color:#192f27!important;border-color:#b59e50!important}
[data-testid="stAlert"] *,[data-testid="stAlertContainer"] *,[data-testid="stNotification"] *{color:#192f27!important;-webkit-text-fill-color:#192f27!important;opacity:1!important}
[data-testid="stTextInputRootElement"],[data-testid="stDateInput"] [data-baseweb="input"],[data-testid="stTimeInput"] [data-baseweb="input"],[data-testid="stNumberInputContainer"], [data-baseweb="input"]>div{background:#fff!important;color:#192f27!important}
[data-testid="stExpander"] details,[data-testid="stExpander"] summary,[data-testid="stExpanderDetails"],[data-testid="stForm"]{background:#fffef9!important;color:#192f27!important}
.entry-logo{max-width:410px;margin:12px auto 24px!important;padding:20px 16px!important}
.walking-logo,.travel-art{display:block;font-size:42px;line-height:1.3;letter-spacing:2px;text-align:center}
.entry-logo h1{margin:8px 0 4px!important;font-size:34px!important}
.entry-logo p{margin:0!important}
.travel-banner{max-width:430px;margin:0 auto 20px;padding:18px;background:linear-gradient(#e8f6ff 0 62%,#e3efcc 62%);border:2px solid #a9c6a0;border-radius:25px;text-align:center}
</style>""",unsafe_allow_html=True)

if st.session_state.pop('notice',None): st.success('가족에게 전했어요! 💌')
try: state=call('/api/state'+('?trip='+str(st.session_state.trip_id) if st.session_state.get('trip_id') else ''))
except ValueError: state=None
if not state:
    stage=st.session_state.get('entry_stage','cover')
    if stage=='cover':
        st.markdown('<div class="entry-logo"><div class="walking-logo">☀️ 🗺️<br>🐰🎒 🧳<br>🌿 👣 🌼</div><h1>안심여행</h1><p>마음은 함께, 여행은 신나게</p></div>',unsafe_allow_html=True)
        if st.button('앱 열기 ✨',type='primary',use_container_width=True):
            st.session_state.entry_stage='role';st.rerun()
    else:
        st.subheader('누구와 함께할까요?')
        a,b=st.columns(2)
        choice=None
        if a.button('🏡 부모로 시작',use_container_width=True): choice='parent'
        if b.button('🎒 자녀로 시작',use_container_width=True): choice='child'
        if choice:
            import secrets
            # Each browser session gets a separate temporary identity, never a shared parent/child account.
            with server.app_context():
                ns=backend_scope()
                with ns['db']() as c:
                    guest=c.execute('INSERT INTO users(username,name,password,app_role) VALUES(?,?,?,?)',
                        ('guest_'+secrets.token_hex(16),'부모' if choice=='parent' else '여행하는 자녀',ns['generate_password_hash'](secrets.token_urlsafe(48)),choice)).lastrowid
            with client.session_transaction() as sess:
                sess.clear();sess['uid']=guest;sess['csrf']=secrets.token_hex(24);sess.permanent=True
            st.rerun()
        if st.button('← 처음으로'): st.session_state.entry_stage='cover';st.rerun()
    st.caption('회원가입 없는 체험 버전 · 초대 코드를 아는 사람이 참여할 수 있어요. 실제 민감정보는 올리지 마세요. 연결을 잃으면 기존 이용자로 복구할 수 없습니다.')
    st.stop()

uid=state['user']['id']
parent_mode=state['user'].get('app_role')=='parent'
with st.sidebar:
    st.write(('🏡 ' if parent_mode else '🎒 ')+state['user']['name'])
    if st.button('역할 선택으로 돌아가기'):
        st.session_state.entry_stage='role'
        st.session_state.pop('trip_id',None)
        st.session_state.page='홈'
        run('/api/logout',{})
    st.caption('위치는 동의 후 수동 전송 · 앱을 닫으면 자동 추적하지 않습니다. 로컬 데이터는 재배포 시 보존되지 않을 수 있습니다.')
def travel_entry():
    with st.expander('💌 초대 코드로 참여',expanded=parent_mode):
        with st.form('join'):
            code=st.text_input('초대 코드',placeholder='자녀가 보내준 코드를 입력하세요')
            if st.form_submit_button('참여하기',type='primary',use_container_width=True):
                try:
                    result=call('/api/trips',dict(action='join',code=code));st.session_state.trip_id=result['trip'];st.rerun()
                except ValueError as e: st.error(str(e))
    if not parent_mode:
        with st.expander('🎒 새 여행 만들기',expanded=True):
            with st.form('create'):
                title=st.text_input('여행 이름',placeholder='예: 부산 바다 여행',max_chars=80)
                dates=st.date_input('여행 기간',value=(date.today(),date.today()))
                if st.form_submit_button('여행 만들고 초대 코드 받기',type='primary',use_container_width=True):
                    if len(dates)!=2: st.error('시작일과 종료일을 선택하세요.')
                    else:
                        try:
                            r=call('/api/trips',dict(title=title,start=str(dates[0]),end=str(dates[1])));st.session_state.trip_id=r['trip'];st.rerun()
                        except ValueError as e: st.error(str(e))
if not state['trips']:
    st.markdown('<div class="travel-banner"><span class="travel-art">☀️ 🗺️<br>🐰🎒 🧳<br>🌿 👣 🌼</span><h3>여행을 시작해요</h3></div>',unsafe_allow_html=True)
    travel_entry()
    st.stop()
ids=[t['id'] for t in state['trips']]
selected=st.sidebar.selectbox('여행',ids,index=ids.index(state['trip']),format_func=lambda x:next(t['title'] for t in state['trips'] if t['id']==x))
if selected!=state['trip']: st.session_state.trip_id=selected;st.rerun()
st.session_state.trip_id=selected
trip=next(t for t in state['trips'] if t['id']==selected)
me=next(m for m in state['members'] if m['user']==uid)
is_parent=parent_mode

def who(user): return next((m['name'] for m in state['members'] if m['user']==user),'가족')
def act(action,**kw): run('/api/action',dict(trip=selected,action=action,**kw))
def show_post(post):
    st.write('**'+post['name']+'**')
    if post['body']: st.text(post['body'])
    if post['photo']:
        response=client.get('/photo/'+str(post['id']))
        if response.status_code==200: st.image(response.data,use_container_width=True)
    st.caption(post['created'].replace('T',' '))

@st.fragment(run_every='12s')
def map_panel():
    import folium,html
    import streamlit.components.v1 as components
    fresh=call('/api/state?trip='+str(selected))
    pins=[m for m in fresh['members'] if m['role']=='child' and m['lat'] is not None and m['lon'] is not None]
    if pins:
        mp=folium.Map(location=[pins[0]['lat'],pins[0]['lon']],zoom_start=15,tiles='CartoDB positron')
        for m in pins:
            folium.Marker([m['lat'],m['lon']],tooltip=html.escape(m['name']),popup=html.escape(m['name']+' · '+str(m['updated']))).add_to(mp)
        if len(pins)>1: mp.fit_bounds([[m['lat'],m['lon']] for m in pins],max_zoom=16)
        components.html(mp.get_root().render(),height=380,scrolling=False)
        st.caption('최근 5분 내 공유 위치 · 마지막 전송 시각은 마커 터치')
    else: st.info('🌳 아직 공유된 현재 위치가 없어요.')

@st.fragment(run_every='12s')
def arrival_panel():
    fresh=call('/api/state?trip='+str(selected))
    events=fresh.get('arrivals',[])
    for emergency in fresh.get('emergencies',[]):
        if not emergency['resolved']: st.error('🆘 '+who(emergency['user'])+' · 도움 요청 · '+emergency['created'].replace('T',' '))
    if not events: st.caption('아직 도착 알림이 없어요.')
    for event in events[:20]:
        with st.container(border=True):
            st.write('📍 **'+who(event['user'])+' · '+event['title']+' 도착**')
            st.caption(event['created'].replace('T',' ')+' · 등록 반경 내 위치 감지')

menus=['홈','사진','일정','알림','미션'] if is_parent else ['홈','일정','사진','위치','긴급','미션']
icons=['🏡','📸','🧭','🔔','🎁'] if is_parent else ['🎒','🧭','📸','📍','🆘','🎁']
page=st.session_state.get('page','홈')
if page not in menus: page='홈';st.session_state.page=page
with st.container(key='bottom_nav'):
    cols=st.columns(len(menus))
    for col,name,icon in zip(cols,menus,icons):
        if col.button(icon+' '+name,key='nav'+name,use_container_width=True,type='primary' if page==name else 'secondary'):
            st.session_state.page=name;st.rerun()
st.markdown('''<style>
.block-container{padding-top:.6rem!important;padding-bottom:110px!important}
.st-key-bottom_nav{position:fixed!important;bottom:0;left:50%;transform:translateX(-50%);width:min(860px,100%);z-index:999;background:#fffdf6!important;border-top:1px solid #c9dfce;border-radius:22px 22px 0 0;padding:10px 5px calc(10px + env(safe-area-inset-bottom));box-shadow:0 -5px 20px #183d3612}
.st-key-bottom_nav [data-testid="stHorizontalBlock"]{gap:3px!important;flex-wrap:nowrap!important}
.st-key-bottom_nav [data-testid="stColumn"]{min-width:0!important;flex:1 1 0!important;width:auto!important}
.st-key-bottom_nav button{padding:4px 1px!important;min-height:50px!important;border:0!important;border-radius:14px!important}
.st-key-bottom_nav button p{font-size:12px!important;white-space:normal!important}
</style>''',unsafe_allow_html=True)
head={'홈':'🏡 우리 아이 안심홈' if is_parent else '🎒 오늘의 여행','사진':'📸 아이의 사진' if is_parent else '📸 여행 사진','일정':'🧭 아이의 일정' if is_parent else '🧭 내 일정','알림':'🔔 도착 알림','위치':'📍 내 위치 공유','미션':'🎁 기존 미션 · 조회 전용','긴급':'🆘 긴급 도움'}
st.subheader(head[page])
if page=='홈':
    if is_parent:
        map_panel()
        st.markdown('#### 🔔 도착 소식')
        arrival_panel()
        latest=next((x for x in state['posts'] if any(m['user']==x['user'] and m['role']=='child' for m in state['members'])),None)
        if latest:
            st.markdown('#### 📸 최근 소식');show_post(latest)
    else:
        st.markdown('<div class="hero"><div class="mascot">☀️ 🐰 🎒 🌳</div><h3>오늘은 어디로 떠날까?</h3></div>',unsafe_allow_html=True)
        if st.button('💚 잘 지내요',type='primary',use_container_width=True): act('well')
        if st.button('📍 현재 위치 공유',use_container_width=True): st.session_state.page='위치';st.rerun()
        st.markdown('#### 💌 부모님 초대 코드')
        st.code(trip['code'],language=None)
        for q in state['plans']:
            if q.get('plan_user')==uid and q['status']!='완료':
                st.info('🧭 다음 · '+q['title']);break
    with st.expander('＋ 다른 여행 만들기 · 참여'):
        travel_entry()
elif page=='알림': arrival_panel()
elif page=='일정':
    for q in state['plans']:
        with st.container(border=True):
            st.write('**'+q['title']+'** · '+q['status'])
            st.caption(q['at'].replace('T',' ')+' · '+who(q.get('plan_user')))
            if q.get('place_lat') is not None: st.caption(f"📍 {q['place_lat']:.5f}, {q['place_lon']:.5f} · 반경 {q['radius_m']}m")
            else: st.caption('이전 일정 · 도착 감지 좌표 없음')
    if not is_parent:
        with st.expander('＋ 일정 · 장소 등록'):
            st.caption('장소 좌표를 등록하면 오늘 일정의 반경 안에서 위치를 전송할 때 도착이 기록돼요. 좌표는 외부 지도에서 확인해 입력하세요.')
            with st.form('plan_add'):
                title=st.text_input('일정 · 장소 이름',max_chars=100)
                day=st.date_input('날짜',value=date.fromisoformat(trip['start']))
                at=st.time_input('시간')
                lat=st.number_input('장소 위도 (-90~90)',min_value=-90.,max_value=90.,value=None,format='%.6f')
                lon=st.number_input('장소 경도 (-180~180)',min_value=-180.,max_value=180.,value=None,format='%.6f')
                radius=st.select_slider('도착 반경 (m)',options=[50,100,200,300,500,1000],value=200)
                if st.form_submit_button('일정 등록',type='primary'):
                    if lat is None or lon is None: st.error('장소의 위도와 경도를 입력하세요.')
                    else: act('plan_add',title=title,at=f'{day}T{at:%H:%M}',place_lat=lat,place_lon=lon,radius_m=radius)
elif page=='사진':
    if not is_parent:
        with st.expander('📸 사진 · 한 줄 남기기'):
            with st.form('photo',clear_on_submit=True):
                photo=st.file_uploader('사진 (선택 · 8MB 이하)',type=['png','jpg','jpeg','webp'])
                body=st.text_input('한 줄 (선택)',max_chars=200)
                if st.form_submit_button('올리기',type='primary'):
                    form=dict(trip=str(selected),body=body,reply='1')
                    if photo: form['photo']=(io.BytesIO(photo.getvalue()),photo.name)
                    run('/api/post',form=form)
    for q in state['posts']:
        if any(m['user']==q['user'] and m['role']=='child' for m in state['members']):
            with st.container(border=True): show_post(q)
elif page=='위치':
    st.caption('내 동의로 가족에게 공유 · 언제든 중지')
    if not me['consent']:
        if st.button('📍 동의하고 위치 공유 켜기',type='primary',use_container_width=True): act('consent',enabled=True)
    else:
        from streamlit_geolocation import streamlit_geolocation
        loc=streamlit_geolocation()
        if loc and loc.get('latitude') is not None:
            if st.button('📍 현재 위치 전송 · 도착 확인',type='primary',use_container_width=True): act('location',lat=loc['latitude'],lon=loc['longitude'])
        if st.button('공유 중지 · 좌표 삭제',use_container_width=True): act('consent',enabled=False)
    st.caption('HTTPS와 위치 권한 필요 · 여행 기간 중에만 가능 · 오늘 등록 일정 대상 · 일정별 한 번만 도착 알림')
    map_panel()
elif page=='긴급':
    st.error('즉시 위험하면 현지 긴급기관에 먼저 연락하세요.')
    st.markdown('[🚑 119 · 한국](tel:119)　[🚓 112 · 한국](tel:112)')
    if st.button('🆘 앱에 도움 요청 남기기',type='primary',use_container_width=True): act('sos')
    st.caption('자동 신고·문자·푸시 기능이 아닙니다. 부모가 앱의 홈 또는 알림 화면을 보고 있을 때 표시됩니다. 해외에서는 현지 긴급번호를 이용하세요.')
elif page=='미션':
    st.caption('기존 기록만 표시 · 새 미션·인증·승인·지급 변경 불가 · 실제 송금 없음')
    if not state['missions']: st.info('기존 미션이 없어요.')
    for q in state['missions']:
        with st.container(border=True):
            st.write('**'+q['title']+'**')
            st.write(f"{who(q['target'])} · {q['amount']:,}원 · {q['status']}")
            if q['evidence']:
                evidence=next((x for x in state['posts'] if x['id']==q['evidence']),None)
                if evidence: show_post(evidence)
            if q['paid_at']: st.caption('지급 기록 '+q['paid_at']+' · 수령 '+('확인' if q['received'] else '미확인'))
with st.sidebar.expander('🔒 안내'):
    st.caption('문자가 아닌 앱 내 기록입니다. 부모의 홈·알림은 화면을 열어 둔 동안 12초 주기로 갱신됩니다. 자녀가 현재 위치를 직접 전송할 때만 도착을 감지합니다. GPS 오차에 따라 실제 도착과 다를 수 있습니다. 좌표를 지도에 표시할 때 외부 지도 서비스를 이용합니다. 사진 EXIF는 제거합니다.')
