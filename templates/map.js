/* folderscan system map : data is embedded in <script id="data"> by folderscan (no server needed) */
(function () {
  'use strict';
  const D = JSON.parse(document.getElementById('data').textContent);
  const $ = s => document.querySelector(s);
  const $$ = s => Array.from(document.querySelectorAll(s));
  const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  // ---------------------------------------------------------------- labels
  const ROLE = {
    'launcher': '起動スクリプト', 'application-entry': '起点(main)', 'web-api/server': 'サーバー', 'frontend/http-client': '通信する画面・処理',
    'frontend-view': '画面', 'frontend/static-asset': '静的ファイル', 'module/library': '部品', 'reference-source': '参照される資料',
    'dependency-manifest': '依存の定義', 'configuration': '設定', 'datastore/schema': 'DB定義', 'datastore': 'データベース',
    'test': 'テスト', 'documentation': '文書', 'generated/vendor': '生成物・外部製', 'binary-artifact': 'バイナリ', 'unclassified': '未分類'
  };
  const TYPE = {
    IMPORT: '読み込み', EXEC: '起動', INCLUDE: '埋め込み', HTTP: '通信', CONFIG: '設定', SQL: 'SQL', DBREF: 'DB参照', DBFILE: 'DBの対',
    REF: '名前の記載', PATTERN: 'パターン一致', FILEMATCH: '名前の一致', SYM: '同じ名前の関数等', KEY: '共通の値', SAME: '同一内容', STEM: '同名・別拡張子'
  };
  const TYPE_COLOR = {
    IMPORT: '#2f5d8a', EXEC: '#c0492b', INCLUDE: '#7a5ea8', HTTP: '#d9822b', CONFIG: '#2f8f63', SQL: '#8a6d2f', DBREF: '#8a6d2f', DBFILE: '#a08a5a',
    REF: '#5b8db8', PATTERN: '#5b8db8', FILEMATCH: '#5b8db8', SYM: '#9aa6b2', KEY: '#b5a7c9', SAME: '#9aa6b2', STEM: '#b0b9c3'
  };
  const ORIGIN = { 'source-code': 'ソースコード', 'text-data': 'テキストデータ', 'test-code': 'テストコード', 'documentation': '文書', 'binary-string': 'バイナリ', 'generated-vendor': '生成物・外部製', 'other': 'その他' };
  const DEPTH = { structure: '構造まで読めた', generic: '文字列だけ', none: '読めていない' };
  const EV = { fact: '明記(確実)', match: '規則で特定', candidate: '推定', weak: '弱い' };
  const ACTION = { actionable: '要対応', tracked: '重複(追跡中)', explained: '説明済み', benign: '問題なし' };
  const CLS = {
    'import-unresolved': 'import 先が見つからない', 'file-read-unexplained': '正体不明の読み込みファイル', 'http-no-route': '通信先のルートが見つからない',
    'http-ambiguous': '通信先が複数候補', 'filename-ambiguous': 'ファイル名が複数に該当', 'format-not-parsed': '形式を解析できない',
    'isolated-file': 'どこからも使われていない', 'role-unclassified': '役割が分からない', 'regex-timeout': '解析が時間切れ',
    'scan-access-error': 'フォルダにアクセスできない', 'scan-empty': 'ファイルがない', 'external-file': 'フォルダ外の読み込みファイル',
    'external-data-reference': 'フォルダ外のデータ参照', 'local-module-missing': '自作の部品が見つからない', 'third-party-or-local-undeclared': '依存の宣言がないライブラリ',
    'third-party-no-manifest': '依存定義ファイルがない', 'third-party-known-undeclared': '宣言のない既知ライブラリ', 'missing-asset-or-served-elsewhere': '見つからない画面部品',
    'external-table': 'フォルダ外のテーブル', 'external-module': '外部モジュール', 'external-other': 'その他の外部参照', 'internal-candidate': '推定の関係',
    'output-file-candidate': '書き出すファイル', 'runtime-work-file': '実行時の作業ファイル', 'runtime-file-candidate': '実行時のファイル', 'configured-data-path': '設定に書かれたパス',
    'external-program': '外部プログラム', 'file-pattern': 'ファイル名のパターン', 'stdlib': '標準ライブラリ', 'third-party-declared': '宣言済みライブラリ', 'lexical-only': '名前だけ(実ファイルでない)',
    'unc-path': '共有フォルダ', 'absolute-path': '絶対パス', 'url': 'URL', 'registry': 'レジストリ', 'env-var': '環境変数', 'ip-address': 'IPアドレス'
  };
  const clsHtml = c => '<span title="' + esc(c) + '">' + esc(CLS[c] || c) + '</span>';
  const STRONG = new Set(['IMPORT', 'EXEC', 'INCLUDE', 'HTTP', 'CONFIG', 'SQL', 'DBREF', 'DBFILE', 'REF', 'PATTERN', 'FILEMATCH']);
  const HEURISTIC = ['SYM', 'KEY', 'SAME', 'STEM'];
  const lab = (m, k) => m[k] || k || '-';

  // ---------------------------------------------------------------- index
  const byNo = new Map(); D.files.forEach(f => byNo.set(f.n, f));
  const push = (m, k, v) => { if (!m.has(k)) m.set(k, []); m.get(k).push(v); };
  const outE = new Map(), inE = new Map();
  D.edges.forEach(e => { if (e.s !== e.d) { push(outE, e.s, e); push(inE, e.d, e); } });
  const extBy = new Map(); D.ext.forEach(x => push(extBy, x.s, x));
  const norm = p => String(p || '').replace(/^(target|cab#\d+)\s+/, '').replace(/^[\\/]+/, '');
  const byPath = new Map(); D.files.forEach(f => byPath.set(norm(f.p).toLowerCase(), f));
  const findBy = new Map(); D.findings.forEach(x => push(findBy, norm(x.file).toLowerCase(), x));
  const fileOfFinding = x => byPath.get(norm(x.file).toLowerCase());
  const roles = f => (f.r || 'unclassified').split(',').filter(Boolean);
  const name = f => { const p = f.p.split(/[\\/]/); return p[p.length - 1]; };
  const dir = f => { const p = f.p.split(/[\\/]/); p.pop(); return p.join('/') || '(top)'; };
  const fmtBytes = b => b < 1024 ? b + ' B' : b < 1048576 ? (b / 1024).toFixed(1) + ' KB' : (b / 1048576).toFixed(1) + ' MB';
  const isStrong = e => STRONG.has(e.t) && (e.v === 'fact' || e.v === 'match');

  // ---------------------------------------------------------------- state
  const DEF_TYPES = Object.keys(TYPE).filter(t => HEURISTIC.indexOf(t) < 0);
  const state = {
    tab: 'overview', sel: null, mode: 'entry',
    f: { q: '', roles: new Set(), langs: new Set(), origins: new Set(), depths: new Set(), types: new Set(DEF_TYPES), ev: new Set(['fact', 'match', 'candidate']) },
    actions: new Set(['actionable'])
  };
  const store = {
    load() { try { return JSON.parse(localStorage.getItem('folderscan-map') || '{}'); } catch (e) { return {}; } },
    save() { try { localStorage.setItem('folderscan-map', JSON.stringify({ tab: state.tab, filter: !$('#filter').classList.contains('closed') })); } catch (e) { } }
  };

  const fileVisible = f => {
    const F = state.f;
    if (F.q && f.p.toLowerCase().indexOf(F.q) < 0) return false;
    if (F.roles.size && !roles(f).some(r => F.roles.has(r))) return false;
    if (F.langs.size && !F.langs.has(f.l || '-')) return false;
    if (F.origins.size && !F.origins.has(f.o)) return false;
    if (F.depths.size && !F.depths.has(f.dp)) return false;
    return true;
  };
  const edgeVisible = e => state.f.types.has(e.t) && state.f.ev.has(e.v) && fileVisible(byNo.get(e.s)) && fileVisible(byNo.get(e.d));
  const filterActive = () => {
    const F = state.f;
    return !!(F.q || F.roles.size || F.langs.size || F.origins.size || F.depths.size || F.ev.size !== 3 || !F.ev.has('candidate')
      || F.types.size !== DEF_TYPES.length || DEF_TYPES.some(t => !F.types.has(t)));
  };

  // ---------------------------------------------------------------- feedback
  let toastTimer = 0;
  const toast = msg => { const t = $('#toast'); t.textContent = msg; t.classList.add('show'); clearTimeout(toastTimer); toastTimer = setTimeout(() => t.classList.remove('show'), 1600); };
  const flash = node => { if (!node) return; node.classList.remove('flash'); void node.offsetWidth; node.classList.add('flash'); };

  // ---------------------------------------------------------------- panels / tabs
  const openPanel = (id, open) => {
    const p = $('#' + id); const on = open == null ? p.classList.contains('closed') : open;
    p.classList.toggle('closed', !on);
    const b = $('#btn-' + id); if (b) b.classList.toggle('on', on);
    store.save();
    if (state.tab === 'graph') setTimeout(fit, 200);
  };
  const showTab = name => {
    state.tab = name;
    $$('#tabs button').forEach(b => b.classList.toggle('active', b.dataset.tab === name));
    $$('.view').forEach(v => v.classList.toggle('active', v.id === 'view-' + name));
    render();
    store.save();
  };
  const render = () => {
    const n = D.files.filter(fileVisible).length;
    $('#visible-count').textContent = '表示 ' + n + ' / ' + D.files.length + ' ファイル';
    $('#filter-badge').classList.toggle('show', filterActive());
    ({ overview: renderOverview, graph: renderGraph, files: renderFiles, config: renderConfig, findings: renderFindings, cleanup: renderCleanup })[state.tab]();
  };

  // ---------------------------------------------------------------- filter panel
  const countBy = (list, keyFn) => { const m = new Map(); list.forEach(x => [].concat(keyFn(x)).forEach(k => m.set(k, (m.get(k) || 0) + 1))); return m; };
  const GROUPS = [
    { key: 'roles', title: '役割', counts: () => countBy(D.files, roles), label: k => lab(ROLE, k), open: true },
    { key: 'langs', title: '言語', counts: () => countBy(D.files, f => f.l || '-'), label: k => k === '-' ? '(判定なし)' : k },
    { key: 'origins', title: '出どころ', counts: () => countBy(D.files, f => f.o), label: k => lab(ORIGIN, k) },
    { key: 'depths', title: '読めた深さ', counts: () => countBy(D.files, f => f.dp), label: k => lab(DEPTH, k) },
    { key: 'types', title: '関係の種類（構成図・詳細）', counts: () => countBy(D.edges, e => e.t), label: k => lab(TYPE, k), swatch: k => TYPE_COLOR[k] },
    { key: 'ev', title: '証拠の強さ（構成図・詳細）', counts: () => countBy(D.edges, e => e.v), label: k => lab(EV, k) }
  ];
  const renderFilter = () => {
    const host = $('#filter-groups'); host.innerHTML = '';
    GROUPS.forEach(g => {
      const counts = g.counts(); const set = state.f[g.key];
      const det = document.createElement('details'); det.className = 'group'; det.open = !!g.open || set.size > 0 && g.key !== 'types' && g.key !== 'ev';
      det.innerHTML = '<summary>' + esc(g.title) + '<em>' + (g.key === 'types' || g.key === 'ev' ? set.size + ' 種類' : set.size ? set.size + ' 件選択' : 'すべて') + '</em></summary>';
      const chips = document.createElement('div'); chips.className = 'chips';
      Array.from(counts.keys()).sort((a, b) => counts.get(b) - counts.get(a)).forEach(k => {
        const b = document.createElement('button'); b.className = 'chip' + (set.has(k) ? ' on' : '');
        b.innerHTML = (g.swatch ? '<span class="swatch" style="background:' + g.swatch(k) + '"></span>' : '') + esc(g.label(k)) + ' <b>' + counts.get(k) + '</b>';
        b.onclick = () => { set.has(k) ? set.delete(k) : set.add(k); renderFilter(); render(); toast($('#visible-count').textContent); };
        chips.appendChild(b);
      });
      det.appendChild(chips); host.appendChild(det);
    });
  };
  const resetFilter = () => {
    const F = state.f; F.q = ''; $('#q').value = '';
    ['roles', 'langs', 'origins', 'depths'].forEach(k => F[k].clear());
    F.types = new Set(DEF_TYPES); F.ev = new Set(['fact', 'match', 'candidate']);
    renderFilter(); render(); toast('絞り込みを解除しました');
  };

  // ---------------------------------------------------------------- helpers
  const fileLink = (n, text) => { const f = byNo.get(n); return f ? '<span class="flink" data-n="' + n + '" title="' + esc(f.p) + '">' + esc(text || f.p) + '</span>' : esc(text || ''); };
  const roleChips = f => roles(f).map(r => '<span class="pill' + (r === 'unclassified' ? ' warn' : '') + '">' + esc(lab(ROLE, r)) + '</span>').join('');
  const evPill = v => '<span class="pill ' + (v === 'fact' || v === 'match' ? 'ok' : v === 'weak' ? 'warn' : '') + '">' + esc(lab(EV, v)) + '</span>';
  const users = n => { // files that need n (directly or indirectly), strong edges only
    const seen = new Set([n]), q = [n], out = [];
    while (q.length) { const v = q.shift(); (inE.get(v) || []).forEach(e => { if (isStrong(e) && !seen.has(e.s)) { seen.add(e.s); q.push(e.s); out.push(e.s); } }); }
    return out;
  };
  const tableSort = {};
  const table = (host, id, cols, rows, onRow) => {
    const st = tableSort[id] || (tableSort[id] = { key: null, asc: true });
    if (st.key) {
      const c = cols.find(x => x.key === st.key);
      rows = rows.slice().sort((a, b) => { const x = c.val(a), y = c.val(b); const r = typeof x === 'number' && typeof y === 'number' ? x - y : String(x).localeCompare(String(y), 'ja'); return st.asc ? r : -r; });
    }
    const limit = 3000;
    let h = '<div class="tablewrap"><table class="t"><thead><tr>' + cols.map(c => '<th data-k="' + c.key + '" class="' + (st.key === c.key ? 'sorted' + (st.asc ? ' asc' : '') : '') + '">' + esc(c.label) + '</th>').join('') + '</tr></thead><tbody>';
    rows.slice(0, limit).forEach((r, i) => { h += '<tr class="row' + (onRow && onRow.sel && onRow.sel(r) ? ' sel' : '') + '" data-i="' + i + '">' + cols.map(c => '<td class="' + (c.num ? 'num' : c.cls || '') + '">' + (c.html ? c.html(r) : esc(c.val(r))) + '</td>').join('') + '</tr>'; });
    h += '</tbody></table></div>';
    if (rows.length > limit) h += '<p class="muted">先頭 ' + limit + ' 件を表示（絞り込みで減らせます）</p>';
    host.innerHTML = h;
    host.querySelectorAll('th').forEach(th => th.onclick = () => { const k = th.dataset.k; if (st.key === k) st.asc = !st.asc; else { st.key = k; st.asc = !cols.find(c => c.key === k).num; } table(host, id, cols, rows, onRow); });
    if (onRow) host.querySelectorAll('tr.row').forEach(tr => tr.onclick = ev => { if (ev.target.closest('.flink')) return; onRow.click(rows[+tr.dataset.i], tr); });
  };

  // ---------------------------------------------------------------- overview
  function renderOverview() {
    const v = $('#view-overview'); const files = D.files.filter(fileVisible);
    const entries = files.filter(f => f.e);
    const act = D.findings.filter(x => x.a === 'actionable');
    const card = (num, lbl, icon, tab, attn) => '<div class="card' + (tab ? ' link' : '') + (attn ? ' attn' : '') + '"' + (tab ? ' data-tab="' + tab + '"' : '') + '><div class="num">' + num + '</div><div class="lbl"><i class="fa-solid ' + icon + '"></i>' + lbl + '</div></div>';
    const resCount = D.ext.filter(x => x.t === 'RESOURCE').length;
    let h = '<h2><i class="fa-solid fa-house"></i>概要 <small>' + esc(D.meta.target) + '</small></h2><div class="cards">'
      + card(files.length, 'ファイル', 'fa-file', 'files') + card(entries.length, '起点（起動・main）', 'fa-play', 'graph')
      + card(D.edges.filter(e => isStrong(e)).length, '確かな関係', 'fa-link', 'graph') + card(act.length, '要対応の未解決', 'fa-circle-exclamation', 'findings', act.length > 0)
      + card(resCount, 'フォルダ外の資源', 'fa-globe', 'config') + card(D.cleanup.length, '整理候補', 'fa-broom', 'cleanup') + '</div>';
    if (D.meta.omittedText || D.meta.omittedDat)
      h += '<div class="note"><i class="fa-solid fa-scissors"></i>scan.txt では本文 ' + D.meta.omittedText + ' ファイル・dat ダンプ ' + D.meta.omittedDat + ' 件を省略しています。必要なファイルは settings.ini の DUMPFILES に書いて再スキャンすると出力されます。</div>';
    h += '<div class="grid2"><div class="box"><h2><i class="fa-solid fa-play"></i>起動の流れ <small>起点から確かな関係をたどる（3 段まで）</small></h2>' + flows(entries) + '</div>';
    const imp = files.filter(f => f.imp > 0).sort((a, b) => b.imp - a.imp).slice(0, 12);
    h += '<div class="box"><h2><i class="fa-solid fa-triangle-exclamation"></i>変更の影響が大きいファイル <small>このファイルに依存しているファイルの数</small></h2>'
      + (imp.length ? '<ul class="rel">' + imp.map(f => '<li><span class="pill acc">' + f.imp + '</span> ' + fileLink(f.n) + ' ' + roleChips(f) + '</li>').join('') + '</ul>' : '<div class="empty">依存されているファイルはありません</div>') + '</div>';
    h += '<div class="box"><h2><i class="fa-solid fa-circle-exclamation"></i>要対応の未解決 <small>重要度順の上位</small></h2>'
      + (act.length ? '<ul class="rel">' + act.slice(0, 10).map(x => { const f = fileOfFinding(x); return '<li><span class="pill warn">' + x.sc + '</span> ' + clsHtml(x.cls) + ' : ' + (f ? fileLink(f.n) : esc(x.file)) + ' <span class="muted">' + esc(x.sub) + '</span></li>'; }).join('') + '</ul>' : '<div class="empty">ありません</div>') + '</div>';
    const dc = countBy(D.files, f => f.dp); const tot = D.files.length || 1;
    h += '<div class="box"><h2><i class="fa-solid fa-magnifying-glass-chart"></i>どこまで読めたか</h2><div class="bar">'
      + [['structure', '#2f5d8a'], ['generic', '#9fb4c9'], ['none', '#e0a7a0']].map(x => '<span style="width:' + (100 * (dc.get(x[0]) || 0) / tot) + '%;background:' + x[1] + '" title="' + lab(DEPTH, x[0]) + '"></span>').join('') + '</div>'
      + [['structure', '#2f5d8a'], ['generic', '#9fb4c9'], ['none', '#e0a7a0']].map(x => '<span class="pill" style="background:' + x[1] + ';color:#fff">' + lab(DEPTH, x[0]) + ' ' + (dc.get(x[0]) || 0) + '</span>').join(' ')
      + '<h2 style="margin-top:12px"><i class="fa-solid fa-eye-slash"></i>今回調べられなかったこと</h2>'
      + (D.notExamined.length ? '<ul class="rel">' + D.notExamined.map(x => '<li><b>' + esc(x.kind) + '</b>' + (x.count ? ' (' + x.count + ')' : '') + ' <span class="muted">' + esc(x.detail) + '</span><div class="why">' + esc(x.next) + '</div></li>').join('') + '</ul>' : '<div class="empty">ありません</div>') + '</div></div>';
    v.innerHTML = h;
    v.querySelectorAll('.card.link').forEach(c => c.onclick = () => showTab(c.dataset.tab));
  }
  function flows(entries) {
    if (!entries.length) return '<div class="empty">起点が見つかりません（起動スクリプトや main がない、または絞り込みで非表示）</div>';
    const seen = new Set();
    const walk = (n, depth) => {
      const list = (outE.get(n) || []).filter(e => isStrong(e) && edgeVisible(e));
      if (!list.length || depth >= 3) return '';
      const uniq = new Map(); list.forEach(e => { if (!uniq.has(e.d)) uniq.set(e.d, e); });
      return '<ul class="flow">' + Array.from(uniq.values()).map(e => {
        const again = seen.has(e.d); seen.add(e.d);
        return '<li><span class="etype" style="color:' + TYPE_COLOR[e.t] + '">' + esc(lab(TYPE, e.t)) + ' →</span>' + fileLink(e.d) + (again ? ' <span class="muted">(上と同じ)</span>' : walk(e.d, depth + 1)) + '</li>';
      }).join('') + '</ul>';
    };
    return '<ul class="flow root">' + entries.slice(0, 15).map(f => { seen.add(f.n); return '<li><i class="fa-solid fa-play" style="color:var(--main)"></i> ' + fileLink(f.n) + walk(f.n, 0) + '</li>'; }).join('') + '</ul>'
      + (entries.length > 15 ? '<p class="muted">ほか ' + (entries.length - 15) + ' 件（ファイル一覧で「起点」を確認できます）</p>' : '');
  }

  // ---------------------------------------------------------------- graph
  const G = { k: 1, x: 0, y: 0, nodes: [], pos: new Map(), edges: [] };
  const NW = 190, NH = 34, GX = 250, GY = 46, MAXN = 400;
  function scope() {
    const edges = D.edges.filter(e => e.s !== e.d && edgeVisible(e));
    const adjOut = new Map(), adjIn = new Map(); edges.forEach(e => { push(adjOut, e.s, e); push(adjIn, e.d, e); });
    let nodes = new Set(), info = '', mode = state.mode;
    if (mode === 'focus' && state.sel == null) { mode = 'entry'; info = '（ファイルが選択されていないため「起点から」で表示）'; }
    if (mode === 'entry') {
      const starts = D.files.filter(f => f.e && fileVisible(f)).map(f => f.n);
      if (!starts.length) { mode = 'all'; info = '（起点がないため「すべて」で表示）'; }
      else { const q = starts.slice(); starts.forEach(n => nodes.add(n)); while (q.length) { const v = q.shift(); (adjOut.get(v) || []).forEach(e => { if (!nodes.has(e.d)) { nodes.add(e.d); q.push(e.d); } }); } }
    }
    if (mode === 'focus') {
      nodes.add(state.sel); let front = [state.sel];
      for (let i = 0; i < 2; i++) { const nx = []; front.forEach(v => { (adjOut.get(v) || []).forEach(e => { if (!nodes.has(e.d)) { nodes.add(e.d); nx.push(e.d); } }); (adjIn.get(v) || []).forEach(e => { if (!nodes.has(e.s)) { nodes.add(e.s); nx.push(e.s); } }); }); front = nx; }
    }
    if (mode === 'all') edges.forEach(e => { nodes.add(e.s); nodes.add(e.d); });
    let list = Array.from(nodes);
    if (list.length > MAXN) {
      list.sort((a, b) => { const fa = byNo.get(a), fb = byNo.get(b); return (fb.imp + fb.in + fb.out) - (fa.imp + fa.in + fa.out); });
      list = list.slice(0, MAXN); info += '（' + nodes.size + ' 件のうち影響の大きい ' + MAXN + ' 件を表示。絞り込みで対象を減らしてください）';
      nodes = new Set(list);
    }
    return { nodes: list, edges: edges.filter(e => nodes.has(e.s) && nodes.has(e.d)), mode, info };
  }
  function layout(sc) {
    const lv = new Map(), outA = new Map(), inA = new Map();
    sc.edges.forEach(e => { push(outA, e.s, e.d); push(inA, e.d, e.s); });
    const bfs = (starts, dirMap, sign) => { const q = starts.slice(); starts.forEach(s => { if (!lv.has(s)) lv.set(s, 0); }); while (q.length) { const v = q.shift(); (dirMap.get(v) || []).forEach(w => { if (!lv.has(w)) { lv.set(w, lv.get(v) + sign); q.push(w); } }); } };
    if (sc.mode === 'focus') { lv.set(state.sel, 0); bfs([state.sel], outA, 1); const back = new Map(); const q = [state.sel]; back.set(state.sel, 0); while (q.length) { const v = q.shift(); (inA.get(v) || []).forEach(w => { if (!back.has(w)) { back.set(w, back.get(v) - 1); q.push(w); } }); } back.forEach((l, n) => { if (!lv.has(n)) lv.set(n, l); }); }
    else {
      // entries that another entry calls are placed after their caller
      let starts = sc.nodes.filter(n => byNo.get(n).e && !(inA.get(n) || []).length);
      if (sc.mode !== 'entry' || !starts.length) starts = sc.nodes.filter(n => !(inA.get(n) || []).length);
      if (!starts.length) starts = sc.nodes.filter(n => byNo.get(n).e);
      bfs(starts, outA, 1);
      sc.nodes.forEach(n => { if (!lv.has(n)) bfs([n], outA, 1); });
    }
    const min = Math.min.apply(null, Array.from(lv.values()).concat([0]));
    const layers = new Map(); sc.nodes.forEach(n => push(layers, lv.get(n) - min, n));
    const keys = Array.from(layers.keys()).sort((a, b) => a - b);
    const order = new Map();
    keys.forEach(k => { layers.get(k).sort((a, b) => byNo.get(a).p.localeCompare(byNo.get(b).p)); layers.get(k).forEach((n, i) => order.set(n, i)); });
    for (let pass = 0; pass < 3; pass++) keys.forEach(k => {
      const L = layers.get(k);
      const bary = n => { const ps = (inA.get(n) || []).concat(outA.get(n) || []).filter(m => order.has(m)); return ps.length ? ps.reduce((s, m) => s + order.get(m), 0) / ps.length : order.get(n); };
      L.sort((a, b) => bary(a) - bary(b)); L.forEach((n, i) => order.set(n, i));
    });
    const maxLen = Math.max.apply(null, keys.map(k => layers.get(k).length).concat([1]));
    G.pos = new Map();
    keys.forEach((k, ci) => { const L = layers.get(k); const off = (maxLen - L.length) * GY / 2; L.forEach((n, i) => G.pos.set(n, { x: ci * GX, y: off + i * GY })); });
  }
  function renderGraph() {
    $$('#graph-mode button').forEach(b => b.classList.toggle('on', b.dataset.mode === state.mode));
    const sc = scope(); G.nodes = sc.nodes; G.edges = sc.edges;
    $('#graph-info').textContent = sc.nodes.length + ' ファイル / ' + sc.edges.length + ' 関係 ' + sc.info;
    const svg = $('#graph');
    if (!sc.nodes.length) { svg.innerHTML = '<text x="20" y="40" fill="#6b7785">表示する関係がありません（絞り込みや表示範囲を変えてください）</text>'; renderLegend([]); return; }
    layout(sc);
    let h = '<g id="vp">';
    sc.edges.forEach((e, i) => {
      const a = G.pos.get(e.s), b = G.pos.get(e.d);
      let d;
      if (b.x > a.x) { const x1 = a.x + NW, y1 = a.y + NH / 2, x2 = b.x, y2 = b.y + NH / 2, cx = (x2 - x1) / 2; d = 'M' + x1 + ',' + y1 + ' C' + (x1 + cx) + ',' + y1 + ' ' + (x2 - cx) + ',' + y2 + ' ' + x2 + ',' + y2; }
      else { const x1 = a.x + NW / 2, y1 = a.y + NH, x2 = b.x + NW / 2, y2 = b.y + NH, dy = 40 + Math.abs(a.x - b.x) / 6; d = 'M' + x1 + ',' + y1 + ' C' + x1 + ',' + (y1 + dy) + ' ' + x2 + ',' + (y2 + dy) + ' ' + x2 + ',' + y2; }
      h += '<path class="edge' + (e.v === 'candidate' || e.v === 'weak' ? ' cand' : '') + '" data-i="' + i + '" d="' + d + '" stroke="' + (TYPE_COLOR[e.t] || '#999') + '" marker-end="url(#ar-' + e.t + ')"><title>' + esc(lab(TYPE, e.t) + ' : ' + e.x) + '</title></path>';
    });
    sc.nodes.forEach(n => {
      const f = byNo.get(n), p = G.pos.get(n); const nm = name(f), dr = dir(f);
      h += '<g class="node' + (f.e ? ' entry' : '') + (f.f ? ' has-f' : '') + '" data-n="' + n + '" transform="translate(' + p.x + ',' + p.y + ')"><rect width="' + NW + '" height="' + NH + '"></rect>'
        + '<text x="8" y="14">' + esc(nm.length > 27 ? nm.slice(0, 26) + '…' : nm) + '</text><text class="sub" x="8" y="27">' + esc((dr.length > 32 ? '…' + dr.slice(-31) : dr) + (f.imp ? '  影響 ' + f.imp : '')) + '</text><title>' + esc(f.p) + '</title></g>';
    });
    h += '</g>';
    const types = Array.from(new Set(sc.edges.map(e => e.t)));
    svg.innerHTML = '<defs>' + types.map(t => '<marker id="ar-' + t + '" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="' + (TYPE_COLOR[t] || '#999') + '"/></marker>').join('') + '</defs>' + h;
    svg.querySelectorAll('.node').forEach(g => g.addEventListener('click', ev => { ev.stopPropagation(); select(+g.dataset.n); }));
    renderLegend(types);
    fit(); highlight();
  }
  function renderLegend(types) {
    $('#legend').innerHTML = types.map(t => '<span><span class="swatch" style="background:' + TYPE_COLOR[t] + '"></span>' + esc(lab(TYPE, t)) + '</span>').join('')
      + '<span><i class="fa-regular fa-square" style="color:var(--main)"></i>太枠 = 起点</span><span><i class="fa-regular fa-square" style="color:var(--accent)"></i>橙枠 = 未解決あり</span><span>点線 = 推定</span>';
  }
  const applyView = () => { const vp = $('#vp'); if (vp) vp.setAttribute('transform', 'translate(' + G.x + ',' + G.y + ') scale(' + G.k + ')'); };
  function fit() {
    const wrap = $('#graph-wrap'); if (!G.pos.size || !wrap.clientWidth) return;
    let x0 = 1e9, y0 = 1e9, x1 = -1e9, y1 = -1e9;
    G.pos.forEach(p => { x0 = Math.min(x0, p.x); y0 = Math.min(y0, p.y); x1 = Math.max(x1, p.x + NW); y1 = Math.max(y1, p.y + NH); });
    const pad = 40, w = x1 - x0 + pad * 2, hh = y1 - y0 + pad * 2;
    G.k = Math.min(1.4, Math.min(wrap.clientWidth / w, wrap.clientHeight / hh));
    G.x = (wrap.clientWidth - (x1 - x0) * G.k) / 2 - x0 * G.k; G.y = (wrap.clientHeight - (y1 - y0) * G.k) / 2 - y0 * G.k;
    applyView();
  }
  const zoom = (f, cx, cy) => { const wrap = $('#graph-wrap'); if (cx == null) { cx = wrap.clientWidth / 2; cy = wrap.clientHeight / 2; } const k2 = Math.max(.08, Math.min(4, G.k * f)); G.x = cx - (cx - G.x) * k2 / G.k; G.y = cy - (cy - G.y) * k2 / G.k; G.k = k2; applyView(); };
  function highlight() {
    const svg = $('#graph'); const s = state.sel;
    const inScope = s != null && G.pos.has(s);
    const near = new Set(inScope ? [s] : []);
    if (inScope) G.edges.forEach(e => { if (e.s === s) near.add(e.d); if (e.d === s) near.add(e.s); });
    svg.querySelectorAll('.node').forEach(g => { const n = +g.dataset.n; g.classList.toggle('sel', n === s); g.classList.toggle('dim', inScope && !near.has(n)); });
    svg.querySelectorAll('.edge').forEach(p => { const e = G.edges[+p.dataset.i]; const on = inScope && (e.s === s || e.d === s); p.classList.toggle('hl', on); p.classList.toggle('dim', inScope && !on); });
  }
  function initGraphEvents() {
    const wrap = $('#graph-wrap'); let drag = null;
    wrap.addEventListener('mousedown', ev => { if (ev.target.closest('.node')) return; drag = { x: ev.clientX - G.x, y: ev.clientY - G.y, moved: false }; wrap.classList.add('drag'); });
    window.addEventListener('mousemove', ev => { if (!drag) return; drag.moved = true; G.x = ev.clientX - drag.x; G.y = ev.clientY - drag.y; applyView(); });
    window.addEventListener('mouseup', () => { if (drag && !drag.moved && state.sel != null) { state.sel = null; highlight(); } drag = null; wrap.classList.remove('drag'); });
    wrap.addEventListener('wheel', ev => { ev.preventDefault(); const r = wrap.getBoundingClientRect(); zoom(ev.deltaY < 0 ? 1.15 : 1 / 1.15, ev.clientX - r.left, ev.clientY - r.top); }, { passive: false });
    $('#zoom-in').onclick = () => zoom(1.25); $('#zoom-out').onclick = () => zoom(0.8); $('#zoom-fit').onclick = fit;
    $$('#graph-mode button').forEach(b => b.onclick = () => { state.mode = b.dataset.mode; renderGraph(); toast('表示範囲 : ' + b.textContent.trim()); });
  }

  // ---------------------------------------------------------------- files
  function renderFiles() {
    const v = $('#view-files');
    v.innerHTML = '<h2><i class="fa-solid fa-list"></i>ファイル一覧 <small>見出しのクリックで並べ替え、行のクリックで詳細</small></h2><div id="files-table"></div>';
    table($('#files-table'), 'files', [
      { key: 'n', label: 'No', num: 1, val: f => f.n },
      { key: 'p', label: 'パス', cls: 'path', val: f => f.p, html: f => (f.e ? '<i class="fa-solid fa-play" title="起点" style="color:var(--main)"></i> ' : '') + esc(f.p) },
      { key: 'l', label: '言語', val: f => f.l || '-' },
      { key: 'r', label: '役割', val: f => roles(f).map(r => lab(ROLE, r)).join(','), html: roleChips },
      { key: 'dp', label: '読めた深さ', val: f => lab(DEPTH, f.dp) },
      { key: 'in', label: '依存元', num: 1, val: f => f.in },
      { key: 'out', label: '依存先', num: 1, val: f => f.out },
      { key: 'imp', label: '影響', num: 1, val: f => f.imp },
      { key: 'f', label: '要対応', num: 1, val: f => f.f, html: f => f.f ? '<span class="pill warn">' + f.f + '</span>' : '' },
      { key: 'b', label: 'サイズ', num: 1, val: f => f.b, html: f => fmtBytes(f.b) },
      { key: 'm', label: '更新日時', val: f => f.m }
    ], D.files.filter(fileVisible), { click: f => select(f.n), sel: f => f.n === state.sel });
  }

  // ---------------------------------------------------------------- config / data / outside resources
  function renderConfig() {
    const v = $('#view-config');
    v.innerHTML = '<h2><i class="fa-solid fa-sliders"></i>設定ファイル <small>どのファイルから読まれているか</small></h2><div id="cfg-t"></div>'
      + '<h2><i class="fa-solid fa-database"></i>データ <small>DB・データファイル・フォルダ外の入出力</small></h2><div id="data-t"></div>'
      + '<h2><i class="fa-solid fa-globe"></i>フォルダ外の資源 <small>サーバー・共有フォルダ・絶対パス・レジストリ・環境変数・未解決の外部参照</small></h2><div id="ext-t"></div>';
    const users = l => (l || []).map(n => fileLink(n, byNo.get(n) ? name(byNo.get(n)) : n)).join(', ') || '<span class="pill warn">読まれている形跡なし</span>';
    table($('#cfg-t'), 'cfg', [
      { key: 'p', label: 'ファイル', cls: 'path', val: c => byNo.get(c.n).p, html: c => fileLink(c.n) },
      { key: 'k', label: 'キー数', num: 1, val: c => c.keys, html: c => c.keysRead ? String(c.keys) : '<span class="muted">未解析</span>' },
      { key: 'by', label: '読んでいるファイル', val: c => (c.by || []).length, html: c => users(c.by) },
      { key: 'how', label: '根拠', val: c => (c.how || []).join(','), html: c => (c.how || []).map(t => '<span class="pill">' + esc(lab(TYPE, t)) + '</span>').join('') }
    ], D.configs.filter(c => fileVisible(byNo.get(c.n))), { click: c => select(c.n) });
    table($('#data-t'), 'data', [
      { key: 'nm', label: '名前', cls: 'path', val: d => d.n ? byNo.get(d.n).p : d.name, html: d => d.n ? fileLink(d.n) : esc(d.name) + ' <span class="pill acc">フォルダ外</span>' },
      { key: 'kind', label: '種類', val: d => d.kind },
      { key: 'by', label: '読み書きするファイル', val: d => (d.by || []).length, html: d => users(d.by) }
    ], D.data.filter(d => !d.n || fileVisible(byNo.get(d.n))), { click: d => select(d.n || (d.by || [])[0]) });
    const g = new Map();
    D.ext.filter(x => fileVisible(byNo.get(x.s) || { p: '' })).forEach(x => { const k = x.cls + '|' + x.val; if (!g.has(k)) g.set(k, { cls: x.cls, val: x.val, t: x.t, files: [] }); if (g.get(k).files.indexOf(x.s) < 0) g.get(k).files.push(x.s); });
    table($('#ext-t'), 'ext', [
      { key: 'cls', label: '種類', val: x => CLS[x.cls] || x.cls, html: x => clsHtml(x.cls) },
      { key: 'val', label: '値', cls: 'path', val: x => x.val },
      { key: 'n', label: 'ファイル数', num: 1, val: x => x.files.length },
      { key: 'f', label: '使っているファイル', val: x => x.files.length, html: x => users(x.files.slice(0, 8)) + (x.files.length > 8 ? ' ほか' + (x.files.length - 8) : '') }
    ], Array.from(g.values()), { click: x => select(x.files[0]) });
  }

  // ---------------------------------------------------------------- findings
  function renderFindings() {
    const v = $('#view-findings');
    const counts = countBy(D.findings, x => x.a);
    v.innerHTML = '<h2><i class="fa-solid fa-circle-exclamation"></i>未解決 <small>今回のスキャンで確定できなかったこと。行のクリックで理由を表示</small></h2><div class="chips" id="act-chips"></div><div id="find-t"></div>';
    const chips = $('#act-chips');
    ['actionable', 'tracked', 'explained'].forEach(a => {
      const b = document.createElement('button'); b.className = 'chip' + (state.actions.has(a) ? ' on' : '');
      b.innerHTML = esc(lab(ACTION, a)) + ' <b>' + (counts.get(a) || 0) + '</b>';
      b.onclick = () => { state.actions.has(a) ? state.actions.delete(a) : state.actions.add(a); renderFindings(); };
      chips.appendChild(b);
    });
    const rows = D.findings.filter(x => state.actions.has(x.a)).filter(x => { const f = fileOfFinding(x); return !f || fileVisible(f); });
    table($('#find-t'), 'find', [
      { key: 'sc', label: '重要度', num: 1, val: x => x.sc, html: x => '<span class="pill ' + (x.a === 'actionable' ? 'warn' : '') + '">' + x.sc + '</span>' },
      { key: 'cls', label: '種類', val: x => CLS[x.cls] || x.cls, html: x => clsHtml(x.cls) },
      { key: 'file', label: 'ファイル', cls: 'path', val: x => norm(x.file), html: x => { const f = fileOfFinding(x); return f ? fileLink(f.n) : esc(norm(x.file)); } },
      { key: 'loc', label: '場所', val: x => x.loc === '-' ? '' : x.loc },
      { key: 'sub', label: '内容', cls: 'path', val: x => x.sub },
      { key: 'chg', label: '前回から', val: x => x.chg === 'persisting' ? x.seen + ' 回連続' : x.chg === 'new' ? '新規' : x.chg }
    ], rows, {
      click: (x, tr) => {
        const nx = tr.nextElementSibling;
        if (nx && nx.classList.contains('why-row')) nx.remove();
        else { const r = document.createElement('tr'); r.className = 'why-row'; r.innerHTML = '<td colspan="6" class="why">理由 : ' + esc(x.why) + '</td>'; tr.after(r); flash(r); }
        const f = fileOfFinding(x); if (f) select(f.n, { keepTab: true });
      }
    });
  }

  // ---------------------------------------------------------------- cleanup
  function renderCleanup() {
    const v = $('#view-cleanup');
    v.innerHTML = '<h2><i class="fa-solid fa-broom"></i>整理候補 <small>使われていない・古い・重複しているファイル。削除する前に中身を確認してください</small></h2><div id="clean-t"></div>';
    table($('#clean-t'), 'clean', [
      { key: 'p', label: 'ファイル', cls: 'path', val: c => byNo.get(c.n).p, html: c => fileLink(c.n) },
      { key: 'why', label: '理由', val: c => c.why.join(' / '), html: c => c.why.map(w => '<span class="pill acc">' + esc(w) + '</span>').join('') },
      { key: 'b', label: 'サイズ', num: 1, val: c => byNo.get(c.n).b, html: c => fmtBytes(byNo.get(c.n).b) },
      { key: 'm', label: '更新日時', val: c => byNo.get(c.n).m },
      { key: 'rel', label: '関係数', num: 1, val: c => byNo.get(c.n).in + byNo.get(c.n).out }
    ], D.cleanup.filter(c => fileVisible(byNo.get(c.n))), { click: c => select(c.n) });
  }

  // ---------------------------------------------------------------- detail
  function select(n, opt) {
    if (n == null || !byNo.has(n)) return;
    state.sel = n; openPanel('detail', true); renderDetail(n);
    if (state.tab === 'graph') { if (state.mode === 'focus') renderGraph(); else highlight(); }
    if (state.tab === 'files' && !(opt && opt.keepTab)) $$('#files-table tr.row').forEach(tr => tr.classList.toggle('sel', false)), renderFiles();
  }
  function relList(edges, side) {
    if (!edges.length) return '<div class="empty">ありません</div>';
    const g = new Map(); edges.forEach(e => push(g, e.t, e));
    return Array.from(g.keys()).map(t => '<div><span class="etype" style="color:' + TYPE_COLOR[t] + '">■ ' + esc(lab(TYPE, t)) + '</span><ul class="rel">'
      + g.get(t).map(e => '<li>' + fileLink(side === 'out' ? e.d : e.s) + ' ' + evPill(e.v) + '<div class="why">' + esc(e.x) + (e.c ? ' @' + esc(e.c) : '') + '</div></li>').join('') + '</ul></div>').join('');
  }
  function renderDetail(n) {
    const f = byNo.get(n); const b = $('#detail-body');
    const vis = e => state.f.types.has(e.t) && state.f.ev.has(e.v);
    const outs = (outE.get(n) || []).filter(vis), ins = (inE.get(n) || []).filter(vis);
    const us = users(n); const ext = extBy.get(n) || []; const fs = findBy.get(norm(f.p).toLowerCase()) || [];
    const sec = (title, icon, count, body, open) => '<details class="sec"' + (open ? ' open' : '') + '><summary><i class="fa-solid ' + icon + '"></i>' + title + '<em>' + count + '</em></summary>' + body + '</details>';
    b.innerHTML = '<div class="d-title">' + esc(f.p) + '</div>'
      + '<div class="d-meta">' + esc(f.src) + ' / ' + esc(f.l || '言語判定なし') + ' / ' + esc(lab(DEPTH, f.dp)) + ' / ' + fmtBytes(f.b) + ' / ' + esc(f.m) + '</div>'
      + '<div>' + roleChips(f) + (f.e ? '<span class="pill ok">起点</span>' : '') + '<span class="pill">' + esc(lab(ORIGIN, f.o)) + '</span></div>'
      + '<div class="d-actions"><button class="btn" id="d-focus"><i class="fa-solid fa-crosshairs"></i>構成図で周辺を見る</button><button class="btn" id="d-copy"><i class="fa-regular fa-copy"></i>パスをコピー</button></div>'
      + sec('変更したときの影響範囲', 'fa-triangle-exclamation', us.length + ' ファイル',
        us.length ? '<div class="why">このファイルに直接・間接に依存しているファイル（確かな関係のみ）</div><ul class="rel">' + us.slice(0, 100).map(m => '<li>' + fileLink(m) + '</li>').join('') + '</ul>' + (us.length > 100 ? '<div class="muted">ほか ' + (us.length - 100) + '</div>' : '') : '<div class="empty">依存しているファイルはありません</div>', true)
      + sec('依存先（このファイルが使うもの）', 'fa-arrow-right', outs.length, relList(outs, 'out'), true)
      + sec('依存元（このファイルを使うもの）', 'fa-arrow-left', ins.length, relList(ins, 'in'), true)
      + sec('フォルダ外の資源・未解決の参照', 'fa-globe', ext.length, ext.length ? '<ul class="rel">' + ext.map(x => '<li><span class="pill">' + clsHtml(x.cls || x.t) + '</span> ' + esc(x.val) + '</li>').join('') + '</ul>' : '<div class="empty">ありません</div>', ext.length > 0 && ext.length <= 8)
      + sec('未解決', 'fa-circle-exclamation', fs.length, fs.length ? '<ul class="rel">' + fs.map(x => '<li><span class="pill ' + (x.a === 'actionable' ? 'warn' : '') + '">' + x.sc + ' ' + esc(lab(ACTION, x.a)) + '</span> ' + clsHtml(x.cls) + ' ' + esc(x.loc === '-' ? '' : x.loc) + '<div class="why">' + esc(x.sub) + ' / ' + esc(x.why) + '</div></li>').join('') + '</ul>' : '<div class="empty">ありません</div>', fs.length > 0);
    $('#d-focus').onclick = () => { state.mode = 'focus'; showTab('graph'); };
    $('#d-copy').onclick = () => { const t = D.meta.target.replace(/[\\/]+$/, '') + '\\' + f.p.replace(/\//g, '\\'); (navigator.clipboard ? navigator.clipboard.writeText(t) : Promise.reject()).then(() => toast('コピーしました : ' + t), () => toast(t)); };
    flash(b);
  }

  // ---------------------------------------------------------------- events
  function init() {
    $('#t-target').textContent = D.meta.target;
    $('#t-run').textContent = D.meta.run + ' / ' + D.meta.tool;
    $('#badge-findings').textContent = D.meta.actionable || '';
    $('#badge-cleanup').textContent = D.cleanup.length || '';
    $$('#tabs button').forEach(b => b.onclick = () => showTab(b.dataset.tab));
    $('#btn-filter').onclick = () => openPanel('filter');
    $('#btn-detail').onclick = () => openPanel('detail');
    $('#btn-help').onclick = () => $('#help').classList.remove('hidden');
    $('#btn-filter-reset').onclick = resetFilter;
    $$('[data-close]').forEach(b => b.onclick = () => { const id = b.dataset.close; if (id === 'help') $('#help').classList.add('hidden'); else openPanel(id, false); });
    $('#help').onclick = ev => { if (ev.target.id === 'help') $('#help').classList.add('hidden'); };
    let qt = 0;
    $('#q').addEventListener('input', ev => { clearTimeout(qt); qt = setTimeout(() => { state.f.q = ev.target.value.trim().toLowerCase(); render(); toast($('#visible-count').textContent); }, 200); });
    $('#q').addEventListener('focus', ev => ev.target.select());
    document.addEventListener('click', ev => { const l = ev.target.closest('.flink'); if (l) { ev.preventDefault(); select(+l.dataset.n); } });
    document.addEventListener('keydown', ev => {
      const typing = /INPUT|TEXTAREA/.test(document.activeElement.tagName);
      if (ev.key === 'Escape') { if (!$('#help').classList.contains('hidden')) $('#help').classList.add('hidden'); else if (typing) document.activeElement.blur(); else if (!$('#detail').classList.contains('closed')) openPanel('detail', false); else openPanel('filter', false); return; }
      if (typing) return;
      const tabs = ['overview', 'graph', 'files', 'config', 'findings', 'cleanup'];
      if (ev.key >= '1' && ev.key <= '6') showTab(tabs[+ev.key - 1]);
      else if (ev.key === 'f' || ev.key === 'F') openPanel('filter');
      else if (ev.key === 'd' || ev.key === 'D') openPanel('detail');
      else if (ev.key === '/') { ev.preventDefault(); openPanel('filter', true); $('#q').focus(); }
      else if (ev.key === '?') $('#help').classList.remove('hidden');
      else if (state.tab === 'graph' && (ev.key === '+' || ev.key === ';')) zoom(1.25);
      else if (state.tab === 'graph' && ev.key === '-') zoom(0.8);
      else if (state.tab === 'graph' && ev.key === '0') fit();
    });
    window.addEventListener('resize', () => { if (state.tab === 'graph') fit(); });
    initGraphEvents();
    renderFilter();
    const saved = store.load();
    if (saved.filter) openPanel('filter', true);
    $('#detail-body').innerHTML = '<div class="empty">ファイルをクリックすると、ここに依存先・依存元・影響範囲が表示されます。</div>';
    showTab(saved.tab && document.getElementById('view-' + saved.tab) ? saved.tab : 'overview');
  }
  init();
})();
