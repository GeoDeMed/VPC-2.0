# Construit l'application connectée (vpc-app/index.html) à partir de la page du canevas.
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

src, dst = sys.argv[1], sys.argv[2]
s = open(src, encoding='utf-8').read()


def rep(a, b):
    global s
    assert s.count(a) == 1, a[:100]
    s = s.replace(a, b)


# --- Script de l'éditeur : démarré par l'application une fois le canevas chargé ---
rep("<script>\n(function(){\n  const W = 1200", "<script>\nwindow.__VPC_START__ = function(){\n  const W = 1200")
i = s.rindex("})();\n</script>")
s = s[:i] + "};\n</script>" + s[i + len("})();\n</script>"):]
rep("""  const HOSTED = (()=>{ try { return window.top === window.self; } catch(e){ return false; } })();
  if (HOSTED) document.documentElement.classList.add('is-hosted');""",
    "  document.documentElement.classList.add('is-hosted');")
rep("""  const hash = (location.hash||'').match(/^#c=(.+)$/);
  if (hash){ try { const s = decodeShare(hash[1]); if (s){ state = normalize(s); readOnly = true; } } catch(e){} }
  if (!readOnly){ try { const s = JSON.parse(localStorage.getItem(KEY)||'null'); if (s) state = normalize(s); } catch(e){} }""",
    "  state = normalize(window.__VPC_INIT__.data || {}); readOnly = window.__VPC_INIT__.role === 'view';")
rep("""  const save = ()=>{ if (readOnly) return; try { localStorage.setItem(KEY, JSON.stringify(state)); } catch(e){} };""",
    "  const save = ()=>{ if (readOnly) return; window.__VPC_SAVE__(state); };")
rep("const who = [state.equipe, state.organisation].filter(Boolean).join(' · ');",
    "const who = window.__VPC_INIT__.owner || '';")
i = s.index("  document.getElementById('b-share').addEventListener('click', ()=>{")
j = s.index("  });\n", i) + len("  });\n")
s = s[:i] + s[j:]
i = s.index("  document.getElementById('b-fork').addEventListener('click', ()=>{")
j = s.index("  });\n", i) + len("  });\n")
s = s[:i] + "  document.getElementById('b-fork').addEventListener('click', ()=>window.__VPC_COPY__());\n" + s[j:]

# --- HTML de l'éditeur ---
rep('<script src="https://cdnjs.cloudflare.com/ajax/libs/lz-string/1.5.0/lz-string.min.js"></script>\n', '')
# --- Icône de l'onglet : le point saumon de mindcrakle. ---
rep('<title>Canevas de proposition de valeur</title>', '<title>Canevas de proposition de valeur</title>\n'
    '<link rel="icon" href="img/favicon.ico" sizes="48x48">\n'
    '<link rel="icon" href="img/favicon.svg" type="image/svg+xml">\n'
    '<link rel="apple-touch-icon" href="img/apple-touch-icon.png">\n'
    '<link rel="manifest" href="img/site.webmanifest">')
rep('      <button class="btn ghostb hosted-only" id="b-share" type="button">Copier le lien de partage</button>\n', '')
rep('<button class="btn primary" id="b-fork" type="button">Modifier une copie</button>',
    '<button class="btn primary" id="b-fork" type="button">Dupliquer dans mes canevas</button>')
# Nom du canevas : modifiable directement dans le titre de la page.
rep('    <p class="eyebrow">Module II · Design Thinking</p>\n    <h1>Canevas de proposition de valeur<span class="beta" title="Version bêta">BETA</span></h1>',
    '    <p class="eyebrow">Canevas de proposition de valeur<span class="beta" title="Version bêta">BETA</span></p>\n'
    '    <h1 class="doc-title"><input id="f-nom" data-meta="nom" placeholder="Nom du canevas" aria-label="Nom du canevas" maxlength="120" autocomplete="off" spellcheck="false"></h1>')
rep('<p class="lede">Commencez par le profil client, en haut.<sup>2</sup> Posez une pastille numérotée par idée, puis rédigez-la dans la vue éclatée, sous le schéma. Votre canevas est enregistré dans ce navigateur.</p>',
    '<p class="lede">Commencez par le profil client, en haut.<sup>2</sup> Posez une pastille numérotée par idée, puis rédigez-la dans la vue éclatée, sous le schéma. Votre canevas est enregistré automatiquement.</p>')
rep('    <p class="status framed-only">L\'export PDF, l\'export Notion et le lien de partage s\'activent sur la version hébergée de cette page.</p>\n', '')
i = s.index('      <li><span class="ui">Copier le lien de partage</span>')
s = s[:i] + s[s.index('</li>\n', i) + len('</li>\n'):]
rep('<div class="wrap" lang="fr">', open(HERE + '/parts/views.html', encoding='utf-8').read().rstrip('\n'))

# --- Crédit exigé par Strategyzer sous chaque canevas (strategyzer.com/legal/usage-of-our-tools) ---
i = s.index('    <p class="legend">')
s = s[:i] + '    <p class="legend credit">Value Proposition Canvas : <a href="https://www.strategyzer.com" target="_blank" rel="noopener">Strategyzer.com</a> et Strategyzer AG.</p>\n' + s[i:]

# --- Police : Inter (licence SIL OFL), hébergée avec l'application pour un rendu identique partout ---
rep('  --sans:-apple-system,"SF Pro Text","SF Pro",system-ui,"Helvetica Neue",Helvetica,Arial,sans-serif;',
    '  --sans:"Inter VPC",-apple-system,BlinkMacSystemFont,"Helvetica Neue",Helvetica,Arial,sans-serif;')
rep('  --display:-apple-system,"SF Pro Display","SF Pro",system-ui,"Helvetica Neue",Helvetica,Arial,sans-serif;',
    '  --display:"Inter VPC",-apple-system,BlinkMacSystemFont,"Helvetica Neue",Helvetica,Arial,sans-serif;')
FONTS = """@font-face{font-family:"Inter VPC";font-style:normal;font-display:swap;font-weight:100 900;src:url(fonts/inter-latin-ext-wght-normal.woff2) format("woff2");
  unicode-range:U+0100-02BA,U+02BD-02C5,U+02C7-02CC,U+02CE-02D7,U+02DD-02FF,U+0304,U+0308,U+0329,U+1D00-1DBF,U+1E00-1E9F,U+1EF2-1EFF,U+2020,U+20A0-20AB,U+20AD-20C0,U+2113,U+2C60-2C7F,U+A720-A7FF}
@font-face{font-family:"Inter VPC";font-style:normal;font-display:swap;font-weight:100 900;src:url(fonts/inter-latin-wght-normal.woff2) format("woff2");
  unicode-range:U+0000-00FF,U+0131,U+0152-0153,U+02BB-02BC,U+02C6,U+02DA,U+02DC,U+0304,U+0308,U+0329,U+2000-206F,U+20AC,U+2122,U+2191,U+2193,U+2212,U+2215,U+FEFF,U+FFFD}
"""
i = s.index('<style>') + len('<style>')
s = s[:i] + '\n' + FONTS + s[i:]

# --- Styles propres à l'application ---
# Collaboration : lire l'état courant et appliquer un état fusionné sans recharger la page.
rep("""  render();

  // ---------- Partage et export ----------""", """  render();
  window.__VPC_STATE__ = ()=>JSON.parse(JSON.stringify(state));
  // Les pastilles glissent avec inertie vers leur nouvelle place ; les nouvelles apparaissent, les supprimées s'effacent.
  window.__VPC_APPLY__ = s=>{
    const before = new Map([...layer.querySelectorAll('.note')].map(el=>[el.dataset.id, el]));
    state = normalize(s);
    document.querySelectorAll('[data-meta]').forEach(el=>{ if (el !== document.activeElement) el.value = state[el.dataset.meta]; });
    render();
    if (matchMedia('(prefers-reduced-motion: reduce)').matches) return;
    layer.querySelectorAll('.note').forEach(el=>{
      const old = before.get(el.dataset.id); before.delete(el.dataset.id);
      if (!old){ el.classList.add('arrive'); setTimeout(()=>el.classList.remove('arrive'), 700); return; }
      if (old.style.left === el.style.left && old.style.top === el.style.top) return;
      const to = [el.style.left, el.style.top];
      el.style.left = old.style.left; el.style.top = old.style.top; void el.offsetWidth;
      el.classList.add('glide'); el.style.left = to[0]; el.style.top = to[1];
      setTimeout(()=>el.classList.remove('glide'), 1000);
    });
    before.forEach(old=>{ old.classList.add('leave'); old.tabIndex = -1; layer.appendChild(old); setTimeout(()=>old.remove(), 500); });
  };

  // ---------- Partage et export ----------""")

rep('</style>', '''
/* Application */
.topbar{position:sticky;top:env(safe-area-inset-top,0px);z-index:20;display:flex;flex-wrap:wrap;align-items:center;gap:10px 16px;
  max-width:1100px;margin:-16px auto 24px;padding-block:10px;background:var(--page);border-bottom:1px solid var(--rule)}
.topbar .brand{font-weight:600;color:var(--ink);text-decoration:none;margin-right:auto}
.topbar .who{font-size:13px;color:var(--muted)}
.topbar .saved{font-size:12px;color:var(--muted)}
a.btn{text-decoration:none;display:inline-block}
.app-view{max-width:1100px;margin:0 auto;display:grid;gap:20px}
.login-card{max-width:520px;margin:10vh auto 0;display:grid;gap:16px}
.list-head{display:flex;flex-wrap:wrap;gap:12px;align-items:end;justify-content:space-between}
.clist{list-style:none;margin:0;padding:0;display:grid;gap:10px}
.clist li{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:12px;align-items:center;background:var(--box);border-radius:14px;padding:14px 18px}
.clist a{color:var(--ink);font-weight:600;text-decoration:none;overflow-wrap:anywhere}
.clist a:hover{color:var(--ui)}
.clist small{display:block;color:var(--muted);font-size:12px;font-weight:400}
#b-json,#b-import{display:none}
.sr{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}
.hint{font-size:13px;color:var(--muted);margin:0}
.row{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin:0}
.login-form{display:grid;gap:8px}
.login-form label{font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:var(--muted)}
.login-form label b{text-transform:none;letter-spacing:0;color:var(--ink);font-weight:600}
.login-form input,.share-list select{font:inherit;font-size:16px;color:var(--ink);background:var(--page);
  border:1px solid var(--rule);border-radius:10px;padding:8px 12px;min-width:0}
.login-form input:focus,.share-list select:focus{border-color:var(--ui);outline:none}
.login-form .row input{flex:1 1 220px}
#l-code{letter-spacing:.3em;font-variant-numeric:tabular-nums}
.shared-sec{display:grid;gap:12px;margin-top:12px}
.share-list{list-style:none;margin:0;padding:0;display:grid;gap:8px}
.share-list li{display:flex;flex-wrap:wrap;gap:8px 12px;align-items:center;justify-content:space-between;border-top:1px solid var(--rule);padding-top:8px;font-size:14px;color:var(--ink)}
.share-list li span{overflow-wrap:anywhere;min-width:0;flex:1 1 200px}
.share-list li div{display:flex;gap:8px;align-items:center}
.share-list select{font-size:14px;padding:5px 10px}
.saved .btn{margin-left:8px;font-size:12px;padding:3px 10px}
''' + open(HERE + '/parts/extra.css', encoding='utf-8').read() + '''@media print{.topbar{display:none!important}}
</style>''')

# --- Script de l'application ---
app = open(HERE + '/parts/app.js', encoding='utf-8').read()
FOOTER = '''<footer class="site-foot" id="site-foot">
  <div class="foot-in">
    <p class="foot-note" id="foot-note"></p>
    <div class="foot-bar">
      <p class="foot-copy" id="foot-copy"></p>
      <nav class="foot-links" id="foot-links" aria-label="Informations légales"></nav>
      <button class="foot-lang" id="foot-lang" type="button"></button>
    </div>
  </div>
</footer>
'''
s = s.rstrip() + '\n' + FOOTER + app

# --- Document complet (encodage déclaré) ---
i = s.index('</style>') + len('</style>')
head, body = s[:i], s[i:]
head = head.replace('<meta name="claude:viewport-fit-sides" content="cover">\n', '')
out = ('<!doctype html>\n<html lang="fr">\n<head>\n<meta charset="utf-8">\n'
       '<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">\n'
       '<meta name="referrer" content="strict-origin-when-cross-origin">\n'
       + head +
       '\n<style>:root{color-scheme:light}body{margin:0}img{max-width:100%}[hidden]{display:none!important}</style>\n'
       '</head>\n<body>' + body + '</body>\n</html>\n')
open(dst, 'w', encoding='utf-8').write(out)
