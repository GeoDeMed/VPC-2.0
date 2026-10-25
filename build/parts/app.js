
<script>
(function(){
  const $ = id=>document.getElementById(id);
  const params = new URLSearchParams(location.search);
  const cid = params.get('c'), view = params.get('v');
  async function api(a, opts){
    const o = {credentials:'same-origin', headers:{}};
    if (opts && opts.body !== undefined){ o.method='POST'; o.headers['Content-Type']='application/json'; o.headers['X-VPC']='1'; o.body=JSON.stringify(opts.body); if (opts.keepalive) o.keepalive = true; }
    const r = await fetch('api.php?a='+a+(opts && opts.qs ? '&'+opts.qs : ''), o);
    const j = await r.json().catch(()=>({}));
    if (!r.ok){ const e = new Error(j.message || j.error || ('HTTP '+r.status)); e.status = r.status; e.code = j.error; throw e; }
    return j;
  }
  const VIEWS = ['view-login','view-setup','view-rk','view-recover','view-unlock','view-account','view-legal','view-list','view-error','view-editor','view-collab'];
  const show = id=>{ VIEWS.forEach(v=>{ $(v).hidden = v!==id; }); window.scrollTo(0,0); };
  const fmt = d=>{ try { return new Date(d.replace(' ','T')+'Z').toLocaleString('fr-FR',{dateStyle:'medium',timeStyle:'short'}); } catch(e){ return d; } };
  const esc = t=>String(t).replace(/[&<>"]/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
  const errText = e=>e.status ? e.message : 'Le serveur ne répond pas. Réessayez dans un instant.';
  const norm = e=>String(e||'').trim().toLowerCase();

  // ---------- Chiffrement (Web Crypto, dans le navigateur) ----------
  // Mot de passe → PBKDF2-SHA-256 (600 000 itérations) → clé de chiffrement + clé de connexion.
  // Clé maîtresse du compte (AES-GCM) chiffrée par le mot de passe et par la clé de secours.
  // Chaque canevas a sa propre clé, transmise aux personnes invitées par échange ECDH P-256.
  const K = (()=>{
    const sub = crypto.subtle, te = new TextEncoder(), td = new TextDecoder();
    const b64 = buf=>{ const u = new Uint8Array(buf); let s = ''; for (let i=0;i<u.length;i+=0x8000) s += String.fromCharCode.apply(null, u.subarray(i,i+0x8000)); return btoa(s); };
    const unb64 = s=>Uint8Array.from(atob(s), c=>c.charCodeAt(0));
    const rand = n=>crypto.getRandomValues(new Uint8Array(n));
    const ITER = 600000;
    async function aes(raw, extractable){ return sub.importKey('raw', raw, 'AES-GCM', !!extractable, ['encrypt','decrypt']); }
    async function enc(key, bytes){ const iv = rand(12); return b64(iv)+'.'+b64(await sub.encrypt({name:'AES-GCM', iv}, key, bytes)); }
    async function dec(key, s){ const [iv, ct] = String(s).split('.'); return new Uint8Array(await sub.decrypt({name:'AES-GCM', iv: unb64(iv)}, key, unb64(ct))); }
    const encJSON = (key, v)=>enc(key, te.encode(JSON.stringify(v)));
    const decJSON = async (key, s)=>JSON.parse(td.decode(await dec(key, s)));
    async function hkdf(raw, info, usage){
      const base = await sub.importKey('raw', raw, 'HKDF', false, ['deriveKey','deriveBits']);
      const p = {name:'HKDF', hash:'SHA-256', salt:new Uint8Array(32), info: te.encode(info)};
      return usage === 'bits' ? new Uint8Array(await sub.deriveBits(p, base, 256)) : sub.deriveKey(p, base, {name:'AES-GCM', length:256}, false, ['encrypt','decrypt']);
    }
    async function fromPassword(pw, salt, iter){
      const base = await sub.importKey('raw', te.encode(pw.normalize('NFC')), 'PBKDF2', false, ['deriveBits']);
      const bits = new Uint8Array(await sub.deriveBits({name:'PBKDF2', hash:'SHA-256', salt: unb64(salt), iterations: iter}, base, 512));
      return {key: await aes(bits.slice(0,32)), auth: b64(bits.slice(32))};
    }
    // Clé de secours : 20 octets aléatoires, écrits en base 32 par groupes de 4.
    function rkText(bytes){ let bits = '', out = ''; bytes.forEach(b=>bits += b.toString(2).padStart(8,'0')); for (let i=0;i+5<=bits.length;i+=5) out += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'[parseInt(bits.slice(i,i+5),2)]; return out.match(/.{1,4}/g).join('-'); }
    function rkBytes(text){ const t = String(text).toUpperCase().replace(/0/g,'O').replace(/1/g,'I').replace(/8/g,'B').replace(/[^A-Z2-7]/g,''); if (t.length !== 32) return null; let bits = ''; for (const c of t) bits += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.indexOf(c).toString(2).padStart(5,'0'); const out = new Uint8Array(20); for (let i=0;i<20;i++) out[i] = parseInt(bits.slice(i*8,i*8+8),2); return out; }
    const rkKey = bytes=>hkdf(bytes, 'vpc-recovery');
    const checkOf = async mkRaw=>b64(await hkdf(mkRaw, 'vpc-check', 'bits'));
    async function openMaster(mkRaw, keys){
      const mk = await aes(mkRaw);
      const priv = await sub.importKey('pkcs8', await dec(mk, keys.priv_ct), {name:'ECDH', namedCurve:'P-256'}, false, ['deriveBits']);
      const email = keys.email_ct ? new TextDecoder().decode(await dec(mk, keys.email_ct)) : '';
      const name = keys.name_ct ? new TextDecoder().decode(await dec(mk, keys.name_ct)) : '';
      return {mk, priv, email, name};
    }
    // Création d'un compte : clé maîtresse, paire de clés, clé de secours.
    async function newAccount(email, pw){
      const mkRaw = rand(32), salt = b64(rand(16)), rk = rand(20);
      const pass = await fromPassword(pw, salt, ITER);
      const pair = await sub.generateKey({name:'ECDH', namedCurve:'P-256'}, true, ['deriveBits']);
      const mk = await aes(mkRaw);
      const keys = {v:1, salt, iter:ITER,
        wrap_pass: await enc(pass.key, mkRaw),
        wrap_rec: await enc(await rkKey(rk), mkRaw),
        priv_ct: await enc(mk, await sub.exportKey('pkcs8', pair.privateKey)),
        email_ct: await enc(mk, te.encode(email))};
      const pub = b64(await sub.exportKey('spki', pair.publicKey));
      return {keys, pub, auth: pass.auth, check: await checkOf(mkRaw), rk: rkText(rk), mkRaw};
    }
    // Nouveau mot de passe pour une clé maîtresse déjà ouverte.
    async function rewrap(keys, mkRaw, pw){
      const salt = b64(rand(16)), pass = await fromPassword(pw, salt, ITER);
      return {keys: Object.assign({}, keys, {salt, iter:ITER, wrap_pass: await enc(pass.key, mkRaw)}), auth: pass.auth, check: await checkOf(mkRaw)};
    }
    // Clé d'un canevas chiffrée pour une personne (échange ECDH avec une clé éphémère).
    async function wrapFor(pubB64, raw){
      const pub = await sub.importKey('spki', unb64(pubB64), {name:'ECDH', namedCurve:'P-256'}, false, []);
      const eph = await sub.generateKey({name:'ECDH', namedCurve:'P-256'}, true, ['deriveBits']);
      const shared = await sub.deriveBits({name:'ECDH', public: pub}, eph.privateKey, 256);
      return 'e:' + b64(await sub.exportKey('spki', eph.publicKey)) + ':' + await enc(await hkdf(shared, 'vpc-wrap'), raw);
    }
    async function unwrap(me, w){
      if (!w) return null;
      if (w.startsWith('m:')) return dec(me.mk, w.slice(2));
      const [, e, ct] = w.split(':');
      const pub = await sub.importKey('spki', unb64(e), {name:'ECDH', namedCurve:'P-256'}, false, []);
      const shared = await sub.deriveBits({name:'ECDH', public: pub}, me.priv, 256);
      return dec(await hkdf(shared, 'vpc-wrap'), ct);
    }
    const ownerWrap = async (me, raw)=>'m:' + await enc(me.mk, raw);
    async function canvasKey(raw){ return {raw, key: await aes(raw)}; }
    const newCanvasKey = ()=>canvasKey(rand(32));
    return {fromPassword, newAccount, rewrap, openMaster, rkBytes, rkKey, checkOf, dec, enc, encJSON, decJSON, wrapFor, unwrap, ownerWrap, canvasKey, newCanvasKey, te};
  })();

  // ---------- Clés ouvertes sur cet appareil (IndexedDB, clés non exportables) ----------
  const Vault = (()=>{
    const open = ()=>new Promise((res, rej)=>{ const r = indexedDB.open('vpc', 1); r.onupgradeneeded = ()=>r.result.createObjectStore('k'); r.onsuccess = ()=>res(r.result); r.onerror = ()=>rej(r.error); });
    async function tx(mode, fn){ const db = await open(); return new Promise((res, rej)=>{ const t = db.transaction('k', mode); const r = fn(t.objectStore('k')); t.oncomplete = ()=>res(r && r.result); t.onerror = ()=>rej(t.error); }); }
    return {
      get: uid=>tx('readonly', s=>s.get('u'+uid)).catch(()=>null),
      put: (uid, v)=>tx('readwrite', s=>s.put(v, 'u'+uid)).catch(()=>{}),
      clear: ()=>tx('readwrite', s=>s.clear()).catch(()=>{}),
    };
  })();
  let ME = null; // {uid, pub, mk, priv, email, name}
  async function remember(uid, pub, opened){ ME = Object.assign({uid, pub}, opened); await Vault.put(uid, ME); }

  const titleOf = d=>String((d && (String(d.produit||'').trim() || String(d.organisation||'').trim())) || 'Sans titre').slice(0,180);
  const pwOk = (a, b, msg)=>{ if (a.length < 10){ msg.textContent = 'Le mot de passe doit faire 10 caractères au moins.'; return false; } if (a !== b){ msg.textContent = 'Les deux mots de passe ne sont pas identiques.'; return false; } return true; };

  // ---------- Connexion ----------
  let codeEmail = '', codePurpose = '';
  try { codeEmail = sessionStorage.getItem('vpc-email') || ''; } catch(e){}
  const keepEmail = e=>{ codeEmail = e; try { sessionStorage.setItem('vpc-email', e); } catch(x){} };

  // Champ de code : un seul champ réel (collage et remplissage automatique), affiché en six cases XXX-XXX.
  function otp(input, onComplete){
    const boxes = input.parentNode.querySelectorAll('.otp-boxes span');
    const paint = ()=>{
      const v = input.value.replace(/\D/g,'').slice(0,6);
      if (input.value !== v) input.value = v;
      boxes.forEach((b, k)=>{ b.textContent = v[k] || ''; b.classList.toggle('on', document.activeElement === input && k === Math.min(v.length, 5)); });
      return v;
    };
    input.oninput = ()=>{ if (paint().length === 6 && onComplete) onComplete(); };
    input.onfocus = input.onblur = paint;
    input.reset = ()=>{ input.value = ''; paint(); };
    input.parentNode.addEventListener('click', ()=>{ if (document.activeElement !== input) input.focus(); });
    paint();
  }

  // Propose l'enregistrement de l'identifiant au gestionnaire de mots de passe quand le navigateur le permet (Chrome, Edge).
  async function storeCredential(email, password){
    try { if (window.PasswordCredential && navigator.credentials) await navigator.credentials.store(new PasswordCredential({id: email, password, name: email})); } catch(e){}
  }


  function showLogin(){
    show('view-login');
    const msg = $('login-msg'), stack = $('login-stack');
    const panel = id=>['f-login','f-email','f-code'].forEach(f=>{ $(f).hidden = f!==id; });
    api('config').then(cfg=>{ if (cfg.domain) document.querySelectorAll('.dom').forEach(el=>el.textContent = ' @'+cfg.domain); }).catch(()=>{});
    panel('f-login'); $('l-email').value = codeEmail;
    // Le champ mot de passe apparaît sous l'adresse ; il reste dans la page pour le remplissage automatique.
    const openPw = ()=>{ stack.classList.add('open'); $('l-pass').tabIndex = 0; stack.querySelectorAll('.pw .go').forEach(x=>x.tabIndex = 0); };
    const emailOk = ()=>$('l-email').checkValidity() && $('l-email').value.trim() !== '';
    $('b-email-go').onclick = ()=>{ if (!emailOk()){ $('l-email').reportValidity(); return; } openPw(); $('l-pass').focus(); };
    $('l-pass').addEventListener('input', ()=>{ if ($('l-pass').value) openPw(); });
    $('f-login').onsubmit = async ev=>{
      ev.preventDefault();
      if (!stack.classList.contains('open') || !$('l-pass').value){ $('b-email-go').click(); return; }
      const email = norm($('l-email').value), password = $('l-pass').value;
      msg.textContent = 'Connexion…';
      try {
        const pre = await api('prelogin',{body:{email}});
        const pass = await K.fromPassword(password, pre.salt, pre.iter);
        const r = await api('login',{body:{email, auth: pass.auth}});
        const mkRaw = await K.dec(pass.key, r.keys.wrap_pass);
        await remember(r.uid, r.pub, await K.openMaster(mkRaw, r.keys));
        await storeCredential(email, password);
        keepEmail(email); location.reload();
      } catch(e){ msg.textContent = e.status ? e.message : 'La connexion a échoué. Vérifiez votre mot de passe.'; }
    };
    const askCode = purpose=>{
      codePurpose = purpose; panel('f-email'); msg.textContent = '';
      $('email-intro').textContent = purpose === 'signup'
        ? 'Saisissez votre adresse e-mail. Vous recevez un code pour la valider, puis vous choisissez votre mot de passe.'
        : 'Saisissez votre adresse e-mail. Vous recevez un code pour la valider, puis vous utilisez votre clé de secours.';
      $('c-email').value = norm($('l-email').value); $('c-email').focus();
    };
    $('b-signup').onclick = ()=>askCode('signup');
    $('b-forgot').onclick = ev=>{ ev.preventDefault(); askCode('forgot'); };
    document.querySelectorAll('.b-back').forEach(b=>b.onclick = ev=>{ ev.preventDefault(); panel('f-login'); msg.textContent = ''; });
    async function send(){
      msg.textContent = 'Envoi du code…';
      try { await api('send-code',{body:{email: codeEmail}}); $('c-to').textContent = codeEmail; panel('f-code'); $('c-code').reset(); $('c-code').focus(); msg.textContent = 'Code envoyé. Il arrive en général en moins d\'une minute.'; }
      catch(e){ msg.textContent = errText(e); }
    }
    $('f-email').onsubmit = ev=>{ ev.preventDefault(); keepEmail(norm($('c-email').value)); send(); };
    $('b-resend').onclick = ev=>{ ev.preventDefault(); send(); };
    otp($('c-code'), ()=>$('f-code').requestSubmit());
    $('f-code').onsubmit = async ev=>{
      ev.preventDefault(); msg.textContent = 'Vérification…';
      try { await api('verify-code',{body:{email: codeEmail, code: $('c-code').value}}); await Vault.clear(); try { sessionStorage.setItem('vpc-step', 'code'); } catch(x){} boot(); }
      catch(e){ msg.textContent = errText(e); $('c-code').reset(); $('c-code').focus(); }
    };
    if (codeEmail){ openPw(); $('l-pass').focus(); } else $('l-email').focus();
  }

  // Premier mot de passe (mode « new ») ou nouveau départ après perte de la clé de secours (mode « reset »).
  function showSetup(me, mode){
    show('view-setup');
    const msg = $('setup-msg');
    $('setup-title').textContent = mode === 'reset' ? 'Choisissez un nouveau mot de passe' : 'Choisissez votre mot de passe';
    $('s-email').value = codeEmail; $('s-email').readOnly = !!codeEmail;
    $('f-setup').onsubmit = async ev=>{
      ev.preventDefault();
      if (!pwOk($('s-pass').value, $('s-pass2').value, msg)) return;
      const email = norm($('s-email').value);
      msg.textContent = 'Création des clés de chiffrement…';
      try {
        const acc = await K.newAccount(email, $('s-pass').value);
        await api('keys-set',{body:{mode, keys: acc.keys, pub: acc.pub, auth: acc.auth, check: acc.check}});
        try { sessionStorage.removeItem('vpc-step'); } catch(x){}
        await remember(me.uid, acc.pub, await K.openMaster(acc.mkRaw, acc.keys));
        await storeCredential(email, $('s-pass').value);
        keepEmail(email); showRecoveryKey(acc.rk);
      } catch(e){ msg.textContent = e.status ? e.message : 'La création a échoué. Réessayez.'; }
    };
  }

  function showRecoveryKey(rk){
    show('view-rk');
    $('rk-value').textContent = rk;
    $('b-rk-copy').onclick = async ()=>{ try { await navigator.clipboard.writeText(rk); $('rk-msg').textContent = 'Clé copiée.'; } catch(e){ $('rk-msg').textContent = 'Copie impossible : sélectionnez la clé et copiez-la.'; } };
    $('b-rk-dl').onclick = ()=>{
      const blob = new Blob(['Clé de secours du canevas de proposition de valeur\r\nCompte : '+codeEmail+'\r\nSite : '+location.origin+location.pathname+'\r\n\r\n'+rk+'\r\n'], {type:'text/plain;charset=utf-8'});
      const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'cle-de-secours-canevas.txt'; document.body.appendChild(a); a.click(); a.remove();
    };
    $('rk-ok').onchange = ()=>{ $('b-rk-done').disabled = !$('rk-ok').checked; };
    $('b-rk-done').onclick = ()=>{ location.href = cid ? '?c='+encodeURIComponent(cid) : './'; };
  }

  function showRecover(me){
    show('view-recover');
    const msg = $('recover-msg');
    $('r-email').value = codeEmail;
    $('f-recover').onsubmit = async ev=>{
      ev.preventDefault();
      if (!pwOk($('r-pass').value, $('r-pass2').value, msg)) return;
      const bytes = K.rkBytes($('r-key').value);
      if (!bytes){ msg.textContent = 'Cette clé de secours n\'a pas le bon format (32 caractères).'; return; }
      msg.textContent = 'Vérification de la clé…';
      try {
        const {keys} = await api('keys');
        let mkRaw;
        try { mkRaw = await K.dec(await K.rkKey(bytes), keys.wrap_rec); } catch(e){ msg.textContent = 'Cette clé de secours ne correspond pas à ce compte.'; return; }
        const nw = await K.rewrap(keys, mkRaw, $('r-pass').value);
        await api('keys-set',{body:{mode:'phrase', keys: nw.keys, pub: me.pub, auth: nw.auth, check: nw.check}});
        await remember(me.uid, me.pub, await K.openMaster(mkRaw, nw.keys));
        await storeCredential(norm($('r-email').value), $('r-pass').value);
        keepEmail(norm($('r-email').value)); location.href = './';
      } catch(e){ msg.textContent = errText(e); }
    };
    let armed = null;
    $('b-reset').onclick = ()=>{
      if (!armed){ $('b-reset').textContent = 'Confirmer : supprimer mes canevas et repartir'; armed = setTimeout(()=>{ armed = null; $('b-reset').textContent = 'Repartir avec un compte vide'; }, 5000); return; }
      clearTimeout(armed); showSetup(me, 'reset');
    };
  }

  function showUnlock(me){
    show('view-unlock');
    const msg = $('unlock-msg');
    $('u-email').value = codeEmail;
    $('f-unlock').onsubmit = async ev=>{
      ev.preventDefault(); msg.textContent = 'Déverrouillage…';
      try {
        const {keys} = await api('keys');
        const pass = await K.fromPassword($('u-pass').value, keys.salt, keys.iter);
        let mkRaw;
        try { mkRaw = await K.dec(pass.key, keys.wrap_pass); } catch(e){ msg.textContent = 'Mot de passe incorrect.'; return; }
        await remember(me.uid, me.pub, await K.openMaster(mkRaw, keys));
        boot();
      } catch(e){ msg.textContent = errText(e); }
    };
    $('b-unlock-forgot').onclick = ev=>{ ev.preventDefault(); if (me.fresh) showRecover(me); else { logout(); } };
    $('u-pass').focus();
  }

  async function logout(){ await Vault.clear(); try { await api('logout',{body:{}}); } catch(e){} try { sessionStorage.removeItem('vpc-email'); sessionStorage.removeItem('vpc-step'); } catch(e){} location.href = './'; }

  // ---------- Mon compte ----------
  // Bouton actif seulement quand il y a quelque chose à enregistrer ; coche verte une fois la demande prise en compte.
  const guard = (form, ok)=>{ const b = form.querySelector('button[type=submit]'), mark = form.querySelector('.ok-mark');
    const upd = ()=>{ b.disabled = !ok(); }; form.addEventListener('input', ()=>{ upd(); if (mark) mark.hidden = true; }); upd(); return upd; };
  const done = form=>{ const m = form.querySelector('.ok-mark'); if (m){ m.hidden = false; m.classList.remove('pop'); void m.offsetWidth; m.classList.add('pop'); } };
  function showAccount(){
    show('view-account');
    const msg = $('acc-msg');
    $('acc-email').textContent = ME.email; $('a-email').value = ME.email;
    $('acc-name').value = ME.name || '';
    const nameBtn = $('f-name').querySelector('button[type=submit]');
    const nameUpd = guard($('f-name'), ()=>{ const v = $('acc-name').value.trim(); nameBtn.textContent = (!v && ME.name) ? 'Retirer le nom' : 'Enregistrer'; return v !== (ME.name || ''); });
    $('f-name').onsubmit = async ev=>{
      ev.preventDefault();
      const name = $('acc-name').value.trim().slice(0, 80);
      nameBtn.disabled = true;
      try {
        await api('name-set',{body:{name_ct: name ? await K.enc(ME.mk, K.te.encode(name)) : ''}});
        ME.name = name; await Vault.put(ME.uid, ME); showWho();
        msg.textContent = name ? 'Nom enregistré.' : 'Nom retiré.'; nameUpd(); done($('f-name'));
      } catch(e){ msg.textContent = errText(e); nameUpd(); }
    };
    const pwUpd = guard($('f-chpass'), ()=>['a-old','a-new','a-new2'].every(id=>$(id).value.length > 0));
    otp($('d-code'));
    const delUpd = guard($('f-del'), ()=>$('d-code').value.length === 6);
    $('f-chpass').onsubmit = async ev=>{
      ev.preventDefault();
      if (!pwOk($('a-new').value, $('a-new2').value, msg)) return;
      msg.textContent = 'Vérification…';
      try {
        const {keys} = await api('keys');
        const old = await K.fromPassword($('a-old').value, keys.salt, keys.iter);
        let mkRaw;
        try { mkRaw = await K.dec(old.key, keys.wrap_pass); } catch(e){ msg.textContent = 'Le mot de passe actuel est incorrect.'; return; }
        const nw = await K.rewrap(keys, mkRaw, $('a-new').value);
        await api('keys-set',{body:{mode:'phrase', keys: nw.keys, pub: ME.pub, auth: nw.auth, check: nw.check}});
        await storeCredential(ME.email, $('a-new').value);
        $('f-chpass').reset(); $('a-email').value = ME.email; msg.textContent = 'Mot de passe changé.'; pwUpd(); done($('f-chpass'));
      } catch(e){ msg.textContent = errText(e); }
    };
    $('b-logout-all').onclick = async ()=>{ try { await api('logout-all',{body:{}}); } catch(e){} await Vault.clear(); location.href = './'; };
    $('b-del-code').onclick = async ()=>{
      msg.textContent = 'Envoi du code…';
      try { await api('send-code',{body:{email: ME.email}}); $('f-del').hidden = false; $('d-code').reset(); delUpd(); $('d-code').focus(); msg.textContent = 'Code envoyé à '+ME.email+'.'; }
      catch(e){ msg.textContent = errText(e); }
    };
    $('f-del').onsubmit = async ev=>{
      ev.preventDefault(); msg.textContent = 'Suppression…';
      try {
        await api('verify-code',{body:{email: ME.email, code: $('d-code').value}});
        await api('account-delete',{body:{}});
        await Vault.clear(); try { sessionStorage.clear(); } catch(e){}
        location.href = './';
      } catch(e){ msg.textContent = errText(e); }
    };
  }

  // ---------- Pages légales et pied de page (français, anglais) ----------
  const CONTACT = 'contact@ADRESSE-DU-SITE';
  const mail = '<a href="mailto:'+CONTACT+'">'+CONTACT+'</a>';
  const LEGAL = {
    fr: {
      foot: {
        copy: 'Copyright © 2023-2026 Quorelix®. Tous droits réservés.',
        links: [['mentions-legales','Mentions légales'],['confidentialite','Confidentialité'],['conditions','Conditions d’utilisation'],['code','Code source']],
        note: 'Quorelix est une marque déposée. Le Value Proposition Canvas est une création de Strategyzer AG (strategyzer.com). Notion, Apple et OVHcloud sont des marques de leurs titulaires respectifs ; leur mention n’implique aucune affiliation ni approbation. Police Inter sous licence SIL Open Font License 1.1.',
        lang: 'English', back: 'Retour',
      },
      'mentions-legales': {
        eyebrow: 'Quorelix / Informations', title: 'Mentions légales',
        sections: [
          ['01 / Édition', 'Éditeur du site.', ['NOM DE L’ÉDITEUR, particulier établi en France.', 'Contact : '+mail]],
          ['02 / Hébergement', 'Hébergeur.', ['OVH SAS — hébergement web mutualisé Pro.<br>SAS au capital de 50 000 000 €, RCS Lille Métropole 424 761 419 00045, N° TVA FR 22 424 761 419.<br>Siège social : 2 rue Kellermann, 59100 Roubaix, France.']],
          ['03 / Propriété intellectuelle', 'Marques et droits.', ['<span lang="en">QUORELIX®, the QUORELIX logo and all associated marks are protected intellectual property and remain the exclusive property of their respective rights holder. © 2023-2026 QUORELIX. All rights reserved.</span>']],
          ['04 / Sources', 'Le canevas.', ['Le Value Proposition Canvas est une création de Strategyzer AG (<a href="https://www.strategyzer.com" target="_blank" rel="noopener noreferrer">strategyzer.com</a>), protégée par le droit d’auteur. Les intitulés des zones reprennent ceux de la version française publiée par Asana.']],
          ['05 / Marques tierces', 'Aucune affiliation implicite.', ['Les noms, marques, logos, produits et services tiers mentionnés sur ce site, notamment ceux de Strategyzer, d’Asana, de Notion, d’Apple et d’OVHcloud, appartiennent à leurs titulaires respectifs. Leur mention sert uniquement à identifier les technologies et contenus concernés. Elle n’implique aucune affiliation, approbation, collaboration ou certification de la part de ces titulaires.', 'La police Inter (© The Inter Project Authors) est utilisée sous licence SIL Open Font License 1.1.']],
        ],
      },
      confidentialite: {
        eyebrow: 'Quorelix / Données personnelles', title: 'Confidentialité', lede: 'Ce que l’application conserve, ce qu’elle ne peut pas lire, et ce que l’hébergement technique peut faire.',
        sections: [
          ['01 / Portée', 'Cette application.', ['Cette politique concerne l’application « Canevas de proposition de valeur ». Le responsable du traitement est NOM DE L’ÉDITEUR. Contact : '+mail+'.']],
          ['02 / Chiffrement', 'Ce que personne d’autre que vous ne peut lire.', ['Vos canevas, leurs titres, les adresses avec lesquelles vous les partagez et une copie de votre propre adresse sont chiffrés dans votre navigateur avant d’être envoyés, avec une clé issue de votre mot de passe. Le serveur ne stocke que ce texte chiffré : l’éditeur du site ne peut pas le lire.', 'Votre mot de passe ne quitte jamais votre navigateur. Le serveur reçoit seulement une clé de connexion qui en est dérivée, et n’en garde qu’un hachage.']],
          ['03 / Serveur', 'Ce que le serveur conserve.', ['Pour chaque compte : une empreinte de l’adresse e-mail (qui permet de la reconnaître sans pouvoir la relire), votre clé publique, vos clés chiffrées, le hachage de la clé de connexion, un compteur d’essais de connexion ratés et la date de création du compte.', 'Pour chaque canevas : son contenu chiffré, ses dates de création et de modification, le nombre de personnes avec qui il est partagé et leurs droits (lecture ou modification).', 'Pour l’envoi des codes : l’empreinte de l’adresse, le code haché, l’heure d’envoi et une empreinte de votre adresse IP, effacés après 24 heures dès la visite suivante sur le site.']],
          ['04 / E-mails', 'Codes et invitations.', ['Votre adresse e-mail passe en clair par le serveur au moment d’envoyer un code ou une invitation, puis elle est oubliée. Ces e-mails partent d’une boîte de messagerie hébergée par OVHcloud. Les éventuels avis de non-distribution reçus par cette boîte peuvent contenir l’adresse concernée.']],
          ['05 / Cookies et stockage', 'Strictement nécessaires.', ['Un seul cookie, « vpc_session », sert à vous garder connecté pendant 7 jours. Il n’est lisible que par le serveur et ne circule qu’en HTTPS.', 'Votre navigateur garde aussi, sur votre appareil uniquement : vos clés déverrouillées et votre adresse jusqu’à la déconnexion, votre adresse pendant l’inscription (effacée à la fermeture de l’onglet) et votre choix de langue.', 'OVHcloud indique que son hébergement mutualisé peut déposer un cookie technique « SERVER ID » pour répartir les requêtes entre serveurs. Sa durée est inférieure à 24 heures. Ce cookie ne sert pas à la publicité ou au profilage par Quorelix.']],
          ['06 / Suivi', 'Aucun suivi ajouté.', ['Le code de l’application n’intègre ni outil d’analyse d’audience, ni publicité, ni pixel de suivi, et ne charge aucun service tiers.', 'L’hébergement peut produire des journaux techniques (adresse IP, page demandée, heure, navigateur) pour son fonctionnement et sa sécurité. OVHcloud indique que « OVHcloud Web Statistics » est activé par défaut sur l’hébergement mutualisé ; sa désactivation doit être confirmée dans le compte OVHcloud.']],
          ['07 / Bases et durées', 'Pourquoi et combien de temps.', ['Votre compte et vos canevas sont traités pour vous fournir le service que vous demandez (article 6.1.b du RGPD). Les limites d’envoi de codes et d’essais de connexion protègent le service (intérêt légitime, article 6.1.f).', 'Votre compte est conservé jusqu’à ce que vous le supprimiez. Une inscription non terminée est effacée. Les données sont hébergées en France par OVH SAS, qui agit comme hébergeur.']],
          ['08 / Vos droits', 'Exercer vos droits.', ['Vous pouvez supprimer à tout moment votre compte, vos canevas et vos accès depuis « Mon compte ». Pour toute autre demande (accès, rectification, limitation, opposition), contactez '+mail+'. Le contenu de vos canevas étant chiffré, seul vous pouvez le lire ou l’exporter. Vous pouvez aussi saisir la <a href="https://www.cnil.fr/fr/plaintes" target="_blank" rel="noopener noreferrer">CNIL</a>.']],
        ],
      },
      conditions: {
        eyebrow: 'Quorelix / Utilisation', title: 'Conditions d’utilisation', lede: 'Les règles d’utilisation du canevas de proposition de valeur.',
        sections: [
          ['01 / Objet', 'Un outil de travail.', ['Cette application permet de remplir, partager et exporter des canevas de proposition de valeur. Elle a été conçue pour un module de cours de Design Thinking. Elle est éditée à titre personnel par NOM DE L’ÉDITEUR.']],
          ['02 / Accès', 'Gratuit, avec un compte.', ['L’utilisation est gratuite. Elle demande une adresse e-mail validée par un code et un mot de passe que vous choisissez. Le service ne propose ni commande ni paiement.']],
          ['03 / Compte', 'Votre mot de passe et votre clé de secours.', ['Vos canevas sont chiffrés avec votre mot de passe. Conservez votre clé de secours : si vous perdez à la fois le mot de passe et la clé, personne, pas même l’éditeur, ne peut récupérer vos canevas.']],
          ['04 / Contenus', 'Vos canevas restent les vôtres.', ['Vous êtes propriétaire et responsable de ce que vous écrivez. N’y mettez pas de données sensibles sur des tiers. Les personnes avec qui vous partagez un canevas peuvent le lire, le modifier si vous l’autorisez, et le dupliquer dans leurs propres canevas.']],
          ['05 / Disponibilité', 'Sans garantie.', ['Le service est fourni en l’état, sans garantie de disponibilité, et peut évoluer ou s’arrêter. Exportez régulièrement vos canevas en PDF ou pour Notion.']],
          ['06 / Fin', 'Supprimer votre compte.', ['Vous pouvez supprimer votre compte à tout moment depuis « Mon compte » ; vos canevas et vos accès sont alors effacés.']],
          ['07 / Contact', 'Une question ?', ['Écrivez à '+mail+'. La gestion de vos données est décrite dans la <a href="?v=confidentialite">politique de confidentialité</a>.']],
        ],
      },
      code: {
        eyebrow: 'Quorelix / Transparence', title: 'Code source', lede: 'Chacun peut lire le code de cet outil et vérifier ce qu’il fait de vos données.',
        sections: [
          ['01 / Principe', 'Rien de caché.', ['Le code complet est publié sur GitHub, sous licence GNU GPL v3 : <a href="https://github.com/UTILISATEUR/DEPOT" target="_blank" rel="noopener noreferrer">github.com/UTILISATEUR/DEPOT</a>. Les fichiers de réglages y figurent en versions neutres, sans aucune donnée d’installation.']],
          ['02 / Télécharger', 'Le paquet complet.', ['<a class="btn primary" href="https://github.com/UTILISATEUR/DEPOT/archive/refs/heads/main.zip" target="_blank" rel="noopener noreferrer">Télécharger le code (.zip)</a>', 'Le paquet contient l’interface (index.html), l’API du serveur (api.php), le modèle de réglages, le schéma de la base, la police et les sources qui servent à construire index.html.']],
          ['03 / Vérifier', 'Comparer avec le dépôt.', ['Le fichier index.html du dépôt est celui de ce site, à trois mentions près : le nom de l’éditeur, l’adresse de contact et l’adresse du dépôt y sont remplacés par des repères neutres. Pour le vérifier, par exemple sur Mac ou Linux, enregistrez la page reçue par votre navigateur puis comparez-la au fichier du dépôt :', '<code class="cmd">curl -s '+esc(new URL('index.html', location.href).href)+' -o en-ligne.html</code>', '<code class="cmd">diff en-ligne.html index.html</code>', 'Seules les lignes qui contiennent ces trois mentions doivent différer.']],
          ['04 / Où regarder', 'Les points qui comptent.', ['Le chiffrement se fait dans index.html, dans la partie « Chiffrement (Web Crypto, dans le navigateur) ». Ce que le serveur enregistre se lit dans api.php : chaque requête vers la base y figure.']],
          ['05 / Limite', 'Ce qu’un audit ne peut pas exclure.', ['Un outil chiffré dans le navigateur fait confiance au code que le serveur lui envoie. La comparaison des empreintes permet de le vérifier à tout moment, mais pas de garantir qu’il ne changera pas plus tard.']],
        ],
      },
    },
    en: {
      foot: {
        copy: 'Copyright © 2023-2026 Quorelix®. All rights reserved.',
        links: [['mentions-legales','Legal notice'],['confidentialite','Privacy'],['conditions','Terms of use'],['code','Source code']],
        note: 'Quorelix is a registered trademark. The Value Proposition Canvas was created by Strategyzer AG (strategyzer.com). Notion, Apple, and OVHcloud are trademarks of their respective owners; their mention does not imply affiliation or endorsement. Inter typeface licensed under the SIL Open Font License 1.1.',
        lang: 'Français', back: 'Back',
      },
      'mentions-legales': {
        eyebrow: 'Quorelix / Information', title: 'Legal notice',
        sections: [
          ['01 / Publisher', 'Site publisher.', ['NOM DE L’ÉDITEUR, an individual based in France.', 'Contact: '+mail]],
          ['02 / Hosting', 'Hosting provider.', ['OVH SAS — Pro shared web hosting.<br>SAS with share capital of €50,000,000, RCS Lille Métropole 424 761 419 00045, VAT no. FR 22 424 761 419.<br>Registered office: 2 rue Kellermann, 59100 Roubaix, France.']],
          ['03 / Intellectual property', 'Marks and rights.', ['QUORELIX®, the QUORELIX logo and all associated marks are protected intellectual property and remain the exclusive property of their respective rights holder. © 2023-2026 QUORELIX. All rights reserved.']],
          ['04 / Sources', 'The canvas.', ['The Value Proposition Canvas was created by Strategyzer AG (<a href="https://www.strategyzer.com" target="_blank" rel="noopener noreferrer">strategyzer.com</a>) and is protected by copyright. Zone labels follow the French version published by Asana.']],
          ['05 / Third-party marks', 'No implied affiliation.', ['Third-party names, marks, logos, products, and services mentioned on this site—including Strategyzer, Asana, Notion, Apple, and OVHcloud—belong to their respective owners. They are named solely to identify the technologies and content concerned. Their mention does not imply affiliation, endorsement, partnership, or certification by those owners.', 'The Inter typeface (© The Inter Project Authors) is used under the SIL Open Font License 1.1.']],
        ],
      },
      confidentialite: {
        eyebrow: 'Quorelix / Personal data', title: 'Privacy', lede: 'What the application keeps, what it cannot read, and what its hosting may do.',
        sections: [
          ['01 / Scope', 'This application.', ['This policy covers the “Value Proposition Canvas” application. The data controller is NOM DE L’ÉDITEUR. Contact: '+mail+'.']],
          ['02 / Encryption', 'What no one but you can read.', ['Your canvases, their titles, the addresses you share them with, and a copy of your own address are encrypted in your browser before being sent, with a key derived from your password. The server stores only this encrypted text: the site publisher cannot read it.', 'Your password never leaves your browser. The server only receives a login key derived from it, and keeps only a hash of that key.']],
          ['03 / Server', 'What the server keeps.', ['For each account: a fingerprint of the email address (which recognizes it without being able to read it back), your public key, your encrypted keys, the hash of the login key, a failed-login counter, and the account creation date.', 'For each canvas: its encrypted content, its creation and modification dates, the number of people it is shared with, and their rights (read or edit).', 'For sending codes: the address fingerprint, the hashed code, the time sent, and a fingerprint of your IP address, deleted after 24 hours at the next visit to the site.']],
          ['04 / Email', 'Codes and invitations.', ['Your email address passes through the server in clear text when a code or invitation is sent, and is then forgotten. These emails are sent from a mailbox hosted by OVHcloud. Any non-delivery notices received by that mailbox may contain the address concerned.']],
          ['05 / Cookies and storage', 'Strictly necessary.', ['A single cookie, “vpc_session”, keeps you signed in for 7 days. Only the server can read it, and it is only sent over HTTPS.', 'Your browser also keeps, on your device only: your unlocked keys and your address until you sign out, your address during sign-up (cleared when the tab closes), and your language choice.', 'OVHcloud states that its shared hosting may set a technical “SERVER ID” cookie to route requests between servers. It lasts less than 24 hours. Quorelix does not use it for advertising or profiling.']],
          ['06 / Tracking', 'No tracking added.', ['The application code includes no audience analytics, advertising, or tracking pixel, and loads no third-party service.', 'The hosting may generate technical logs (IP address, requested page, time, browser) for its operation and security. OVHcloud states that “OVHcloud Web Statistics” is enabled by default on shared hosting; disabling it must be confirmed in the OVHcloud account.']],
          ['07 / Grounds and retention', 'Why and for how long.', ['Your account and canvases are processed to provide the service you request (Article 6(1)(b) GDPR). Limits on code requests and login attempts protect the service (legitimate interest, Article 6(1)(f)).', 'Your account is kept until you delete it. An unfinished sign-up is erased. Data is hosted in France by OVH SAS, acting as hosting provider.']],
          ['08 / Your rights', 'Exercise your rights.', ['You can delete your account, canvases, and access at any time from “Mon compte”. For any other request (access, correction, restriction, objection), contact '+mail+'. Because your canvases are encrypted, only you can read or export them. You may also contact the <a href="https://www.cnil.fr/fr/plaintes" target="_blank" rel="noopener noreferrer">French data protection authority (CNIL)</a>.']],
        ],
      },
      conditions: {
        eyebrow: 'Quorelix / Use', title: 'Terms of use', lede: 'Terms for using the value proposition canvas.',
        sections: [
          ['01 / Scope', 'A working tool.', ['This application lets you fill in, share, and export value proposition canvases. It was designed for a Design Thinking course module. It is published personally by NOM DE L’ÉDITEUR.']],
          ['02 / Access', 'Free, with an account.', ['Use is free. It requires an email address verified with a code and a password you choose. The service offers no ordering or payment.']],
          ['03 / Account', 'Your password and recovery key.', ['Your canvases are encrypted with your password. Keep your recovery key: if you lose both the password and the key, no one—not even the publisher—can recover your canvases.']],
          ['04 / Content', 'Your canvases remain yours.', ['You own and are responsible for what you write. Do not include sensitive data about other people. People you share a canvas with can read it, edit it if you allow, and duplicate it into their own canvases.']],
          ['05 / Availability', 'No guarantee.', ['The service is provided as is, with no guarantee of availability, and may change or stop. Export your canvases regularly to PDF or for Notion.']],
          ['06 / Ending', 'Deleting your account.', ['You can delete your account at any time from “Mon compte”; your canvases and access are then erased.']],
          ['07 / Contact', 'Questions?', ['Write to '+mail+'. The handling of your data is described in the <a href="?v=confidentialite">privacy policy</a>.']],
        ],
      },
      code: {
        eyebrow: 'Quorelix / Transparency', title: 'Source code', lede: 'Anyone can read this tool’s code and check what it does with your data.',
        sections: [
          ['01 / Principle', 'Nothing hidden.', ['The complete code is published on GitHub under the GNU GPL v3: <a href="https://github.com/UTILISATEUR/DEPOT" target="_blank" rel="noopener noreferrer">github.com/UTILISATEUR/DEPOT</a>. Settings files are included as neutral templates, with no installation data.']],
          ['02 / Download', 'The complete package.', ['<a class="btn primary" href="https://github.com/UTILISATEUR/DEPOT/archive/refs/heads/main.zip" target="_blank" rel="noopener noreferrer">Download the code (.zip)</a>', 'The package contains the interface (index.html), the server API (api.php), the settings template, the database schema, the typeface, and the sources used to build index.html.']],
          ['03 / Verify', 'Compare with the repository.', ['The repository’s index.html is this site’s page except for three mentions: the publisher’s name, the contact address, and the repository address are replaced with neutral placeholders. To check, for example on Mac or Linux, save the page your browser receives and compare it with the repository file:', '<code class="cmd">curl -s '+esc(new URL('index.html', location.href).href)+' -o online.html</code>', '<code class="cmd">diff online.html index.html</code>', 'Only the lines containing those three mentions should differ.']],
          ['04 / Where to look', 'What matters.', ['Encryption happens in index.html, in the section “Chiffrement (Web Crypto, dans le navigateur)”. What the server stores can be read in api.php: every database query is there.']],
          ['05 / Limit', 'What an audit cannot rule out.', ['A tool encrypted in the browser trusts the code the server sends it. Comparing fingerprints lets you check that code at any time, but cannot guarantee it will not change later.']],
        ],
      },
    },
  };
  let LANG = 'fr';
  try { LANG = localStorage.getItem('vpc-lang') || ((navigator.language||'fr').toLowerCase().startsWith('fr') ? 'fr' : 'en'); } catch(e){}
  if (!LEGAL[LANG]) LANG = 'fr';

  function renderFooter(){
    const f = LEGAL[LANG].foot;
    $('foot-copy').textContent = f.copy;
    $('foot-note').textContent = f.note;
    $('foot-links').innerHTML = f.links.map(([v, t])=>'<a href="?v='+v+'">'+esc(t)+'</a>').join('');
    const b = $('foot-lang'); b.textContent = f.lang; b.lang = LANG === 'fr' ? 'en' : 'fr';
    b.onclick = ()=>{ LANG = LANG === 'fr' ? 'en' : 'fr'; try { localStorage.setItem('vpc-lang', LANG); } catch(e){} renderFooter(); if (!$('view-legal').hidden) showLegal(view === 'donnees' ? 'confidentialite' : view); };
  }

  function showLegal(page){
    const d = LEGAL[LANG][page];
    show('view-legal');
    document.documentElement.lang = LANG;
    $('legal-body').lang = LANG;
    $('legal-body').innerHTML = '<header class="legal-hero"><p class="eyebrow">'+d.eyebrow+'</p><h1>'+d.title+'<span class="accent">.</span></h1>'+(d.lede ? '<p class="lede">'+d.lede+'</p>' : '')+'</header>'
      + d.sections.map(([eb, h, ps])=>'<section class="legal-sec"><p class="eyebrow">'+eb+'</p><div><h2>'+h+'</h2>'+ps.map(p=>p.startsWith('<div') || p.startsWith('<code') ? p : '<p>'+p+'</p>').join('')+'</div></section>').join('')
      + '<p class="legal-back"><a class="btn ghostb" href="./">'+LEGAL[LANG].foot.back+'</a></p>';
  }

  // ---------- Liste ----------
  function twoStep(b, label, confirmLabel, action){
    let armed = null;
    b.addEventListener('click', ()=>{
      if (!armed){ b.textContent = confirmLabel; armed = setTimeout(()=>{ armed = null; b.textContent = label; }, 4000); return; }
      clearTimeout(armed); armed = null; b.textContent = label; action();
    });
  }

  // Transmet la clé d'un canevas aux personnes invitées qui ont créé leur compte depuis.
  async function grantPending(id, ck, shares){
    const wraps = {};
    for (const s of shares) if (s.pending && s.pub) wraps[s.h] = await K.wrapFor(s.pub, ck.raw);
    if (!Object.keys(wraps).length) return null;
    return (await api('share-keys',{body:{id, wraps}})).shares;
  }

  async function openCanvas(c){
    const raw = await K.unwrap(ME, c.wrap);
    const ck = await K.canvasKey(raw);
    return {ck, meta: await K.decJSON(ck.key, c.meta_ct)};
  }

  async function showList(onlyShared){
    show('view-list');
    const ul = $('clist'), sl = $('slist'), msg = $('list-msg');
    if (onlyShared){
      document.querySelector('#view-list .list-head .eyebrow').textContent = 'Partagés avec moi';
      ul.hidden = true; $('b-new').hidden = true; document.querySelector('#shared-sec h2').hidden = true;
    }
    let r;
    try { r = await api('list'); } catch(e){ msg.textContent = 'Impossible de charger vos canevas.'; return; }
    ul.innerHTML = r.canvases.length ? '' : '<li><span>Vous n\'avez pas encore de canevas. Créez le premier.</span></li>';
    for (const c of r.canvases){
      const li = document.createElement('li');
      let title = 'Canevas illisible';
      try { const o = await openCanvas(c); title = o.meta.title; grantPending(c.id, o.ck, c.shares).catch(()=>{}); } catch(e){}
      const n = c.shares.length;
      li.innerHTML = '<a href="?c='+encodeURIComponent(c.id)+'">'+esc(title)+'<small>Modifié le '+esc(fmt(c.updated_at))+(n ? ' · Partagé avec '+n+(n>1?' personnes':' personne') : '')+'</small></a><button class="btn warn" type="button">Supprimer</button>';
      twoStep(li.querySelector('button'), 'Supprimer', 'Confirmer la suppression', async ()=>{
        try { await api('delete',{body:{id:c.id}}); li.remove(); msg.textContent = 'Canevas supprimé.'; } catch(e){ msg.textContent = 'La suppression a échoué.'; }
      });
      ul.appendChild(li);
    }
    $('shared-sec').hidden = !r.shared.length; sl.innerHTML = '';
    if (onlyShared && !r.shared.length) msg.textContent = 'Aucun canevas ne vous est partagé pour l\'instant.';
    // Un groupe par créateur : chaque personne qui vous partage des canevas forme un espace.
    const groups = {};
    const groupOf = owner=>{
      const k = owner || '';
      if (!groups[k]){
        const d = document.createElement('div'), h = document.createElement('h3'), u = document.createElement('ul');
        h.textContent = owner ? 'De '+owner : 'Accès en attente'; u.className = 'clist';
        d.append(h, u); groups[k] = u;
        if (owner) sl.insertBefore(d, sl.querySelector('div[data-pending]')); else { d.dataset.pending = ''; sl.appendChild(d); }
      }
      return groups[k];
    };
    for (const c of r.shared){
      const li = document.createElement('li');
      let title = '', owner = '';
      if (c.wrap){ try { const o = await openCanvas(c); title = o.meta.title; owner = o.meta.owner; } catch(e){} }
      if (title){
        li.innerHTML = '<a href="?c='+encodeURIComponent(c.id)+'">'+esc(title)+'<small>'+(c.role==='edit'?'Modification':'Lecture seule')+' · Modifié le '+esc(fmt(c.updated_at))+'</small></a>';
      } else {
        li.className = 'locked';
        li.innerHTML = '<a>Canevas partagé <span class="badge">accès en attente</span><small>Votre accès sera prêt dès que son créateur rouvrira l\'application.</small></a>';
      }
      const b = document.createElement('button'); b.className = 'btn ghostb'; b.type = 'button'; b.textContent = 'Retirer de ma liste'; li.appendChild(b);
      twoStep(b, 'Retirer de ma liste', 'Confirmer', async ()=>{
        try { await api('share-leave',{body:{id:c.id}}); const g = li.parentNode; li.remove(); if (!g.children.length) g.parentNode.remove(); if (!sl.children.length) $('shared-sec').hidden = true; msg.textContent = 'Canevas retiré de votre liste. Son créateur peut vous l\'ouvrir à nouveau.'; } catch(e){ msg.textContent = 'L\'opération a échoué.'; }
      });
      groupOf(title ? owner : '').appendChild(li);
    }
  }

  async function createCanvas(data){
    const ck = await K.newCanvasKey();
    const r = await api('create',{body:{wrap: await K.ownerWrap(ME, ck.raw), meta_ct: await K.encJSON(ck.key, {title: titleOf(data), owner: ME.email}), data_ct: await K.encJSON(ck.key, data)}});
    location.href = '?c='+encodeURIComponent(r.id);
  }

  // ---------- Éditeur ----------
  async function showEditor(id){
    let c, ck, meta, data;
    try {
      c = await api('get',{qs:'id='+encodeURIComponent(id)});
      if (!c.wrap){ show('view-error'); $('error-msg').textContent = 'Votre accès à ce canevas sera prêt dès que son créateur rouvrira l\'application.'; return; }
      ck = await K.canvasKey(await K.unwrap(ME, c.wrap));
      meta = await K.decJSON(ck.key, c.meta_ct);
      data = await K.decJSON(ck.key, c.data_ct);
    } catch(e){
      show('view-error');
      if (e.status && e.status !== 404) $('error-msg').textContent = 'Le canevas n\'a pas pu être chargé. Réessayez.';
      else if (!e.status) $('error-msg').textContent = 'Ce canevas n\'a pas pu être déchiffré.';
      return;
    }
    const saved = $('saved');
    let timer = null, pending = null, rev = c.rev, stopped = false, last = data, busy = Promise.resolve();
    const payload = async d=>({meta_ct: await K.encJSON(ck.key, {title: titleOf(d), owner: meta.owner}), data_ct: await K.encJSON(ck.key, d)});
    async function flush(keepalive){
      if (!pending || stopped) return;
      const d = pending; pending = null; clearTimeout(timer); timer = null;
      try { rev = (await api('save',{body:Object.assign({id, rev}, await payload(d)), keepalive})).rev; if (!pending) saved.textContent = 'Enregistré'; }
      catch(e){
        if (!pending) pending = d;
        if (e.status===409){
          stopped = true;
          saved.innerHTML = 'Modifié entre-temps par une autre personne. Vos dernières modifications ne sont pas enregistrées.<button class="btn primary" type="button">Recharger</button>';
          saved.querySelector('button').addEventListener('click', ()=>location.reload());
          return;
        }
        saved.textContent = e.status===401 ? 'Session expirée : rechargez la page pour vous reconnecter.' : 'Enregistrement impossible, nouvel essai…';
        if (e.status!==401) timer = setTimeout(()=>flush(false), 5000);
      }
    }
    const queue = fn=>(busy = busy.then(fn, fn));
    window.__VPC_SAVE__ = st=>{ last = pending = JSON.parse(JSON.stringify(st)); saved.textContent = 'Modifications en cours…'; clearTimeout(timer); timer = setTimeout(()=>queue(()=>flush(false)), 800); };
    window.addEventListener('pagehide', ()=>flush(true));
    document.addEventListener('visibilitychange', ()=>{ if (document.visibilityState==='hidden') flush(true); });
    window.__VPC_COPY__ = async ()=>{
      try { await createCanvas(last); }
      catch(e){ $('status').textContent = 'La duplication a échoué. Réessayez.'; }
    };
    window.__VPC_INIT__ = {data: data || {}, role: c.role, owner: meta.owner};
    show('view-editor');
    if (c.role !== 'view') saved.textContent = 'Enregistré';
    if (c.role === 'owner'){
      $('menu-collab').href = '?v=collaborateurs&c='+encodeURIComponent(id);
      grantPending(id, ck, c.shares).catch(()=>{});
    }
    window.__VPC_START__();
    if (c.role === 'edit'){
      $('banner').hidden = false;
      $('banner-text').textContent = 'Canevas de '+meta.owner+', partagé avec vous en modification. Vos changements sont enregistrés pour tous.';
    }
  }

  // ---------- Collaborateurs ----------
  async function showCollab(pre){
    show('view-collab');
    const sel = $('co-canvas'), list = $('co-list'), msg = $('co-msg'), form = $('co-form'), ta = $('co-emails');
    let r;
    try { r = await api('list'); } catch(e){ msg.textContent = 'Impossible de charger vos canevas.'; return; }
    const own = [];
    for (const c of r.canvases){ try { own.push({id: c.id, title: (await openCanvas(c)).meta.title}); } catch(e){} }
    if (!own.length){ $('co-body').hidden = true; $('co-empty').hidden = false; return; }
    sel.innerHTML = own.map(o=>'<option value="'+esc(o.id)+'">'+esc(o.title)+'</option>').join('');
    if (pre && own.some(o=>o.id===pre)) sel.value = pre;
    let cur = null, busy = Promise.resolve();
    const queue = fn=>(busy = busy.then(fn, fn));
    const splitEmails = t=>[...new Set(String(t).split(/[\s,;]+/).map(norm).filter(Boolean))];
    const upd = guard(form, ()=>!!cur && splitEmails(ta.value).length > 0);

    // Le canevas tel qu'il est sur le serveur maintenant : clé, contenu et liste de partage.
    async function fetchCanvas(id){
      const c = await api('get',{qs:'id='+encodeURIComponent(id)});
      const ck = await K.canvasKey(await K.unwrap(ME, c.wrap));
      return {c, ck};
    }
    async function render(items){
      cur.shares = items;
      list.innerHTML = items.length ? '' : '<li><span>Ce canevas n\'est encore partagé avec personne.</span></li>';
      for (const it of items){
        let label = '(adresse illisible)';
        try { label = new TextDecoder().decode(await K.dec(cur.ck.key, it.label_ct)); } catch(e){}
        it.email = label;
        const st = !it.pending ? ['st-ok','Accès actif'] : it.pub ? ['st-wait','En attente'] : ['st-sent','Invitation envoyée'];
        const li = document.createElement('li');
        li.innerHTML = '<span>'+esc(label)+'<i class="badge '+st[0]+'">'+st[1]+'</i></span><div><select aria-label="Droit de '+esc(label)+'"><option value="view">Lecture seule</option><option value="edit">Peut modifier</option></select><button class="btn warn" type="button">Retirer</button></div>';
        const s = li.querySelector('select'); s.value = it.role;
        s.addEventListener('change', ()=>queue(async ()=>{
          try { await render((await api('share-role',{body:{id: cur.id, h: it.h, role: s.value}})).shares); msg.textContent = 'Droit modifié pour '+label+'.'; }
          catch(e){ msg.textContent = errText(e); s.value = it.role; }
        }));
        twoStep(li.querySelector('button'), 'Retirer', 'Confirmer', ()=>queue(()=>removeShare(it)));
        list.appendChild(li);
      }
    }
    async function load(id){
      cur = null; upd(); msg.textContent = '';
      list.innerHTML = '<li><span>Chargement…</span></li>';
      $('co-open').href = '?c='+encodeURIComponent(id);
      $('menu-collab').href = '?v=collaborateurs&c='+encodeURIComponent(id);
      try { history.replaceState(null, '', '?v=collaborateurs&c='+encodeURIComponent(id)); } catch(e){}
      try {
        const {c, ck} = await fetchCanvas(id);
        cur = {id, ck, shares: c.shares};
        await render(c.shares);
        const g = await grantPending(id, ck, c.shares).catch(()=>null);
        if (g) await render(g);
      } catch(e){ list.innerHTML = ''; msg.textContent = 'Ce canevas n\'a pas pu être chargé. '+errText(e); }
      upd();
    }
    // Retirer quelqu'un change la clé du canevas : la personne retirée ne peut plus rien déchiffrer de nouveau.
    async function removeShare(it){
      msg.textContent = 'Retrait et rechiffrement…';
      try {
        const {c, ck} = await fetchCanvas(cur.id);
        const meta = await K.decJSON(ck.key, c.meta_ct), data = await K.decJSON(ck.key, c.data_ct);
        const nk = await K.newCanvasKey(), rest = {};
        for (const s of c.shares){
          if (s.h === it.h) continue;
          let email = ''; try { email = new TextDecoder().decode(await K.dec(ck.key, s.label_ct)); } catch(e){}
          rest[s.h] = {wrap: s.pub ? await K.wrapFor(s.pub, nk.raw) : null, label_ct: await K.enc(nk.key, K.te.encode(email))};
        }
        const r = await api('rekey',{body:{id: cur.id, rev: c.rev, remove: it.h, wrap: await K.ownerWrap(ME, nk.raw), shares: rest,
          meta_ct: await K.encJSON(nk.key, meta), data_ct: await K.encJSON(nk.key, data)}});
        cur.ck = nk; await render(r.shares); msg.textContent = it.email+' n\'a plus accès à ce canevas.';
      } catch(e){ msg.textContent = e.status===409 ? e.message+' Réessayez.' : 'Le retrait a échoué. '+errText(e); }
    }
    form.onsubmit = ev=>{
      ev.preventDefault();
      const emails = splitEmails(ta.value), role = $('co-role').value;
      if (!cur || !emails.length) return;
      const bad = emails.filter(e=>!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(e));
      if (bad.length){ msg.textContent = 'Adresse non valide : '+bad.join(', ')+'.'; return; }
      form.querySelector('button[type=submit]').disabled = true;
      queue(async ()=>{
        const ok = [], mailFail = [], errs = [];
        let shares = cur.shares;
        for (const email of emails){
          msg.textContent = 'Invitation de '+email+'…';
          try {
            const r = await api('share-add',{body:{id: cur.id, email, role, from: ME.email, label_ct: await K.enc(cur.ck.key, K.te.encode(email))}});
            shares = r.shares; (r.notified ? ok : mailFail).push(email);
          } catch(e){ errs.push(email+' : '+errText(e)); }
        }
        const g = await grantPending(cur.id, cur.ck, shares).catch(()=>null);
        await render(g || shares);
        const parts = [];
        if (ok.length) parts.push((ok.length>1 ? 'Invitations envoyées à ' : 'Invitation envoyée à ')+ok.join(', ')+'.');
        if (mailFail.length) parts.push('Accès ajouté pour '+mailFail.join(', ')+', mais l\'e-mail n\'est pas parti : envoyez le lien vous-même.');
        if (errs.length) parts.push(errs.join(' '));
        msg.textContent = parts.join(' ');
        if (!errs.length){ ta.value = ''; $('co-role').value = 'view'; done(form); }
        upd();
      });
    };
    sel.onchange = ()=>queue(()=>load(sel.value));
    $('co-copylink').onclick = async ()=>{
      if (!cur) return;
      const link = location.origin + location.pathname + '?c=' + encodeURIComponent(cur.id);
      try { await navigator.clipboard.writeText(link); msg.textContent = 'Lien copié. Il ne s\'ouvre que pour vous et les adresses de la liste.'; }
      catch(e){ msg.textContent = link; }
    };
    await queue(()=>load(sel.value));
  }

  $('b-logout').addEventListener('click', logout);
  function showWho(){ $('who').textContent = ME.name || ME.email; $('who-line').hidden = false; }
  // Menu : s'ouvre sous le bouton, se ferme au clic ailleurs ou avec Échap.
  const menu = $('menu'), menuBtn = $('b-menu');
  const setMenu = open=>{ menu.hidden = !open; menuBtn.setAttribute('aria-expanded', String(open)); };
  menuBtn.addEventListener('click', e=>{ e.stopPropagation(); setMenu(menu.hidden); if (!menu.hidden) menu.querySelector('a,button').focus(); });
  document.addEventListener('click', e=>{ if (!menu.hidden && !menu.contains(e.target)) setMenu(false); });
  document.addEventListener('keydown', e=>{ if (e.key==='Escape' && !menu.hidden){ setMenu(false); menuBtn.focus(); } });
  $('b-new').addEventListener('click', async ()=>{
    try { await createCanvas({v:4, notes:[]}); }
    catch(e){ $('list-msg').textContent = 'La création a échoué. Réessayez.'; }
  });

  async function boot(){
    renderFooter();
    const page = view === 'donnees' ? 'confidentialite' : view;
    if (LEGAL.fr[page] && page !== 'foot') return showLegal(page);
    if (!window.crypto || !crypto.subtle){ show('view-error'); $('error-msg').textContent = 'Ce navigateur ne permet pas le chiffrement. Ouvrez le site en HTTPS dans un navigateur récent.'; return; }
    let me;
    try { me = await api('me'); }
    catch(e){ if (e.status===401){ await Vault.clear(); return showLogin(); } show('view-error'); $('error-msg').textContent = 'Le serveur ne répond pas. Réessayez dans un instant.'; return; }
    // Inscription commencée dans un navigateur fermé depuis : on annule et on revient à la connexion.
    let step = ''; try { step = sessionStorage.getItem('vpc-step') || ''; } catch(e){}
    if (!me.pub){
      if (step !== 'code'){ try { await api('logout',{body:{}}); } catch(e){} return showLogin(); }
      return showSetup(me, 'new');
    }
    const v = await Vault.get(me.uid);
    if (!v || v.pub !== me.pub){
      if (me.fresh && step === 'code' && codePurpose !== 'signup') return showRecover(me);
      return showUnlock(me);
    }
    ME = v;
    $('topbar').hidden = false; showWho();
    // Nom changé depuis un autre appareil : mis à jour en arrière-plan.
    api('keys').then(async r=>{
      const name = r.keys && r.keys.name_ct ? new TextDecoder().decode(await K.dec(ME.mk, r.keys.name_ct)) : '';
      if (name !== (ME.name||'')){ ME.name = name; await Vault.put(ME.uid, ME); showWho(); }
    }).catch(()=>{});
    document.querySelectorAll('#menu a').forEach(a=>{ const v = new URLSearchParams(a.getAttribute('href').split('?')[1]||'').get('v');
      if ((v || null) === (cid && !view ? '__' : view)) a.setAttribute('aria-current', 'page'); });
    if (view === 'compte') return showAccount();
    if (view === 'collaborateurs') return showCollab(cid);
    if (view === 'partages') return showList(true);
    if (cid) showEditor(cid); else showList();
  }
  boot();
})();
</script>
