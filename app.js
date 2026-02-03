/* Daily Log PWA - Relationship/Conflict tracker
   - Offline-first PWA (IndexedDB)
   - PIN lock + Recovery Key reset
   - Incident logging + Silent tracking
   - Reports: counts, started-by %, top triggers, silent durations
*/

const $ = (q) => document.querySelector(q);
const $$ = (q) => Array.from(document.querySelectorAll(q));

const DEFAULT_TRIGGERS = [
  "Respect/Behavior",
  "Money",
  "Time/Attention",
  "Family/Relatives",
  "Kids",
  "House/Chores",
  "Phone/Social",
  "Misunderstanding",
  "Other"
];

const STARTED_BY = ["Wife", "Me", "Both", "Unknown"];
const INTENSITY = ["1","2","3","4","5"];
const WHAT = ["Argument", "Silent", "Yelling", "Crying", "Insult", "Other"];

const SETTINGS_KEYS = {
  triggers: "triggers",
  pin: "pin",
  recovery: "recovery",
  silentCurrent: "silentCurrent",
  lastQuick: "lastQuick"
};

let state = {
  unlocked: false,
  startedBy: "Wife",
  intensity: "3",
  trigger: "Misunderstanding",
  what: ["Argument"],
};

function nowTs(){ return Date.now(); }
function fmtDT(ts){
  const d = new Date(ts);
  const yyyy = d.getFullYear();
  const mm = String(d.getMonth()+1).padStart(2,'0');
  const dd = String(d.getDate()).padStart(2,'0');
  const hh = String(d.getHours()).padStart(2,'0');
  const mi = String(d.getMinutes()).padStart(2,'0');
  return `${yyyy}-${mm}-${dd} ${hh}:${mi}`;
}
function daysBetween(a,b){
  const ms = Math.max(0, b-a);
  return ms / (1000*60*60*24);
}
function toast(msg){
  const t = $("#toast");
  t.textContent = msg;
  t.hidden = false;
  clearTimeout(toast._timer);
  toast._timer = setTimeout(()=>t.hidden=true, 2200);
}

function uid(){
  return `${Date.now()}_${Math.random().toString(16).slice(2)}`;
}

/* ---------- Crypto helpers (WebCrypto) ---------- */
async function sha256(str){
  const enc = new TextEncoder().encode(str);
  const hash = await crypto.subtle.digest("SHA-256", enc);
  return btoa(String.fromCharCode(...new Uint8Array(hash)));
}
function randomKeyString(){
  // user can write this down
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes).map(b=>b.toString(16).padStart(2,'0')).join('');
}
async function deriveKeyFromPassphrase(pass, saltB64){
  const salt = Uint8Array.from(atob(saltB64), c=>c.charCodeAt(0));
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey(
    "raw",
    enc.encode(pass),
    {name:"PBKDF2"},
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    {name:"PBKDF2", salt, iterations: 150000, hash:"SHA-256"},
    baseKey,
    {name:"AES-GCM", length: 256},
    false,
    ["encrypt","decrypt"]
  );
}
async function encryptJSON(obj, passphrase){
  const salt = new Uint8Array(16);
  crypto.getRandomValues(salt);
  const saltB64 = btoa(String.fromCharCode(...salt));
  const key = await deriveKeyFromPassphrase(passphrase, saltB64);
  const iv = new Uint8Array(12);
  crypto.getRandomValues(iv);
  const ivB64 = btoa(String.fromCharCode(...iv));
  const enc = new TextEncoder().encode(JSON.stringify(obj));
  const ct = await crypto.subtle.encrypt({name:"AES-GCM", iv}, key, enc);
  const ctB64 = btoa(String.fromCharCode(...new Uint8Array(ct)));
  return { v:1, alg:"AES-GCM", kdf:"PBKDF2-SHA256", iter:150000, salt:saltB64, iv:ivB64, ct:ctB64 };
}
async function decryptJSON(payload, passphrase){
  if (!payload || payload.alg !== "AES-GCM" || payload.kdf !== "PBKDF2-SHA256") {
    throw new Error("Invalid backup format");
  }
  const key = await deriveKeyFromPassphrase(passphrase, payload.salt);
  const iv = Uint8Array.from(atob(payload.iv), c=>c.charCodeAt(0));
  const ct = Uint8Array.from(atob(payload.ct), c=>c.charCodeAt(0));
  const pt = await crypto.subtle.decrypt({name:"AES-GCM", iv}, key, ct);
  const txt = new TextDecoder().decode(pt);
  return JSON.parse(txt);
}

/* ---------- Settings ---------- */
async function getSetting(key, fallback=null){
  const row = await IDBStore.get("settings", key);
  return row ? row.value : fallback;
}
async function setSetting(key, value){
  await IDBStore.put("settings", {key, value});
}
async function ensureDefaults(){
  const triggers = await getSetting(SETTINGS_KEYS.triggers, null);
  if (!triggers) await setSetting(SETTINGS_KEYS.triggers, DEFAULT_TRIGGERS);

  const rec = await getSetting(SETTINGS_KEYS.recovery, null);
  if (!rec) await setSetting(SETTINGS_KEYS.recovery, randomKeyString());

  const silent = await getSetting(SETTINGS_KEYS.silentCurrent, null);
  if (!silent) await setSetting(SETTINGS_KEYS.silentCurrent, { active:false, startTs:null });

  // If no PIN -> unlocked
  const pin = await getSetting(SETTINGS_KEYS.pin, null);
  state.unlocked = !pin;
}

/* ---------- UI builders ---------- */
function buildChips(container, items, activeValue, onPick){
  container.innerHTML = "";
  items.forEach(v=>{
    const b = document.createElement("button");
    b.className = "chip" + (v===activeValue ? " active":"");
    b.textContent = v;
    b.onclick = () => onPick(v);
    container.appendChild(b);
  });
}
function buildMultiChips(container, items, activeList, onToggle){
  container.innerHTML = "";
  items.forEach(v=>{
    const b = document.createElement("button");
    b.className = "chip" + (activeList.includes(v) ? " active":"");
    b.textContent = v;
    b.onclick = () => onToggle(v);
    container.appendChild(b);
  });
}

function switchView(name){
  const map = {
    Home: "#viewHome",
    History: "#viewHistory",
    Reports: "#viewReports",
    Settings: "#viewSettings"
  };
  Object.entries(map).forEach(([k, sel])=>{
    $(sel).hidden = (k !== name);
  });
  $$(".navBtn").forEach(b=>{
    b.classList.toggle("active", b.dataset.nav === name);
  });
  $("#headerSub").textContent = name === "Home" ? "Private • Offline" : name;
}

async function refreshHome(){
  await refreshSilentStatus();
  await renderRecent();
}

async function refreshSilentStatus(){
  const silent = await getSetting(SETTINGS_KEYS.silentCurrent, {active:false, startTs:null});
  const el = $("#silentStatus");
  if (silent.active && silent.startTs){
    el.textContent = `Silent: ON (since ${fmtDT(silent.startTs)})`;
  } else {
    el.textContent = "Silent: OFF";
  }
}

function badge(cls, txt){
  const s = document.createElement("span");
  s.className = `badge ${cls||""}`.trim();
  s.textContent = txt;
  return s;
}

async function renderRecent(){
  const list = $("#recentList");
  const all = await IDBStore.getAll("incidents");
  all.sort((a,b)=>b.ts-a.ts);
  const items = all.slice(0,7);
  list.innerHTML = items.length ? "" : `<div class="tinyNote">No incidents yet.</div>`;
  items.forEach(it=>{
    list.appendChild(renderIncidentItem(it));
  });
}

function renderIncidentItem(it){
  const div = document.createElement("div");
  div.className = "item";

  const top = document.createElement("div");
  top.className = "itemTop";

  const left = document.createElement("div");
  const badges = document.createElement("div");
  badges.className = "badges";

  badges.appendChild(badge("info", it.startedBy));
  badges.appendChild(badge("warn", it.trigger));
  badges.appendChild(badge("", `I:${it.intensity}`));

  if (it.what?.includes("Silent") || it.silentStartTs) badges.appendChild(badge("warn","Silent"));
  if (it.silentStartTs && it.silentEndTs) {
    const d = daysBetween(it.silentStartTs, it.silentEndTs);
    badges.appendChild(badge("ok", `${d.toFixed(1)}d`));
  }

  left.appendChild(badges);

  const right = document.createElement("div");
  right.appendChild(badge("", fmtDT(it.ts)));

  top.appendChild(left);
  top.appendChild(right);

  const note = document.createElement("div");
  note.className = "itemNote";
  note.textContent = it.note || "—";

  const meta = document.createElement("div");
  meta.className = "itemMeta";
  meta.textContent = (it.what || []).join(", ");

  const actions = document.createElement("div");
  actions.className = "itemActions";

  const btnEdit = document.createElement("button");
  btnEdit.className = "smallBtn";
  btnEdit.textContent = "Edit";
  btnEdit.onclick = async ()=>{
    await openEditDialog(it.id);
  };

  const btnDelete = document.createElement("button");
  btnDelete.className = "smallBtn";
  btnDelete.textContent = "Delete";
  btnDelete.onclick = async ()=>{
    if (!confirm("Delete this item?")) return;
    await IDBStore.del("incidents", it.id);
    toast("Deleted");
    await refreshAll();
  };

  actions.appendChild(btnEdit);
  actions.appendChild(btnDelete);

  div.appendChild(top);
  div.appendChild(note);
  div.appendChild(meta);
  div.appendChild(actions);
  return div;
}

/* ---------- Incident CRUD ---------- */
async function saveIncident({startSilent=false}={}){
  const note = $("#noteInput").value.trim();
  const silent = await getSetting(SETTINGS_KEYS.silentCurrent, {active:false, startTs:null});
  const incident = {
    id: uid(),
    ts: nowTs(),
    startedBy: state.startedBy,
    intensity: state.intensity,
    trigger: state.trigger,
    what: state.what.slice(),
    note,
    silentStartTs: null,
    silentEndTs: null
  };

  if (startSilent){
    incident.silentStartTs = nowTs();
    incident.what = Array.from(new Set([...incident.what, "Silent"]));
    await setSetting(SETTINGS_KEYS.silentCurrent, {active:true, startTs: incident.silentStartTs});
  }

  await IDBStore.put("incidents", incident);
  await setSetting(SETTINGS_KEYS.lastQuick, {
    startedBy: incident.startedBy, intensity: incident.intensity, trigger: incident.trigger, what: incident.what
  });

  $("#noteInput").value = "";
  toast("Saved");
  await refreshAll();
}

async function openEditDialog(id){
  const it = await IDBStore.get("incidents", id);
  if (!it) return;

  const startedBy = prompt("Started by (Wife/Me/Both/Unknown):", it.startedBy) || it.startedBy;
  const intensity = prompt("Intensity (1-5):", it.intensity) || it.intensity;
  const trigger = prompt("Trigger:", it.trigger) || it.trigger;
  const note = prompt("Note:", it.note || "") ?? it.note;

  it.startedBy = STARTED_BY.includes(startedBy) ? startedBy : it.startedBy;
  it.intensity = INTENSITY.includes(String(intensity)) ? String(intensity) : it.intensity;
  it.trigger = trigger.trim() ? trigger.trim() : it.trigger;
  it.note = note;

  await IDBStore.put("incidents", it);
  toast("Updated");
  await refreshAll();
}

/* ---------- Silent tracking ---------- */
async function startSilent(){
  const silent = await getSetting(SETTINGS_KEYS.silentCurrent, {active:false, startTs:null});
  if (silent.active && silent.startTs){
    toast("Silent already ON");
    return;
  }
  const st = nowTs();
  await setSetting(SETTINGS_KEYS.silentCurrent, {active:true, startTs: st});
  toast("Silent started");
  await refreshAll();
}
async function endSilent(){
  const silent = await getSetting(SETTINGS_KEYS.silentCurrent, {active:false, startTs:null});
  if (!silent.active || !silent.startTs){
    toast("Silent is OFF");
    return;
  }
  const en = nowTs();
  const session = { id: uid(), startTs: silent.startTs, endTs: en };
  await IDBStore.put("silent", session);

  // Also attach to last incident if it looks like a silent-related one
  const all = await IDBStore.getAll("incidents");
  all.sort((a,b)=>b.ts-a.ts);
  const last = all[0];
  if (last && (!last.silentEndTs) && (last.silentStartTs || last.what?.includes("Silent"))){
    last.silentStartTs = last.silentStartTs || silent.startTs;
    last.silentEndTs = en;
    await IDBStore.put("incidents", last);
  }

  await setSetting(SETTINGS_KEYS.silentCurrent, {active:false, startTs:null});
  toast("Silent ended");
  await refreshAll();
}

/* ---------- History & Reports ---------- */
function rangeStartTs(range){
  const now = new Date();
  const end = now.getTime();
  if (range === "all") return 0;
  if (range === "week"){
    const d = new Date(now);
    const day = (d.getDay()+6)%7; // Monday=0
    d.setHours(0,0,0,0);
    d.setDate(d.getDate()-day);
    return d.getTime();
  }
  if (range === "month"){
    const d = new Date(now.getFullYear(), now.getMonth(), 1);
    d.setHours(0,0,0,0);
    return d.getTime();
  }
  if (range === "year"){
    const d = new Date(now.getFullYear(), 0, 1);
    d.setHours(0,0,0,0);
    return d.getTime();
  }
  const days = Number(range);
  if (!Number.isFinite(days)) return 0;
  return end - days*24*60*60*1000;
}

async function renderHistory(){
  const list = $("#historyList");
  const range = $("#historyRange").value;
  const q = $("#historySearch").value.trim().toLowerCase();

  let all = await IDBStore.getAll("incidents");
  const start = rangeStartTs(range);
  all = all.filter(i => i.ts >= start);
  all.sort((a,b)=>b.ts-a.ts);

  if (q){
    all = all.filter(i =>
      (i.note||"").toLowerCase().includes(q) ||
      (i.trigger||"").toLowerCase().includes(q) ||
      (i.startedBy||"").toLowerCase().includes(q)
    );
  }

  list.innerHTML = all.length ? "" : `<div class="tinyNote">No items for this filter.</div>`;
  all.forEach(it=> list.appendChild(renderIncidentItem(it)));
}

async function renderReports(){
  const range = $("#reportRange").value;
  const start = rangeStartTs(range);
  const incidents = (await IDBStore.getAll("incidents")).filter(i => i.ts >= start);
  incidents.sort((a,b)=>b.ts-a.ts);

  const silentSessions = (await IDBStore.getAll("silent")).filter(s => s.startTs >= start);

  $("#kpiIncidents").textContent = String(incidents.length);

  // Silent durations from sessions + incident-linked
  const durations = [];
  silentSessions.forEach(s=>{
    if (s.endTs && s.startTs) durations.push(daysBetween(s.startTs, s.endTs));
  });
  // Also include incidents that have silentStart+silentEnd in case sessions missed
  incidents.forEach(i=>{
    if (i.silentStartTs && i.silentEndTs){
      durations.push(daysBetween(i.silentStartTs, i.silentEndTs));
    }
  });

  const sum = durations.reduce((a,b)=>a+b,0);
  const avg = durations.length ? sum / durations.length : 0;
  const longest = durations.length ? Math.max(...durations) : 0;

  $("#kpiSilentDays").textContent = sum.toFixed(1);
  $("#kpiAvgSilent").textContent = avg.toFixed(1);
  $("#kpiLongest").textContent = longest.toFixed(1);

  // Started-by %
  const sb = {};
  incidents.forEach(i=> sb[i.startedBy] = (sb[i.startedBy]||0)+1);
  renderStatBars("#startedByStats", sb, incidents.length);

  // Top triggers
  const tr = {};
  incidents.forEach(i=> tr[i.trigger] = (tr[i.trigger]||0)+1);
  renderStatBars("#triggerStats", tr, incidents.length, 6);
}

function renderStatBars(containerSel, counts, total, limit=10){
  const container = $(containerSel);
  container.innerHTML = "";
  const rows = Object.entries(counts)
    .sort((a,b)=>b[1]-a[1])
    .slice(0, limit);

  if (!rows.length){
    container.innerHTML = `<div class="tinyNote">No data.</div>`;
    return;
  }

  rows.forEach(([k,v])=>{
    const row = document.createElement("div");
    row.className = "statRow";

    const lbl = document.createElement("div");
    lbl.className = "statLbl";
    lbl.textContent = k;

    const barWrap = document.createElement("div");
    barWrap.className = "barWrap";
    const bar = document.createElement("div");
    bar.className = "bar";
    const pct = total ? (v/total)*100 : 0;
    bar.style.width = `${Math.max(6, pct)}%`;
    barWrap.appendChild(bar);

    const val = document.createElement("div");
    val.className = "statVal";
    val.textContent = `${v} (${pct.toFixed(0)}%)`;

    row.appendChild(lbl);
    row.appendChild(barWrap);
    row.appendChild(val);
    container.appendChild(row);
  });
}

/* ---------- Triggers manage ---------- */
async function renderTriggerManager(){
  const list = $("#triggerManageList");
  const triggers = await getSetting(SETTINGS_KEYS.triggers, DEFAULT_TRIGGERS);
  list.innerHTML = "";
  triggers.forEach((t, idx)=>{
    const div = document.createElement("div");
    div.className = "item";
    div.innerHTML = `
      <div class="itemTop">
        <div class="itemNote">${t}</div>
        <div class="badges"><span class="badge">${idx+1}</span></div>
      </div>
      <div class="itemActions">
        <button class="smallBtn" data-act="rename">Rename</button>
        <button class="smallBtn" data-act="delete">Delete</button>
      </div>
    `;
    const [btnRename, btnDelete] = div.querySelectorAll("button");
    btnRename.onclick = async ()=>{
      const nv = prompt("Rename trigger:", t);
      if (!nv || !nv.trim()) return;
      const arr = (await getSetting(SETTINGS_KEYS.triggers, DEFAULT_TRIGGERS)).slice();
      arr[idx] = nv.trim();
      await setSetting(SETTINGS_KEYS.triggers, arr);
      toast("Updated");
      await refreshAll();
    };
    btnDelete.onclick = async ()=>{
      if (!confirm("Delete trigger?")) return;
      const arr = (await getSetting(SETTINGS_KEYS.triggers, DEFAULT_TRIGGERS)).slice();
      arr.splice(idx,1);
      await setSetting(SETTINGS_KEYS.triggers, arr);
      toast("Deleted");
      await refreshAll();
    };
    list.appendChild(div);
  });
}

async function rebuildHomeChips(){
  buildChips($("#startedByChips"), STARTED_BY, state.startedBy, (v)=>{
    state.startedBy = v;
    rebuildHomeChips();
  });
  buildChips($("#intensityChips"), INTENSITY, state.intensity, (v)=>{
    state.intensity = v;
    rebuildHomeChips();
  });

  const triggers = await getSetting(SETTINGS_KEYS.triggers, DEFAULT_TRIGGERS);
  buildChips($("#triggerChips"), triggers, state.trigger, (v)=>{
    state.trigger = v;
    rebuildHomeChips();
  });

  buildMultiChips($("#whatChips"), WHAT, state.what, (v)=>{
    if (state.what.includes(v)) state.what = state.what.filter(x=>x!==v);
    else state.what = [...state.what, v];
    rebuildHomeChips();
  });
}




document.addEventListener("visibilitychange", async ()=>{
  if (document.visibilityState === "hidden"){
    sessionUnlocked = false;
  }
  if (document.visibilityState === "visible"){
    await showLockIfNeeded();
  }
});


/* ===== PIN / LOCK REMOVED ===== */
async function showLockIfNeeded(){
  state.unlocked = true;
  return;
}
async function unlockWithPIN(){ return; }
async function lockNow(){ return; }
async function setOrChangePIN(){
  toast("PIN disabled");
}
async function resetPinWithRecovery(){
  toast("PIN disabled");
}
document.addEventListener("visibilitychange", ()=>{});
/* ===== END ===== */
