/* --- state --- */
var LIVE = JSON.parse(localStorage.getItem('autoRefresh') || 'true');
var VIEW = localStorage.getItem('view') || 'stream';
var MAX_ROWS = 5000; // fallback - overwritten by /api/v1/config on init (mirrors BUFFER_SIZE env var)
var pendingUnblocks = new Set(); // Track value\0target_hostname keys with pending unblock requests
var completedUnblocks = new Set(); // Track value\0target_hostname keys that have been unblocked

/* elements */
var autoRefreshEl = document.getElementById('autoRefresh');
var actionEl = document.getElementById('actionFilter');
var compEl = document.getElementById('componentFilter');
var searchEl = document.getElementById('search');
var streamBody = document.getElementById('streamBody');
var connectionStatus = document.getElementById('connectionStatus');
var tabStream = document.getElementById('tabStream');
var tabAgg = document.getElementById('tabAgg');
var streamView = document.getElementById('streamView');
var aggView = document.getElementById('aggView');
var aggBody = document.getElementById('aggBody');
var aggStats = document.getElementById('aggStats');

/* persistence + tab init */
autoRefreshEl.checked = LIVE;
function setView(v){
  VIEW = v; localStorage.setItem('view', v);
  tabStream.classList.toggle('active', v==='stream');
  tabAgg.classList.toggle('active', v==='agg');
  streamView.style.display = (v==='stream')?'flex':'none';
  aggView.style.display = (v==='agg')?'flex':'none';
}
setView(VIEW);
tabStream.onclick = function(){
  setView('stream');
  reload();               // refresh/backfill on tab switch
};
tabAgg.onclick = function(){
  setView('agg');
  reload();               // refresh/backfill on tab switch
};

/* controls */
function applyFilters(){
  if(VIEW==='stream') renderStream();
  else renderAgg();
}

// Auto-apply filters on change
actionEl.addEventListener('change', applyFilters);
compEl.addEventListener('change', applyFilters);
searchEl.addEventListener('input', applyFilters);

document.getElementById('clearBtn').onclick = async function(){
  if(!confirm('Clear all logs?')) return;
  var apiKey = localStorage.getItem('apiKey') || '';
  var clearHeaders = {};
  if (apiKey) clearHeaders['X-Api-Key'] = apiKey;
  var clearRes = await fetch('/api/v1/logs', {method:'DELETE', headers: clearHeaders});
  if (!clearRes.ok) { alert('Failed to clear logs (status ' + clearRes.status + ')'); return; }
  streamBody.innerHTML=''; allItems.length=0; renderAgg();
};
autoRefreshEl.addEventListener('change', function(){
  LIVE = autoRefreshEl.checked;
  localStorage.setItem('autoRefresh', JSON.stringify(LIVE));
  if (LIVE) connectSSE(); else disconnectSSE();
});

/* --- helpers --- */
function esc(s){
  if(s===null||s===undefined) return '';
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;');
}
function rel(t){var d=Date.now()-new Date(t).getTime();if(!isFinite(d))return'';var s=Math.floor(d/1000);if(s<60)return s+'s';var m=Math.floor(s/60);if(m<60)return m+'m';var h=Math.floor(m/60);if(h<24)return h+'h';return Math.floor(h/24)+'d';}
function sanitizeRemoteData(s){
  // Sanitize data from remote sources
  if(s===null||s===undefined) return '';
  return String(s).substring(0, 1000); // Limit length to prevent DoS
}
function norm(it){try{ if(it && typeof it.fields==='string' && it.fields && it.fields!=='null'){ it.fields=JSON.parse(it.fields);} }catch{ /* ignore parse errors */ } return it;}
function getAction(it){return sanitizeRemoteData(it && (it.action || (it.fields&&it.fields.action) || '')).toUpperCase();}
function getComp(it){return sanitizeRemoteData(it && (it.component || (it.fields&&it.fields.component) || '')).toLowerCase();}
function hostOf(it){var f=(it&&it.fields)||{};return sanitizeRemoteData((it&&(it.http_host||it.host||it.https||it.qname))||f.http_host||f.host||f.https||f.qname||'');}
function joinHostPort(ip, port){ return (ip&&ip.indexOf(':')!==-1&&ip.indexOf('[')===-1) ? '['+ip+']:'+port : ip+':'+port; }
function dstOf(it){if(it&&it.dst)return sanitizeRemoteData(it.dst); if(it&&it.destination_ip&&it.destination_port)return sanitizeRemoteData(joinHostPort(it.destination_ip,it.destination_port)); return it&&it.destination_ip?sanitizeRemoteData(it.destination_ip):'';}
function srcOf(it){if(it&&it.src)return sanitizeRemoteData(it.src); if(it&&it.source_ip&&it.source_port)return sanitizeRemoteData(joinHostPort(it.source_ip,it.source_port)); return it&&it.source_ip?sanitizeRemoteData(it.source_ip):'';}
function hostnameOf(it){return sanitizeRemoteData(it.hostname || ((it.fields&&it.fields.hostname)||''));}
function flowIdOf(it){return sanitizeRemoteData(it.flow_id || ((it.fields&&it.fields.flow_id)||''));}
function versionOf(it){return sanitizeRemoteData(it.version || ((it.fields&&it.fields.version)||''));}

/* filter */
function sanitizeInput(s){
  // Sanitize user input to prevent injection attacks
  if(!s) return '';
  // Limit length and strip non-whitelisted characters
  return String(s).slice(0, 200).replace(/[^\w\s\-.:@]/g, '');
}

function matches(it){
  var act=getAction(it); if(filterAction && act!==filterAction) return false;
  var comp=getComp(it); if(filterComp && comp!==filterComp) return false;
  if(!filterQuery) return true;
  var hay=[act, comp, hostOf(it), srcOf(it), dstOf(it), hostnameOf(it), flowIdOf(it), versionOf(it)].join(' ').toLowerCase();
  return hay.indexOf(filterQuery)!==-1;
}

/* --- stream --- */
var allItems=[];

/* filter cache - updated once per render pass instead of re-reading DOM on every row */
var filterAction='';
var filterComp='';
var filterQuery='';
function updateFilterCache(){
  filterAction=sanitizeInput(actionEl.value||'').toUpperCase();
  filterComp=sanitizeInput(compEl.value||'').toLowerCase();
  filterQuery=sanitizeInput(searchEl.value||'').toLowerCase();
}

/* --- unblock helpers --- */
async function requestUnblock(type, value, targetHostname) {
  try {
    var apiKey = localStorage.getItem('apiKey') || '';
    var headers = {'Content-Type': 'application/json'};
    if (apiKey) headers['X-Api-Key'] = apiKey;
    
    var body = {type: type, value: value};
    if (targetHostname) body.target_hostname = targetHostname;
    
    var res = await fetch('/api/v1/unblocks', {
      method: 'POST',
      headers: headers,
      body: JSON.stringify(body)
    });
    if (res.ok) {
      var displayTarget = targetHostname || 'all hosts';
      alert('Unblock request queued for: ' + value + ' (target: ' + displayTarget + ')');
      // Track this value+target as pending and re-render to hide the button
      var storeTarget = targetHostname || '';
      pendingUnblocks.add(value.toLowerCase() + '\0' + storeTarget.toLowerCase());
      renderStream();
    } else {
      var err = await res.json();
      alert('Failed to queue unblock: ' + (err.error || 'Unknown error'));
    }
  } catch (e) {
    alert('Failed to queue unblock: ' + e.message);
  }
}

function unblockDomain(domain, sourceHostname) {
  var targetHost = prompt('Target client (leave empty for all clients):', sourceHostname || '');
  if (targetHost === null) return; // Cancelled
  if (!confirm('Queue unblock request for domain: ' + domain + '?')) return;
  requestUnblock('domain', domain, targetHost.trim());
}

function unblockIP(ip, sourceHostname) {
  // Strip port if present - only for IPv4 (e.g. "1.2.3.4:80").
  // IPv6 addresses are passed without a port suffix; bracketed form "[::1]:80" is also handled.
  var cleanIP = ip;
  if (ip.charAt(0) === '[') {
    // Bracketed IPv6 with port: "[2001:db8::1]:443" → "2001:db8::1"
    var m = ip.match(/^\[([^\]]+)\]/);
    if (m) cleanIP = m[1];
  } else if (ip.indexOf('.') !== -1 && ip.indexOf(':') !== -1) {
    // IPv4 with port: "1.2.3.4:443" → "1.2.3.4"
    cleanIP = ip.split(':')[0];
  }
  var targetHost = prompt('Target client (leave empty for all clients):', sourceHostname || '');
  if (targetHost === null) return; // Cancelled
  if (!confirm('Queue unblock request for IP: ' + cleanIP + '?')) return;
  requestUnblock('ip', cleanIP, targetHost.trim());
}

// Expose to global scope for onclick handlers
window.unblockDomain = unblockDomain;
window.unblockIP = unblockIP;

// Escape a value for safe inclusion in a single-quoted JavaScript string literal
// inside an HTML attribute (e.g. onclick="...").
//
// HTML entities like &#x27; are decoded by the HTML parser *before* JS executes,
// so they cannot be used to neutralise JS-special characters in this context.
// Instead we use JS hex/unicode escapes which are invisible to the HTML parser
// and are then interpreted safely by the JS engine.
function jsStringEsc(value) {
  return String(value == null ? '' : value)
    .replace(/\\/g, '\\x5C')   // backslash - must come first
    .replace(/'/g, '\\x27')    // single quote - JS string delimiter
    .replace(/"/g, '\\x22')    // double quote - HTML attribute delimiter
    .replace(/</g, '\\x3C')    // prevent tag injection
    .replace(/>/g, '\\x3E')
    .replace(/&/g, '\\x26')    // prevent entity injection
    .replace(/\r/g, '\\r')
    .replace(/\n/g, '\\n')
    .replace(/\u2028/g, '\\u2028') // JS line/paragraph separators
    .replace(/\u2029/g, '\\u2029');
}

// Check if a value is in an unblock set for a given hostname.
// Matches exact (value, hostname) pair OR (value, "") meaning all hosts.
function isUnblocked(set, value, hostname) {
  var v = value.toLowerCase();
  var h = (hostname || '').toLowerCase();
  return set.has(v + '\0' + h) || set.has(v + '\0');
}

function rowHTML(it){
  var act  = getAction(it);
  var comp = getComp(it);
  var host = hostOf(it);
  var src  = srcOf(it);
  var dst  = dstOf(it);
  var hn   = hostnameOf(it);
  var fid  = flowIdOf(it);
  var ver  = versionOf(it);
  var when = it.time || it.ts || new Date().toISOString();
  var badge = 'badge-'+act;
  
  // Unblock button for blocked items - pass source hostname as default target
  // Show status: Unblocked (green) > Pending (yellow) > Unblock button
  var unblockBtn = '';
  if (act === 'BLOCKED' || act === 'AUDIT') {
    var escapedHn = jsStringEsc(hn);
    if (host) {
      if (isUnblocked(completedUnblocks, host, hn)) {
        unblockBtn = '<span class="unblock-done">Unblocked</span>';
      } else if (isUnblocked(pendingUnblocks, host, hn)) {
        unblockBtn = '<span class="unblock-pending">Pending</span>';
      } else {
        unblockBtn = '<button class="unblock-btn" onclick="unblockDomain(\''+jsStringEsc(host)+'\', \''+escapedHn+'\')">Unblock Domain</button>';
      }
    } else if (dst) {
      // Prefer the clean destination_ip field to avoid parsing the dst string,
      // which uses non-standard "ipv6addr:port" notation for IPv6.
      var cleanDst = (it.destination_ip) ? sanitizeRemoteData(it.destination_ip) : dst.split(':')[0];
      if (isUnblocked(completedUnblocks, cleanDst, hn)) {
        unblockBtn = '<span class="unblock-done">Unblocked</span>';
      } else if (isUnblocked(pendingUnblocks, cleanDst, hn)) {
        unblockBtn = '<span class="unblock-pending">Pending</span>';
      } else {
        unblockBtn = '<button class="unblock-btn" onclick="unblockIP(\''+jsStringEsc(cleanDst)+'\', \''+escapedHn+'\')">Unblock IP</button>';
      }
    }
  }
  
  return '<tr>' +
    '<td><span class="badge '+badge+'">'+esc(act)+'</span></td>' +
    '<td>'+unblockBtn+'</td>' +
    '<td>'+esc(comp)+'</td>' +
    '<td>'+esc(host)+'</td>' +
    '<td class="mono">'+esc(src)+'</td>' +
    '<td class="mono">'+esc(dst)+'</td>' +
    '<td>'+esc(hn)+'</td>' +
    '<td class="mono">'+esc(fid)+'</td>' +
    '<td class="mono">'+esc(ver)+'</td>' +
    '<td><small>'+esc(new Date(when).toLocaleString())+' <span style="opacity:.6">('+esc(rel(when))+' ago)</span></small></td>' +
  '</tr>';
}
function renderStream(){
  updateFilterCache();
  var out='';
  for(var i=0;i<allItems.length;i++){
    var it=allItems[i];
    if(!matches(it)) continue;
    out+=rowHTML(it);
  }
  streamBody.innerHTML=out;
}

/* --- aggregates --- */
function renderAgg(){
  updateFilterCache();
  // Single O(n) pass: accumulate totals and per-action counts together
  var map=new Map();

  function keyFor(it){
    var key = hostOf(it);
    if(!key) key = dstOf(it);
    return key || '';
  }

  for(var i=0;i<allItems.length;i++){
    var it=allItems[i]; if(!matches(it)) continue;
    var key=keyFor(it); if(!key) continue;
    var rec = map.get(key);
    if(!rec){ rec={ total:0, lastSeen:0, allowed:0, blocked:0 }; map.set(key, rec); }
    rec.total++;
    var t=new Date(it.time||it.ts||Date.now()).getTime();
    if(t>rec.lastSeen) rec.lastSeen=t;
    var action=getAction(it);
    if(action==='ALLOWED') rec.allowed++; else if(action==='BLOCKED'||action==='AUDIT') rec.blocked++;
  }

  var rows=[];
  map.forEach(function(v,k){ rows.push({key:k,total:v.total,lastSeen:v.lastSeen,allowed:v.allowed,blocked:v.blocked}); });

  rows.sort(function(a,b){ return (b.total-a.total) || (b.lastSeen-a.lastSeen); });

  var html='';
  for(var r=0;r<rows.length;r++){
    var a=rows[r];
    var act = a.blocked >= a.allowed ? 'BLOCKED' : 'ALLOWED';
    html+='<tr>'+
      '<td class="agg-key">'+esc(a.key)+'</td>'+
      '<td>'+a.total+'</td>'+
      '<td><span class="badge badge-'+act+'">'+esc(act)+'</span></td>'+
      '<td>'+(a.lastSeen? esc(new Date(a.lastSeen).toLocaleString())+' <span style="opacity:.6">('+esc(rel(a.lastSeen))+' ago)</span>':'')+'</td>'+
    '</tr>';
  }

  aggBody.innerHTML=html;
  aggStats.textContent=rows.length+' keys';
}
document.getElementById('aggRefresh').onclick=function(){ renderAgg(); };

/* --- data load (backfill from memory store) --- */
async function reload(){
  try {
    var res = await fetch('/api/v1/logs?limit='+MAX_ROWS);
    if (!res.ok) { console.error('reload failed:', res.status); return; }
    var items = await res.json();
    for(var i=0;i<items.length;i++) items[i]=norm(items[i]);
    allItems = items;
    renderStream();
    renderAgg();
  } catch(e) {
    console.error('reload error:', e);
  }
}

/* --- SSE --- */
var es=null;
function connectSSE(){
  disconnectSSE();
  es = new EventSource('/api/v1/events');
  es.onmessage = function(ev){
    try{
      var it = JSON.parse(ev.data);
      if(it && it.type==='cleared'){
        streamBody.innerHTML=''; allItems.length=0; renderAgg(); return;
      }
      it = norm(it);
      allItems.unshift(it);
      if(allItems.length>MAX_ROWS) allItems.pop();
      updateFilterCache();
      if(VIEW==='stream' && matches(it)){
        streamBody.insertAdjacentHTML('afterbegin', rowHTML(it));
      }
      if(VIEW==='agg') renderAgg();
    }catch{ /* ignore parse errors */ }
  };
  es.onerror = function(){
    if(LIVE){
      connectionStatus.classList.add('disconnected');
      // EventSource auto-retries using server "retry:" hint
    }
  };
  es.onopen = function(){
    connectionStatus.classList.remove('disconnected');
  };
}
function disconnectSSE(){ if(es){ es.close(); es=null; } }

/* --- unblock status polling --- */
function setsEqual(a, b){
  if(a.size !== b.size) return false;
  for(var v of a) if(!b.has(v)) return false;
  return true;
}
async function loadUnblockStatus(){
  try {
    var res = await fetch('/api/v1/unblocks/status');
    if (!res.ok) return;
    var data = await res.json();
    
    var changed = false;
    
    // Update pending set (keyed by value\0target_hostname)
    var newPending = new Set();
    if (data.pending) {
      for (var i = 0; i < data.pending.length; i++) {
        var p = data.pending[i];
        newPending.add(p.value.toLowerCase() + '\0' + (p.target_hostname || '').toLowerCase());
      }
    }
    if(!setsEqual(newPending, pendingUnblocks)) changed = true;
    pendingUnblocks = newPending;

    // Update completed set (keyed by value\0target_hostname)
    var newCompleted = new Set();
    if (data.completed) {
      for (var j = 0; j < data.completed.length; j++) {
        var c = data.completed[j];
        newCompleted.add(c.value.toLowerCase() + '\0' + (c.target_hostname || '').toLowerCase());
      }
    }
    if(!setsEqual(newCompleted, completedUnblocks)) changed = true;
    completedUnblocks = newCompleted;
    
    // Re-render if status changed
    if (changed) {
      renderStream();
    }
  } catch {
    // Ignore errors - status polling is best-effort
  }
}

// Poll for unblock status every 5 seconds
var unblockPollInterval = null;
function startUnblockPolling() {
  if (unblockPollInterval) return;
  unblockPollInterval = setInterval(loadUnblockStatus, 5000);
}

/* init */
// Fetch server config first so MAX_ROWS matches the server's actual buffer size,
// then backfill, start unblock polling, and connect SSE.
fetch('/api/v1/config')
  .then(function(r){ return r.ok ? r.json() : Promise.resolve({}); })
  .catch(function(){ return {}; })
  .then(function(cfg){
    if(cfg.buffer_size > 0) MAX_ROWS = cfg.buffer_size;
  })
  .then(function(){
    return reload();
  })
  .then(function(){
    loadUnblockStatus();
    startUnblockPolling();
    if(LIVE) connectSSE();
  });
