import { exec } from 'kernelsu';
const MOD='/data/adb/modules/sshprotocol_ksu';
const BASE='/data/adb/sshprotocol';
const run=(cmd)=>{const r=exec(cmd);if(r && typeof r==='object'){if(r.errno!==0)throw Error(r.stderr||r.stdout||'Command failed');return r.stdout||'';}return String(r??'');};
async function action(cmd){try{run(`sh ${MOD}/action.sh ${cmd}`);await refresh();}catch(e){alert(String(e));}}
async function refresh(){try{document.getElementById('status').textContent=run(`sh ${MOD}/action.sh status`).trim();}catch(e){document.getElementById('status').textContent='ERROR';}refreshLogs();refreshStats();}
async function refreshLogs(){try{document.getElementById('logs').textContent=run(`sh ${MOD}/action.sh logs`);}catch(e){document.getElementById('logs').textContent=String(e);}}
async function refreshStats(){try{document.getElementById('stats').textContent=run(`sh ${MOD}/action.sh stats`);}catch(e){document.getElementById('stats').textContent=String(e);}}
window.scanHostKey=()=>{try{const out=run(`${MOD}/bin/sshprotocol scan-host-key ${BASE}/config.json`);const lines=out.split(String.fromCharCode(10));const i=lines.findIndex(x=>x.startsWith('Known-hosts line:'));if(i>=0&&lines[i+1]){const box=document.getElementById('known_hosts');box.value=(box.value.trim()?box.value.trim()+String.fromCharCode(10):'')+lines[i+1];}alert(out);}catch(e){alert('Host-key scan failed: '+e);}};
window.loadKnownHosts=()=>{try{document.getElementById('known_hosts').value=run(`cat ${BASE}/known_hosts 2>/dev/null`);}catch(e){alert(String(e));}};
async function load(){try{const c=JSON.parse(run(`cat ${BASE}/config.json`));for(const k of ['mode','ssh_host','ssh_port','username','password','private_key','proxy_host','proxy_port','proxy_username','proxy_password','tls_server_name','tls_version','payload','payload_mode','host_key_policy'])if(c[k]!==undefined)document.getElementById(k).value=c[k];document.getElementById('auto_reconnect').value=String(c.auto_reconnect!==false);document.getElementById('tcp_no_delay').value=String(c.tcp_no_delay!==false);for(const k of ['socket_send_buffer_size','socket_receive_buffer_size'])if(c[k]!==undefined)document.getElementById(k).value=c[k];}catch(e){}try{document.getElementById('known_hosts').value=run(`cat ${BASE}/known_hosts 2>/dev/null`);}catch(e){}refresh();}
window.action=action;window.refreshLogs=refreshLogs;window.refreshStats=refreshStats;
window.toggleFlag=(name)=>{try{const path=BASE+'/'+name;const exists=run(`test -f ${path} && echo yes || echo no`).trim()==='yes';run(exists?`rm -f ${path}`:`touch ${path}`);alert(name+' '+(exists?'disabled':'enabled'));refresh();}catch(e){alert(String(e));}};
window.save=()=>{try{
 const get=k=>document.getElementById(k).value;
 const mode=get('mode');
 const c={mode,ssh_host:get('ssh_host').trim(),ssh_port:Number(get('ssh_port')||22),username:get('username'),password:get('password'),private_key:get('private_key'),
 proxy_host:get('proxy_host').trim(),proxy_port:Number(get('proxy_port')||0),proxy_username:get('proxy_username'),proxy_password:get('proxy_password'),
 tls_server_name:get('tls_server_name').trim(),tls_version:get('tls_version'),payload:get('payload'),payload_mode:get('payload_mode'),host_key_policy:get('host_key_policy'),
 known_hosts_file:BASE+'/known_hosts',local_socks_host:'127.0.0.1',local_socks_port:10808,connect_timeout_seconds:15,keepalive_seconds:30,
 auto_reconnect:get('auto_reconnect')==='true',max_reconnect:0,tcp_no_delay:get('tcp_no_delay')==='true',socket_send_buffer_size:Number(get('socket_send_buffer_size')||16384),socket_receive_buffer_size:Number(get('socket_receive_buffer_size')||32768),log_file:BASE+'/logs/sshprotocol.log'};
 const b64=btoa(unescape(encodeURIComponent(JSON.stringify(c,null,2))));
 const kh=btoa(unescape(encodeURIComponent(document.getElementById('known_hosts').value)));
 run(`mkdir -p ${BASE}/logs; printf '%s' '${b64}' | base64 -d > ${BASE}/config.json; chmod 600 ${BASE}/config.json; if [ -n '${kh}' ]; then printf '%s' '${kh}' | base64 -d > ${BASE}/known_hosts; chmod 600 ${BASE}/known_hosts; fi`);
 alert('Configuration saved. Restart the tunnel to apply.');}catch(e){alert('Save failed: '+e);}};
load();
