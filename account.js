/* Account and server persistence; learning UI remains in index.html. */
window.StudyFlow=(()=>{
 'use strict';
 const $=s=>document.querySelector(s);
 const esc=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
 let core,user=null,pendingUser=null,revision=0,dirty=false,saving=null,blocked=false,loading=false,serial=0,debounce,register=false;
 async function api(path,method='GET',data){
  const response=await fetch('/api'+path,{method,credentials:'same-origin',headers:data===undefined?{}:{'Content-Type':'application/json'},body:data===undefined?undefined:JSON.stringify(data),signal:AbortSignal.timeout(15000)});
  let result;try{result=await response.json()}catch{throw new Error('服务器返回异常，请稍后重试')}
  if(!response.ok){const error=new Error(result.error||'操作失败');error.status=response.status;throw error}return result;
 }
 function status(text,failed=false){$('#syncStatus').textContent=text;$('#syncStatus').classList.toggle('failed',failed)}
 function message(text){$('#syncMessage').textContent=text;$('#syncBanner').hidden=false}
 function exportData(){const blob=new Blob([JSON.stringify(core.get(),null,2)],{type:'application/json'}),url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download=`studyflow-${pendingUser?.username||user?.username||'backup'}-${Date.now()}.json`;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000)}
 function mark(){if(!user||loading)return;dirty=true;serial++;pendingUser=user;status('等待保存…');clearTimeout(debounce);debounce=setTimeout(flush,250)}
 function flush(){
  clearTimeout(debounce);if(saving)return saving;if(!dirty||blocked||!user)return Promise.resolve(!dirty);
  saving=(async()=>{
   try{while(dirty&&!blocked&&user){status('正在保存…');const version=serial;const result=await api('/state','PUT',{revision,data:core.get()});revision=result.revision;dirty=serial!==version;$('#syncBanner').hidden=true;status(dirty?'等待保存…':'已保存到后台')}return !dirty}
   catch(error){status('尚未保存',true);if(error.status===409){blocked=true;message(error.message)}else if(error.status===401){blocked=true;message('登录已失效。请导出尚未保存的数据，再重新登录。')}else{message('保存失败，当前修改仍保留在此页面。请重试，或导出备份。')}return false}
   finally{saving=null}
  })();return saving;
 }
 function showLogin(){user=null;core.pause();register=false;document.querySelectorAll('[data-auth-mode]').forEach(b=>b.classList.toggle('active',b.dataset.authMode==='login'));$('#authSubmit').textContent='登录';$('#authPassword').autocomplete='current-password';$('#authPassword').minLength=1;$('.app').hidden=true;$('#authScreen').hidden=false;$('#authExport').hidden=!dirty;$('#authError').textContent='';$('#authPassword').value='';$('#authUsername').focus()}
 async function enter(next){
  loading=true;
  try{
   const saved=await api('/state');
   const keep=dirty&&pendingUser?.id===next.id&&pendingUser?.username===next.username;
   if(!keep){core.set(saved.data);revision=saved.revision;dirty=false;serial=0}
   user=next;pendingUser=next;blocked=false;$('#syncBanner').hidden=true;
   $('#accountName').textContent=next.username+(next.role==='admin'?' · 管理员':'');$('#adminOpen').hidden=next.role!=='admin';$('#adminPanel').hidden=true;$('#learningContent').hidden=false;
   $('#authScreen').hidden=true;$('.app').hidden=false;status(dirty?'等待保存…':'已保存到后台');core.render();
   let legacy=null;try{legacy=JSON.parse(localStorage.getItem('studyflow.v1'))}catch{}
   $('#importLegacy').hidden=!!saved.data||!legacy||!Array.isArray(legacy.tasks);
  }finally{loading=false}
  core.resume();if(dirty)flush();
 }
 async function loadUsers(){
  const list=await api('/admin/users');$('#adminCount').textContent=`共 ${list.length} 个账号`;
  const date=n=>n?new Date(n*1000).toLocaleString('zh-CN'):'尚未登录';
  $('#adminUsers').innerHTML=list.map(u=>`<tr><td>${esc(u.username)}</td><td>${u.role==='admin'?'管理员':'普通用户'}</td><td>${esc(date(u.createdAt))}</td><td>${esc(date(u.lastLogin))}</td><td>${u.sessions} 个有效会话</td><td>${u.role==='admin'?'使用「修改密码」':`<button class="secondary" data-reset-user="${u.id}" data-name="${esc(u.username)}">重置密码</button><button class="danger" data-delete-user="${u.id}" data-name="${esc(u.username)}">删除用户</button>`}</td></tr>`).join('');
 }
 function mount(adapter){
  core=adapter;
  $('#authForm').addEventListener('submit',async e=>{e.preventDefault();const button=$('#authSubmit');button.disabled=true;$('#authError').textContent='';try{
   if(dirty&&(!pendingUser||$('#authUsername').value.trim().toLowerCase()!==pendingUser.username.toLowerCase())&&!confirm('当前还有未保存的数据。建议先导出备份；继续切换账号会丢弃这些修改。是否继续？'))return;
   const next=await api(register?'/register':'/login','POST',{username:$('#authUsername').value.trim(),password:$('#authPassword').value});await enter(next)
  }catch(error){$('#authError').textContent=error.message}finally{button.disabled=false}});
  document.querySelectorAll('[data-auth-mode]').forEach(b=>b.addEventListener('click',()=>{register=b.dataset.authMode==='register';document.querySelectorAll('[data-auth-mode]').forEach(x=>x.classList.toggle('active',x===b));$('#authSubmit').textContent=register?'注册并开始学习':'登录';$('#authPassword').autocomplete=register?'new-password':'current-password';$('#authPassword').minLength=register?6:1;$('#authError').textContent=''}));
  $('#retrySave').onclick=()=>{if(blocked){message('请先导出备份，再重新登录或刷新页面以取得最新数据。');return}flush()};$('#exportData').onclick=exportData;$('#authExport').onclick=exportData;
  $('#reloadData').onclick=()=>{if(dirty&&!confirm('刷新将丢弃本页未保存的修改。请确认已导出备份，是否继续？'))return;location.reload()};
  $('#logout').onclick=async()=>{if(dirty&&!(await flush())){if(!confirm('修改尚未保存，退出会丢弃这些修改。请先导出备份。仍要退出？'))return}try{await api('/logout','POST');dirty=false;blocked=false;core.set(null);showLogin()}catch(e){message(e.message)}};
  $('#relogin').onclick=async()=>{if(saving)await saving;showLogin()};
  $('#adminOpen').onclick=async()=>{try{await loadUsers();$('#learningContent').hidden=true;$('#adminPanel').hidden=false}catch(e){message(e.message)}};
  $('#adminBack').onclick=()=>{$('#adminPanel').hidden=true;$('#learningContent').hidden=false};$('#refreshUsers').onclick=()=>loadUsers().catch(e=>message(e.message));
  $('#nav').addEventListener('click',e=>{if(e.target.closest('[data-view]')){$('#adminPanel').hidden=true;$('#learningContent').hidden=false}});
  $('#adminUsers').onclick=async e=>{const b=e.target.closest('[data-reset-user],[data-delete-user]');if(!b)return;const reset=b.hasAttribute('data-reset-user'),id=reset?b.dataset.resetUser:b.dataset.deleteUser;
   if(!confirm(reset?`将「${b.dataset.name}」的密码重置为其用户名，并让其退出登录？`:`永久删除「${b.dataset.name}」及其全部学习数据？此操作无法撤销。`))return;
   b.disabled=true;try{await api(`/admin/users/${id}${reset?'/reset-password':''}`,reset?'POST':'DELETE');await loadUsers();core.toast(reset?'密码已重置为用户名':'用户及其数据已删除')}catch(error){message(error.message)}finally{b.disabled=false}
  };
  $('#passwordOpen').onclick=()=>{$('#passwordForm').reset();$('#passwordError').textContent='';$('#passwordDialog').showModal()};$('#passwordCancel').onclick=()=>$('#passwordDialog').close();
  $('#passwordForm').onsubmit=async e=>{e.preventDefault();if(dirty&&!(await flush())){ $('#passwordError').textContent='请先处理尚未保存的数据';return}const b=$('#passwordSubmit');b.disabled=true;try{await api('/password','POST',{current:$('#currentPassword').value,password:$('#newPassword').value});$('#passwordDialog').close();showLogin();$('#authError').textContent='密码已修改，请使用新密码登录'}catch(error){$('#passwordError').textContent=error.message}finally{b.disabled=false}};
  $('#importLegacy').onclick=async()=>{if(!confirm('将此浏览器旧版的学习数据导入当前账号？这会替换当前账号的数据。'))return;try{const data=JSON.parse(localStorage.getItem('studyflow.v1'));if(!data||!Array.isArray(data.tasks)||!Array.isArray(data.blocks))throw new Error('旧数据格式不正确');core.set(data);core.render();mark();if(await flush()){$('#importLegacy').hidden=true;core.toast('旧数据已导入后台')}}catch(e){message(e.message)}};
  window.addEventListener('beforeunload',e=>{if(dirty){e.preventDefault();e.returnValue=''}});
  window.addEventListener('online',()=>{if(!blocked)flush()});
  api('/me').then(enter).catch(e=>{showLogin();if(e.status!==401)$('#authError').textContent='暂时无法连接后台，请确认服务已启动后重试'});
 }
 return {mount,save:mark,active:()=>!!user,exportData};
})();
