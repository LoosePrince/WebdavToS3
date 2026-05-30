import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import {
  type TenantRegistry,
  type Tenant,
  type UpstreamBinding,
  type BucketBinding,
} from '../tenancy/tenant-registry.js';
import { getConfig, saveConfig } from '../config/index.js';
import { info } from '../observability/logger.js';
import { getRequestId } from '../observability/request-context.js';

export function registerAdminRoutes(
  app: FastifyInstance,
  adminKey: string,
  registry: TenantRegistry,
): void {
  const prefix = `/admin/${adminKey}`;

  app.get(`${prefix}`, async (_req: FastifyRequest, reply: FastifyReply) => {
    return reply.type('text/html; charset=utf-8').send(adminPageHtml(adminKey));
  });

  app.get(`${prefix}/api/config`, async (_req, reply) => {
    const config = getConfig();
    const sanitized = sanitizeConfig(config);
    return reply.send(sanitized);
  });

  app.put(`${prefix}/api/config`, async (req: FastifyRequest, reply: FastifyReply) => {
    const requestId = getRequestId();
    const body = req.body as Record<string, unknown>;

    const currentConfig = getConfig();
    const merged = {
      ...body,
      server: {
        ...(body.server as Record<string, unknown> ?? {}),
        host: currentConfig.server.host,
        port: currentConfig.server.port,
      },
    };

    try {
      const validated = saveConfig(merged);
      hotReloadRegistry(registry, validated);
      info('config hot-reloaded', { requestId });
      return reply.send({ ok: true, message: 'Config saved and hot-reloaded' });
    } catch (err) {
      return reply.status(400).send({ ok: false, message: String(err) });
    }
  });
}

// ─── helpers ───────────────────────────────────────────────────

function sanitizeConfig(config: import('../config/schema.js').AppConfig) {
  const { host, port, ...editableServer } = config.server;
  return {
    server: editableServer,
    s3: config.s3,
    metadata: config.metadata,
    lifecycle: config.lifecycle,
    tenants: config.tenants.map((t) => ({
      id: t.id,
      accessKeyId: t.accessKeyId,
      secretAccessKey: t.secretAccessKey,
      upstreams: t.upstreams.map((u) => ({
        id: u.id,
        endpoint: u.endpoint,
        username: u.username,
        password: u.password,
        rejectUnauthorized: u.rejectUnauthorized,
        connectTimeoutMs: u.connectTimeoutMs,
        requestTimeoutMs: u.requestTimeoutMs,
      })),
      buckets: t.buckets.map((b) => ({
        name: b.name,
        upstreamId: b.upstreamId,
        rootPath: b.rootPath,
        region: b.region,
      })),
    })),
  };
}

function hotReloadRegistry(registry: TenantRegistry, config: import('../config/schema.js').AppConfig): void {
  registry.clear();
  for (const tc of config.tenants) {
    const upstreams = new Map<string, UpstreamBinding>();
    for (const uc of tc.upstreams) {
      upstreams.set(uc.id, {
        id: uc.id,
        endpoint: uc.endpoint,
        username: uc.username,
        password: uc.password,
        rejectUnauthorized: uc.rejectUnauthorized,
        connectTimeoutMs: uc.connectTimeoutMs,
        requestTimeoutMs: uc.requestTimeoutMs,
      });
    }
    const buckets = new Map<string, BucketBinding>();
    for (const bc of tc.buckets) {
      buckets.set(bc.name, {
        name: bc.name,
        upstreamId: bc.upstreamId,
        rootPath: bc.rootPath,
        region: bc.region,
      });
    }
    const tenant: Tenant = { id: tc.id, accessKeyId: tc.accessKeyId, secretAccessKey: tc.secretAccessKey, upstreams, buckets };
    registry.add(tenant);
  }
}

// ─── HTML page ────────────────────────────────────────────────

function adminPageHtml(adminKey: string): string {
  const apiBase = `/admin/${adminKey}/api`;

  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WebDAV to S3 — 管理后台</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f5f5f5;color:#222;padding:20px}
h1{margin-bottom:8px;font-size:22px}
.sub{color:#666;font-size:13px;margin-bottom:24px}
.card{background:#fff;border-radius:8px;box-shadow:0 1px 3px rgba(0,0,0,.1);padding:20px;margin-bottom:20px}
.card h2{font-size:16px;margin-bottom:12px;padding-bottom:8px;border-bottom:1px solid #eee}
.field{margin-bottom:12px}
.field label{display:block;font-size:12px;color:#666;margin-bottom:3px}
.field input,.field select{width:100%;padding:8px 10px;border:1px solid #ddd;border-radius:4px;font-size:14px;font-family:inherit}
.tenant-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:8px}
.tenant-header h3{font-size:15px}
.btn{padding:6px 14px;border:none;border-radius:4px;cursor:pointer;font-size:13px}
.btn-danger{background:#e74c3c;color:#fff}
.btn-danger:hover{background:#c0392b}
.btn-add{background:#3498db;color:#fff}
.btn-add:hover{background:#2980b9}
.btn-save{background:#27ae60;color:#fff;padding:10px 24px;font-size:15px;margin-top:16px}
.btn-save:hover{background:#219a52}
.btn-small{padding:4px 10px;font-size:12px}
.sub-section{margin-left:16px;padding:12px;background:#fafafa;border-radius:6px;margin-bottom:12px}
.sub-section h4{font-size:13px;color:#555;margin-bottom:8px}
.row{display:grid;grid-template-columns:1fr 1fr;gap:8px}
.row-3{grid-template-columns:1fr 1fr 1fr}
.status{display:none;padding:10px 14px;border-radius:4px;margin-top:12px;font-size:14px}
.status.ok{display:block;background:#d5f5e3;color:#1e8449}
.status.err{display:block;background:#fadbd8;color:#922b21}
.remove-bar{display:flex;justify-content:flex-end;margin-top:8px}
.tenant-card{border:1px solid #e0e0e0;border-radius:6px;padding:14px;margin-bottom:14px}
</style>
</head>
<body>
<h1>&#x2699;&#xFE0F; WebDAV &#x2192; S3 &#x7BA1;&#x7406;&#x540E;&#x53F0;</h1>
<p class="sub">修改配置后点击保存，自动校验、写入文件并热应用生效。<br>host 和 port 仅用于监听，不可在此修改。每次启动会生成新的管理地址。</p>
<div id="app"><span id="loading-msg" style="color:#888">正在加载配置...</span></div>
<div id="status" class="status"></div>
<button class="btn btn-save" id="saveBtn">&#x1F4BE; 保存并应用</button>

<script>
var API = '${apiBase}';
var data = null;

function showStatus(m,t){
  var s=document.getElementById('status');
  s.className='status'+(t?' '+t:'');
  s.textContent=m;
}

async function load(){
  showStatus('加载中...','');
  try{
    var r=await fetch(API+'/config');
    if(!r.ok){showStatus('加载失败: HTTP '+r.status,'err');return;}
    data=await r.json();
    document.getElementById('loading-msg').style.display='none';
    render();
  }catch(e){showStatus('加载失败: '+e,'err');}
}

function esc(s){return (s||'').replace(/&/g,'&amp;').replace(/"/g,'&quot;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}

function inputVal(v,fn){
  var el=document.createElement('input');
  el.value=v==null?'':String(v);
  el.style.width='100%';el.style.padding='8px 10px';el.style.border='1px solid #ddd';el.style.borderRadius='4px';el.style.fontSize='14px';
  el.onchange=fn;
  return el.outerHTML;
}

function boolSel(v,fn){
  var el=document.createElement('select');
  el.style.width='100%';el.style.padding='8px 10px';el.style.border='1px solid #ddd';el.style.borderRadius='4px';el.style.fontSize='14px';
  el.innerHTML='<option value="true">是</option><option value="false">否</option>';
  el.value=String(v);
  el.onchange=fn;
  return el.outerHTML;
}

function fld(lbl,html){
  return '<div class="field"><label>'+esc(lbl)+'</label>'+html+'</div>';
}

function render(){
  var root=document.getElementById('app');
  var h='<div class="card"><h2>全局设置</h2>';
  h+=fld('S3 区域',inputVal(data.s3&&data.s3.region,function(){data.s3.region=this.value}));
  h+=fld('信任代理 (trustProxy)',boolSel(data.server&&data.server.trustProxy,function(){data.server.trustProxy=this.value==='true'}));
  h+=fld('最大对象大小 (字节)',inputVal(data.server&&data.server.maxObjectSizeBytes,function(){data.server.maxObjectSizeBytes=Number(this.value)}));
  h+=fld('请求超时 (毫秒)',inputVal(data.server&&data.server.requestTimeoutMs,function(){data.server.requestTimeoutMs=Number(this.value)}));
  h+='</div>';
  root.innerHTML=h;
  if(data.tenants){
    for(var i=0;i<data.tenants.length;i++){root.innerHTML+=renderTenant(data.tenants[i],i);}
  }
  root.innerHTML+='<button class="btn btn-add" onclick="addTenant()" style="margin-top:8px">+ 新增租户</button>';
}

function renderTenant(t,i){
  var h='<div class="tenant-card">';
  h+='<div class="tenant-header"><h3>租户 #'+(i+1)+'</h3><button class="btn btn-danger btn-small" onclick="removeTenant('+i+')">删除</button></div>';
  h+=fld('标识',inputVal(t.id,function(){data.tenants[i].id=this.value}));
  h+=fld('访问密钥 ID',inputVal(t.accessKeyId,function(){data.tenants[i].accessKeyId=this.value}));
  h+=fld('秘密访问密钥',inputVal(t.secretAccessKey,function(){data.tenants[i].secretAccessKey=this.value}));
  h+='<div class="sub-section"><div class="remove-bar"><span style="flex:1"><b>上游服务器</b></span><button class="btn btn-add btn-small" onclick="addUpstream('+i+')">+ 添加</button></div>';
  if(t.upstreams){
    for(var ui=0;ui<t.upstreams.length;ui++){h+=renderUpstream(i,ui,t.upstreams[ui]);}
  }
  h+='</div>';
  h+='<div class="sub-section"><div class="remove-bar"><span style="flex:1"><b>桶映射</b></span><button class="btn btn-add btn-small" onclick="addBucket('+i+')">+ 添加</button></div>';
  if(t.buckets){
    for(var bi=0;bi<t.buckets.length;bi++){h+=renderBucket(i,bi,t.buckets[bi]);}
  }
  h+='</div></div>';
  return h;
}

function renderUpstream(i,ui,u){
  var h='<div style="border:1px solid #eee;border-radius:4px;padding:10px;margin-bottom:8px">';
  h+='<div class="remove-bar"><span style="flex:1;font-size:12px;color:#888">上游 '+(ui+1)+'</span><button class="btn btn-danger btn-small" onclick="removeUpstream('+i+','+ui+')">删除</button></div>';
  h+=fld('标识',inputVal(u.id,function(){data.tenants[i].upstreams[ui].id=this.value}));
  h+=fld('端点地址',inputVal(u.endpoint,function(){data.tenants[i].upstreams[ui].endpoint=this.value}));
  h+=fld('用户名',inputVal(u.username,function(){data.tenants[i].upstreams[ui].username=this.value}));
  h+=fld('密码',inputVal(u.password,function(){data.tenants[i].upstreams[ui].password=this.value}));
  h+=fld('拒绝未授权证书',boolSel(u.rejectUnauthorized,function(){data.tenants[i].upstreams[ui].rejectUnauthorized=this.value==='true'}));
  h+=fld('连接超时 (毫秒)',inputVal(u.connectTimeoutMs||10000,function(){data.tenants[i].upstreams[ui].connectTimeoutMs=Number(this.value)}));
  h+=fld('请求超时 (毫秒)',inputVal(u.requestTimeoutMs||120000,function(){data.tenants[i].upstreams[ui].requestTimeoutMs=Number(this.value)}));
  h+='</div>';
  return h;
}

function renderBucket(i,bi,b){
  var h='<div style="border:1px solid #eee;border-radius:4px;padding:10px;margin-bottom:8px">';
  h+='<div class="remove-bar"><span style="flex:1;font-size:12px;color:#888">桶 '+(bi+1)+'</span><button class="btn btn-danger btn-small" onclick="removeBucket('+i+','+bi+')">删除</button></div>';
  h+=fld('桶名',inputVal(b.name,function(){data.tenants[i].buckets[bi].name=this.value}));
  h+=fld('上游标识',inputVal(b.upstreamId,function(){data.tenants[i].buckets[bi].upstreamId=this.value}));
  h+=fld('根路径',inputVal(b.rootPath,function(){data.tenants[i].buckets[bi].rootPath=this.value}));
  h+=fld('区域',inputVal(b.region,function(){data.tenants[i].buckets[bi].region=this.value}));
  h+='</div>';
  return h;
}

function addTenant(){
  data.tenants.push({id:'new-tenant',accessKeyId:'',secretAccessKey:'',upstreams:[{id:'main',endpoint:'https://',username:'',password:'',rejectUnauthorized:true,connectTimeoutMs:10000,requestTimeoutMs:120000}],buckets:[{name:'new-bucket',upstreamId:'main',rootPath:'/',region:'us-east-1'}]});
  render();
}
function removeTenant(i){data.tenants.splice(i,1);render();}
function addUpstream(i){data.tenants[i].upstreams.push({id:'new-upstream',endpoint:'https://',username:'',password:'',rejectUnauthorized:true,connectTimeoutMs:10000,requestTimeoutMs:120000});render();}
function removeUpstream(i,ui){data.tenants[i].upstreams.splice(ui,1);render();}
function addBucket(i){data.tenants[i].buckets.push({name:'new-bucket',upstreamId:'',rootPath:'/',region:'us-east-1'});render();}
function removeBucket(i,bi){data.tenants[i].buckets.splice(bi,1);render();}

document.getElementById('saveBtn').onclick=async function(){
  var s=document.getElementById('status');
  s.className='status';
  try{
    var r=await fetch(API+'/config',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});
    var j=await r.json();
    if(r.ok){s.className='status ok';s.textContent='保存成功: '+j.message;}
    else{s.className='status err';s.textContent='保存失败: '+j.message;}
  }catch(e){s.className='status err';s.textContent='保存失败: '+e;}
};

load();
</script>
</body>
</html>`;
}