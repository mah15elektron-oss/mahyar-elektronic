const JSON_HEADERS = {"Content-Type":"application/json; charset=utf-8","X-Content-Type-Options":"nosniff","Cache-Control":"no-store"};
const cors = (origin, env) => {
  const allowed = (env.SITE_ORIGIN || "").split(",").map(x=>x.trim()).filter(Boolean);
  if (!origin || allowed.includes(origin)) return {"Access-Control-Allow-Origin":origin || allowed[0] || "*","Vary":"Origin","Access-Control-Allow-Methods":"GET,POST,PUT,DELETE,OPTIONS","Access-Control-Allow-Headers":"Content-Type,Authorization","Access-Control-Max-Age":"86400"};
  return {"Vary":"Origin"};
};
const response = (data,status=200,headers={}) => new Response(JSON.stringify(data),{status,headers:{...JSON_HEADERS,...headers}});
const err = (message,status=400,headers={}) => response({error:message},status,headers);
const now = ()=>new Date().toISOString();
const id = ()=>crypto.randomUUID();
const deviceType = ua => /iPad|Tablet/i.test(ua||"")?"tablet":/Mobi|Android|iPhone/i.test(ua||"")?"mobile":"desktop";
function b64url(bytes){return btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/=/g,"").replace(/\+/g,"-").replace(/\//g,"_")}
async function signToken(payload,secret){const data=b64url(new TextEncoder().encode(JSON.stringify(payload)));const key=await crypto.subtle.importKey("raw",new TextEncoder().encode(secret),{name:"HMAC",hash:"SHA-256"},false,["sign"]);const sig=await crypto.subtle.sign("HMAC",key,new TextEncoder().encode(data));return `${data}.${b64url(sig)}`}
async function verifyToken(token,secret){try{const [data,sig]=token.split(".");if(!data||!sig)return false;const key=await crypto.subtle.importKey("raw",new TextEncoder().encode(secret),{name:"HMAC",hash:"SHA-256"},false,["verify"]);const raw=Uint8Array.from(atob(sig.replace(/-/g,"+").replace(/_/g,"/")),c=>c.charCodeAt(0));const ok=await crypto.subtle.verify("HMAC",key,raw,new TextEncoder().encode(data));const payload=JSON.parse(atob(data.replace(/-/g,"+").replace(/_/g,"/")));return ok&&payload.exp>Date.now()&&payload.role==="admin"}catch{return false}}
async function isAdmin(req,env){const auth=req.headers.get("Authorization")||"";const token=auth.startsWith("Bearer ")?auth.slice(7):"";return !!(env.TOKEN_SECRET&&token&&await verifyToken(token,env.TOKEN_SECRET))}
function cleanPost(p){const allowed=["الکترونیک","دیجیتال","آردوینو","برنامه‌نویسی","پروژه"];return {id:String(p.id||id()).slice(0,80),title:String(p.title||"").trim().slice(0,140),excerpt:String(p.excerpt||"").trim().slice(0,260),category:allowed.includes(p.category)?p.category:"پروژه",read_time:String(p.read||p.read_time||"۵ دقیقه").slice(0,30),image_url:String(p.image||p.image_url||"").slice(0,1000),body:String(p.body||"").slice(0,100000)}}
function mapPost(r){return {id:r.id,title:r.title,excerpt:r.excerpt,category:r.category,read:r.read_time,image:r.image_url,body:r.body,date:new Date(r.published_at).toLocaleDateString("fa-IR"),featured:r.category==="دیجیتال"?"A·B":r.category==="آردوینو"?"{ }":"ME"}}
async function adminLogin(req,env){if(!env.ADMIN_PASSWORD||!env.TOKEN_SECRET)return err("Admin secrets are not configured",503);let body;try{body=await req.json()}catch{return err("Invalid JSON")}const password=String(body.password||"");if(password.length>200||password!==env.ADMIN_PASSWORD)return err("Invalid credentials",401);const token=await signToken({role:"admin",exp:Date.now()+8*60*60*1000},env.TOKEN_SECRET);return response({token,expiresIn:28800})}
async function handle(req,env,ctx){
 const origin=req.headers.get("Origin")||"";
 const headers=cors(origin,env);
 if(req.method==="OPTIONS")return new Response(null,{status:204,headers});
 if(origin && headers["Access-Control-Allow-Origin"]!==origin)return err("Origin not allowed",403,headers);
 const url=new URL(req.url),path=url.pathname;
 if(path==="/api/health")return response({ok:true,service:"Mahyar Elektronic API"});
 if(path==="/api/admin/login"&&req.method==="POST")return adminLogin(req,env);
 if(path==="/api/posts"&&req.method==="GET"){
   const {results=[]}=await env.DB.prepare("SELECT * FROM posts ORDER BY published_at DESC").all();
   return response({posts:results.map(mapPost)},200,headers);
 }
 if(path==="/api/consent"&&req.method==="POST"){
   let b;try{b=await req.json()}catch{return err("Invalid JSON",400,headers)}
   const analytics=!!b.analytics;
   // Cloudflare provides approximate country/city metadata; raw IP is not read or stored here.
   if(analytics){const cf=req.cf||{};ctx.waitUntil(env.DB.prepare("INSERT INTO consent_events (id,analytics_allowed,country,city,device_type,created_at) VALUES (?,?,?,?,?,?)").bind(id(),1,cf.country||null,cf.city||null,deviceType(req.headers.get("User-Agent")),now()).run())}
   return response({saved:true},200,headers);
 }
 if(path==="/api/analytics/view"&&req.method==="POST"){
   let b;try{b=await req.json()}catch{return err("Invalid JSON",400,headers)}
   if(b.analytics!==true)return response({saved:false},200,headers);
   const cf=req.cf||{},pathname=String(b.path||"/").slice(0,300);
   ctx.waitUntil(env.DB.prepare("INSERT INTO page_views (id,path,country,city,device_type,created_at) VALUES (?,?,?,?,?,?)").bind(id(),pathname,cf.country||null,cf.city||null,deviceType(req.headers.get("User-Agent")),now()).run());
   return response({saved:true},200,headers);
 }
 if(path.startsWith("/api/admin/")){
   if(!await isAdmin(req,env))return err("Unauthorized",401,headers);
   if(path==="/api/admin/posts"&&(req.method==="POST"||req.method==="PUT")){
     let b;try{b=await req.json()}catch{return err("Invalid JSON",400,headers)}
     const p=cleanPost(b);if(!p.title||!p.excerpt||!p.body)return err("Title, excerpt and body are required",400,headers);
     const existing=await env.DB.prepare("SELECT id,published_at FROM posts WHERE id=?").bind(p.id).first();
     const published=existing?.published_at||now(),updated=now();
     await env.DB.prepare(`INSERT INTO posts (id,title,excerpt,category,read_time,image_url,body,published_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET title=excluded.title,excerpt=excluded.excerpt,category=excluded.category,read_time=excluded.read_time,image_url=excluded.image_url,body=excluded.body,updated_at=excluded.updated_at`).bind(p.id,p.title,p.excerpt,p.category,p.read_time,p.image_url,p.body,published,updated).run();
     return response({post:mapPost({...p,published_at:published})},200,headers);
   }
   const deleteMatch=path.match(/^\/api\/admin\/posts\/([^/]+)$/);
   if(deleteMatch&&req.method==="DELETE"){await env.DB.prepare("DELETE FROM posts WHERE id=?").bind(decodeURIComponent(deleteMatch[1])).run();return response({deleted:true},200,headers)}
   if(path==="/api/admin/analytics"&&req.method==="GET"){
     const views=await env.DB.prepare("SELECT COUNT(*) AS count FROM page_views").first();
     const countries=await env.DB.prepare("SELECT country,COUNT(*) AS count FROM page_views WHERE country IS NOT NULL GROUP BY country ORDER BY count DESC LIMIT 15").all();
     const devices=await env.DB.prepare("SELECT device_type,COUNT(*) AS count FROM page_views GROUP BY device_type").all();
     return response({views:views?.count||0,countries:countries.results||[],devices:devices.results||[]},200,headers);
   }
   if(path==="/api/admin/upload"&&req.method==="POST"){
     const ct=req.headers.get("Content-Type")||"";
     if(!ct.startsWith("image/")&&!ct.startsWith("video/")&&!ct.startsWith("application/pdf")&&!ct.startsWith("text/plain")&&!ct.startsWith("application/zip"))return err("File type not allowed",415,headers);
     const len=Number(req.headers.get("Content-Length")||0);if(len>25*1024*1024)return err("File too large (25 MB max)",413,headers);
     const key=`uploads/${new Date().toISOString().slice(0,10)}/${id()}`;
     await env.UPLOADS.put(key,req.body,{httpMetadata:{contentType:ct}});
     return response({key,publicUrl:`/files/${key}`},201,headers);
   }
   return err("Admin route not found",404,headers);
 }
 if(path.startsWith("/files/")&&req.method==="GET"){
   const key=decodeURIComponent(path.slice("/files/".length));
   if(key.includes(".."))return err("Invalid path",400,headers);
   const object=await env.UPLOADS.get(key);if(!object)return err("Not found",404,headers);
   const h=new Headers(headers);object.writeHttpMetadata(h);h.set("ETag",object.httpEtag);h.set("X-Content-Type-Options","nosniff");h.set("Cache-Control","public, max-age=3600");
   return new Response(object.body,{headers:h});
 }
 return err("Not found",404,headers);
}
export default {fetch(req,env,ctx){return handle(req,env,ctx).catch(e=>{console.error("API error",e);return response({error:"Internal server error"},500,cors(req.headers.get("Origin")||"",env))})}}
