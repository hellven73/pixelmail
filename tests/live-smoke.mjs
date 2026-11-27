import assert from 'node:assert/strict';
import {randomBytes,randomUUID,createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';
const config=await readFile(new URL('../config.js',import.meta.url),'utf8');
const url=config.match(/url: '([^']+)'/)[1], key=config.match(/anonKey: '([^']+)'/)[1];

const suffix=randomBytes(5).toString('hex');
const users=['pmtesta_'+suffix,'pmtestb_'+suffix,'pmtestc_'+suffix];
const password=randomBytes(24).toString('base64url');
async function request(path,method='GET',body,token,extra={}){
  const response=await fetch(url+path,{method,headers:{apikey:key,Authorization:'Bearer '+(token||key),'Content-Type':'application/json',...extra},body:body===undefined?undefined:JSON.stringify(body)});
  const raw=await response.text();
  let data;try{data=JSON.parse(raw)}catch{data=raw}
  if(!response.ok)throw Error(method+' '+path.split('?')[0]+' returned '+response.status+' '+String(data?.message||data?.msg||data?.error_description||'').slice(0,160));
  return data;
}
const tokens=[], ids=[];
for(const username of users){
  await request('/functions/v1/pixelmail-register','POST',{username,password},undefined,{Origin:'https://hellven73.github.io'});
  const login=await request('/auth/v1/token?grant_type=password','POST',{email:username+'@pixelmail.invalid',password});
  assert.ok(login.access_token);
  tokens.push(login.access_token);
  ids.push(login.user.id);
}
console.log('Temporary test accounts: '+users.join(', '));
const inbox=token=>request('/rest/v1/mailbox?select=sender,recipient,subject,folder,body','GET',undefined,token);
const profiles=await request('/rest/v1/profiles?select=username','GET',undefined,tokens[0]);
assert.deepEqual(profiles,[{username:users[0]}]);
await request('/rest/v1/rpc/send_mail_v6','POST',{targets:[users[1]],mail_subject:'PixelMail smoke test',mail_body:'Internal message delivery',mail_attachments:[]},tokens[0]);
assert.equal((await inbox(tokens[0]))[0].folder,'sent');
assert.equal((await inbox(tokens[1]))[0].folder,'inbox');
assert.equal((await inbox(tokens[1]))[0].sender,users[0]);
assert.equal((await inbox(tokens[2])).length,0);
await request('/rest/v1/rpc/send_mail_v6','POST',{targets:[users[0]],mail_subject:'Reply',mail_body:'Received',mail_attachments:[]},tokens[1]);
assert.equal((await inbox(tokens[0])).length,2);
assert.equal((await inbox(tokens[2])).length,0);
console.log('PASS: three-account registration, sign-in, profile isolation, delivery, reply and private mailbox access');

const file=Buffer.alloc(25*1024*1024,37);
const objectPath=ids[0]+'/'+randomUUID();
const storage='/storage/v1/object/';
const bucket='mail-attachments';
const authHeaders=token=>({apikey:key,Authorization:'Bearer '+token});
const upload=await fetch(url+storage+bucket+'/'+objectPath,{method:'POST',headers:{...authHeaders(tokens[0]),'Content-Type':'application/octet-stream','x-upsert':'false'},body:file});
assert.ok(upload.ok,'Attachment upload failed '+upload.status+' '+await upload.text());
const metadata={name:'pixelmail-test.bin',size:file.length,path:objectPath};
const msg={targets:[users[1]],mail_subject:'25 MiB attachment',mail_body:'Private file test',mail_attachments:[metadata]};
await assert.rejects(request('/rest/v1/rpc/send_mail_v6','POST',{...msg,mail_attachments:[metadata,metadata]},tokens[0]));
await assert.rejects(request('/rest/v1/rpc/send_mail_v6','POST',{...msg,mail_attachments:[{...metadata,size:file.length-1}]},tokens[0]));
await request('/rest/v1/rpc/send_mail_v6','POST',msg,tokens[0]);
const dl=token=>fetch(url+storage+'authenticated/'+bucket+'/'+objectPath,{headers:authHeaders(token)});
const received=await dl(tokens[1]);
assert.ok(received.ok,'Recipient could not download '+received.status);
const data=Buffer.from(await received.arrayBuffer());
assert.equal(data.length,file.length);
assert.equal(createHash('sha256').update(data).digest('hex'),createHash('sha256').update(file).digest('hex'));
assert.equal((await dl(tokens[2])).ok,false,'Third party attachment access');
const publicDownload=await fetch(url+storage+'public/'+bucket+'/'+objectPath);
assert.equal(publicDownload.ok,false,'Public attachment access');
await request('/rest/v1/mailbox?subject=eq.25%20MiB%20attachment','DELETE',undefined,tokens[0]);
await request('/rest/v1/mailbox?subject=eq.25%20MiB%20attachment','DELETE',undefined,tokens[1]);
const removed=await fetch(url+storage+bucket,{method:'DELETE',headers:{...authHeaders(tokens[0]),'Content-Type':'application/json'},body:JSON.stringify({prefixes:[objectPath]})});
assert.ok(removed.ok,'Attachment cleanup failed '+removed.status);
assert.equal((await dl(tokens[0])).ok,false,'File still exists after cleanup');
console.log('PASS: actual 25 MiB upload, aggregate limit, file integrity, private recipient download, third-party denial, cleanup');
