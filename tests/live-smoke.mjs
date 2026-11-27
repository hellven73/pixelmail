import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
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
const tokens=[];
for(const username of users){
  await request('/functions/v1/pixelmail-register','POST',{username,password},undefined,{Origin:'https://hellven73.github.io'});
  const login=await request('/auth/v1/token?grant_type=password','POST',{email:username+'@pixelmail.invalid',password});
  assert.ok(login.access_token);
  tokens.push(login.access_token);
}
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
