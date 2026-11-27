import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {chromium} from 'playwright-core';

const config=await readFile(new URL('../config.js',import.meta.url),'utf8');
const api=config.match(/url: '([^']+)'/)[1], key=config.match(/anonKey: '([^']+)'/)[1];
const site='https://hellven73.github.io/pixelmail/';
const names=['pmtestui_a'+randomBytes(5).toString('hex'),'pmtestui_b'+randomBytes(5).toString('hex')];
const password=randomBytes(24).toString('base64url');
const subject='Browser test '+randomBytes(4).toString('hex');
const errors=[];
const browser=await chromium.launch({channel:'chrome',headless:true,args:['--no-sandbox']});
const pages=[];
const contentTypes={'index.html':'text/html; charset=utf-8','style.css':'text/css; charset=utf-8','app.js':'application/javascript; charset=utf-8','motion.js':'application/javascript; charset=utf-8','config.js':'application/javascript; charset=utf-8'};
console.log('Temporary browser test accounts: '+names.join(', '));
async function setup(username){
  const context=await browser.newContext({viewport:{width:1365,height:900},acceptDownloads:true});
  const page=await context.newPage();
  pages.push(page);
  page.on('pageerror',e=>errors.push(e.message));
  await page.route(site+'**',async route=>{
    const path=new URL(route.request().url()).pathname.slice('/pixelmail/'.length)||'index.html';
    if(!Object.hasOwn(contentTypes,path))return route.fulfill({status:404,body:''});
    await route.fulfill({status:200,contentType:contentTypes[path],body:await readFile(new URL('../'+path,import.meta.url))});
  });
  await page.goto(site,{waitUntil:'domcontentloaded'});
  await page.locator('#authform').waitFor({timeout:60000});
  await page.locator('[data-action="auth-toggle"]').click();
  await page.locator('#email').fill(username+'@pixelmail');
  await page.locator('#password').fill(password);
  await page.locator('#authform button.primary').click();
  try{await page.locator('.profile-info strong').waitFor({timeout:45000})}catch(e){throw Error('Signup UI failed: '+await page.locator('#toast').innerText())}
  assert.equal(await page.locator('.profile-info strong').innerText(),username);
  return page;
}
async function token(page){return page.evaluate(()=>{const k=Object.keys(localStorage).find(x=>x.startsWith('sb-')&&x.endsWith('-auth-token'));return JSON.parse(localStorage.getItem(k)).access_token})}
async function cleanup(){
  if(pages.length!==2)return;
  try{
    const tokens=await Promise.all(pages.map(token));
    const headers=t=>({apikey:key,Authorization:'Bearer '+t,'Content-Type':'application/json'});
    const path='/rest/v1/mailbox?subject=eq.'+encodeURIComponent(subject);
    for(const t of tokens)await fetch(api+path,{method:'DELETE',headers:headers(t)});
    const profile=await fetch(api+'/auth/v1/user',{headers:headers(tokens[0])}).then(r=>r.json());
    if(profile.id){const objects=await fetch(api+'/storage/v1/object/list/mail-attachments',{method:'POST',headers:headers(tokens[0]),body:JSON.stringify({prefix:profile.id,limit:100})}).then(r=>r.json());const attachments=Array.isArray(objects)?objects.map(x=>profile.id+'/'+x.name):[];if(attachments.length)await fetch(api+'/storage/v1/object/mail-attachments',{method:'DELETE',headers:headers(tokens[0]),body:JSON.stringify({prefixes:attachments})})}
  }catch(e){console.log('Browser cleanup needs review: '+e.message)}
}
try{
  const a=await setup(names[0]), b=await setup(names[1]);
  await a.locator('.sidebar [data-action="compose"]').click();
  await a.locator('#composeform input[name="recipient"]').fill(names[1]+'@pixelmail');
  await a.locator('#composeform input[name="subject"]').fill(subject);
  await a.locator('#composeform textarea').fill('Hello from the real PixelMail interface');
  await a.locator('#file-input').setInputFiles({name:'hello.txt',mimeType:'text/plain',buffer:Buffer.from('PixelMail test file')});
  await a.locator('.compose .attachment-chip').waitFor({timeout:30000});
  await a.locator('#composeform button.primary').click();
  await a.locator('#toast .undo-btn').click();
  await a.locator('#composeform').waitFor();
  assert.equal(await a.locator('#composeform input[name="subject"]').inputValue(),subject);
  await a.locator('#composeform button.primary').click();
  await a.locator('.row').filter({hasText:subject}).waitFor({timeout:30000});
  await b.locator('.row').filter({hasText:subject}).waitFor({timeout:35000});
  await b.locator('.row').filter({hasText:subject}).click();
  await b.locator('.message-card .body').waitFor();
  assert.equal(await b.locator('.message-card .body').innerText(),'Hello from the real PixelMail interface');
  const downloading=b.waitForEvent('download');
  await b.locator('.message-card [data-action="download-attachment"]').click();
  const download=await downloading;
  assert.equal(download.suggestedFilename(),'hello.txt');
  assert.equal(await readFile(await download.path(),'utf8'),'PixelMail test file');
  await b.locator('[data-action="reply"]').click();
  await b.locator('#composeform textarea').fill('Reply from the browser');
  await b.locator('#composeform button.primary').click();
  await b.locator('.row').filter({hasText:'Re: '+subject}).waitFor({timeout:30000});
  await a.locator('[data-folder="inbox"]').click();
  await a.locator('[data-action="refresh"]').click();
  await a.locator('.row').filter({hasText:'Re: '+subject}).waitFor({timeout:35000});
  await a.setViewportSize({width:390,height:844});
  assert.ok(await a.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),'Mobile layout overflows horizontally');
  assert.deepEqual(errors,[]);
  console.log('PASS: original frontend, real signup UI, send and undo send, live inbox, browser attachment upload/download, reply, responsive layout');
}finally{
  await cleanup();
  await browser.close();
}
