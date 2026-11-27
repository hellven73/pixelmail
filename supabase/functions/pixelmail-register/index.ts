import {createClient} from "npm:@supabase/supabase-js@2.49.4";
const origin="https://hellven73.github.io";
const headers={"Access-Control-Allow-Origin":origin,"Access-Control-Allow-Headers":"authorization, apikey, content-type, x-client-info","Access-Control-Allow-Methods":"POST, OPTIONS","Content-Type":"application/json","Cache-Control":"no-store","Vary":"Origin"};
const reply=(status:number,message:string)=>new Response(JSON.stringify({message}),{status,headers});
Deno.serve(async req=>{
 if(req.method==="OPTIONS")return new Response(null,{status:204,headers});
 if(req.method!=="POST")return reply(405,"Method not allowed");
 if(req.headers.get("origin")!==origin)return reply(403,"Invalid origin");
 try{
 if(Number(req.headers.get("content-length")||0)>4096)return reply(413,"Request too large");
 const input=await req.text();
 if(input.length>4096)return reply(413,"Request too large");
 const {username,password}=JSON.parse(input);
 if(typeof username!=="string"||!/^[a-z0-9_]{3,24}$/.test(username)||["admin","support","pixelmail","system","postmaster"].includes(username)||typeof password!=="string"||password.length<10||password.length>72||new TextEncoder().encode(password).length>72)return reply(400,"Choose a valid username and a password of 10 to 72 bytes.");
 const url=Deno.env.get("SUPABASE_URL"), secret=Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
 if(!url||!secret)return reply(503,"Registration unavailable");
 const admin=createClient(url,secret,{auth:{persistSession:false,autoRefreshToken:false}});
 const {data:allowed,error:limitError}=await admin.rpc("pixelmail_reserve_signup");
 if(limitError)return reply(503,"Registration unavailable");
 if(!allowed)return reply(429,"Registration limit reached. Try again later.");
 const {error}=await admin.auth.admin.createUser({email:username+"@pixelmail.invalid",password,email_confirm:true,app_metadata:{pixelmail_internal:true}});
 if(error)return reply(409,"Account could not be created. Choose another username or try again.");
 return reply(201,"Account created");
 }catch{return reply(400,"Invalid registration request")}
});