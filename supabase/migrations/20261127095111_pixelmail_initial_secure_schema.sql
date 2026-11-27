create schema if not exists pixelmail_private;
revoke all on schema pixelmail_private from public, anon, authenticated;
grant usage on schema pixelmail_private to authenticated;
create table public.profiles(id uuid primary key references auth.users(id) on delete cascade, username text not null unique check(username ~ '^[a-z0-9_]{3,24}$'));
create table public.mailbox(
 id uuid primary key default gen_random_uuid(), owner uuid not null references auth.users(id) on delete cascade,
 sender text not null check(sender ~ '^[a-z0-9_]{3,24}$'), recipient text not null default '' check(char_length(recipient)<=260),
 subject text not null default '' check(char_length(subject)<=160), body text not null default '' check(char_length(body)<=20000),
 folder text not null check(folder in ('inbox','sent','drafts','archive','trash')), original_folder text not null default 'drafts' check(original_folder in ('inbox','sent','drafts')),
 starred boolean not null default false, read boolean not null default false, created_at timestamptz not null default now(),
 labels text[] not null default '{}', snoozed_until timestamptz, spam boolean not null default false,
 attachments jsonb not null default '[]', thread_id uuid, message_id uuid,
 check(not spam or original_folder='inbox'), check(snoozed_until is null or original_folder='inbox')
);
create index mailbox_owner_date on public.mailbox(owner,created_at desc);
create table pixelmail_private.mail_rate(owner uuid primary key references auth.users(id) on delete cascade,window_start timestamptz not null default now(),sent_count integer not null default 0);
alter table pixelmail_private.mail_rate enable row level security;
alter table public.profiles enable row level security;
alter table public.mailbox enable row level security;
revoke all on public.profiles,public.mailbox from public,anon,authenticated;
grant select on public.profiles to authenticated;
grant select,delete on public.mailbox to authenticated;
grant insert(owner,sender,recipient,subject,body,folder,read,attachments,thread_id) on public.mailbox to authenticated;
grant update(recipient,subject,body,folder,starred,read,labels,snoozed_until,spam,attachments,thread_id) on public.mailbox to authenticated;
create policy profile_self on public.profiles for select to authenticated using(id=(select auth.uid()));
create policy mailbox_self_read on public.mailbox for select to authenticated using(owner=(select auth.uid()));
create policy mailbox_self_delete on public.mailbox for delete to authenticated using(owner=(select auth.uid()));
create policy mailbox_self_draft on public.mailbox for insert to authenticated with check(owner=(select auth.uid()) and folder='drafts' and sender=(select username from public.profiles where id=(select auth.uid())));
create policy mailbox_self_update on public.mailbox for update to authenticated using(owner=(select auth.uid())) with check(owner=(select auth.uid()));
create function pixelmail_private.valid_attachments(value jsonb) returns boolean language plpgsql immutable set search_path='' as $$
declare item jsonb; total bigint:=0; n bigint;
begin
 if value is null or jsonb_typeof(value)<>'array' then return false; end if;
 if jsonb_array_length(value)>5 or octet_length(value::text)>8192 then return false; end if;
 for item in select * from jsonb_array_elements(value) loop
 if jsonb_typeof(item)<>'object' or jsonb_typeof(item->'name') is distinct from 'string' or jsonb_typeof(item->'path') is distinct from 'string' or jsonb_typeof(item->'size') is distinct from 'number' or char_length(item->>'name') not between 1 and 150 or item->>'path' !~ '^[0-9a-f-]{36}/[0-9a-f-]{36}$' then return false; end if;
 n:=(item->>'size')::bigint; if n<0 or n>26214400 then return false; end if; total:=total+n;
 end loop;
 return total<=26214400;
exception when others then return false;
end $$;
revoke all on function pixelmail_private.valid_attachments(jsonb) from public,anon;
grant execute on function pixelmail_private.valid_attachments(jsonb) to authenticated;
alter table public.mailbox add constraint mailbox_attachments_valid check(pixelmail_private.valid_attachments(attachments));
create function pixelmail_private.valid_labels(value text[]) returns boolean language sql immutable set search_path='' as $$ select coalesce(cardinality(value)<=20 and not exists(select 1 from unnest(value) as item where item is null or char_length(item) not between 1 and 40),false) $$;
revoke all on function pixelmail_private.valid_labels(text[]) from public,anon;
grant execute on function pixelmail_private.valid_labels(text[]) to authenticated;
alter table public.mailbox add constraint mailbox_labels_valid check(pixelmail_private.valid_labels(labels));
create function pixelmail_private.guard_update() returns trigger language plpgsql set search_path='' as $$
begin
 if old.original_folder<>'drafts' and (new.recipient is distinct from old.recipient or new.subject is distinct from old.subject or new.body is distinct from old.body or new.attachments is distinct from old.attachments or new.thread_id is distinct from old.thread_id) then raise exception 'Delivered messages cannot be edited'; end if;
 if new.folder not in ('trash',old.original_folder) and not(old.original_folder='inbox' and new.folder='archive') then raise exception 'Invalid folder'; end if;
 return new;
end $$;
revoke all on function pixelmail_private.guard_update() from public,anon,authenticated;
create trigger guard_mailbox before update on public.mailbox for each row execute function pixelmail_private.guard_update();
create function pixelmail_private.claim_username(requested text) returns void language plpgsql security definer set search_path='' as $$
begin
 if auth.uid() is null then raise exception 'Sign in first'; end if;
 if requested is null or requested !~ '^[a-z0-9_]{3,24}$' or requested in ('admin','support','pixelmail','system','postmaster') then raise exception 'Choose a different username'; end if;
 insert into public.profiles(id,username) values(auth.uid(),requested);
exception when unique_violation then raise exception 'Username unavailable or already set';
end $$;
revoke all on function pixelmail_private.claim_username(text) from public,anon;
grant execute on function pixelmail_private.claim_username(text) to authenticated;
create function public.claim_username(requested text) returns void language sql security invoker set search_path='' as $$ select pixelmail_private.claim_username(requested) $$;
revoke all on function public.claim_username(text) from public,anon;
grant execute on function public.claim_username(text) to authenticated;
insert into storage.buckets(id,name,public,file_size_limit) values('mail-attachments','mail-attachments',false,26214400);
create policy pixelmail_upload on storage.objects for insert to authenticated with check(bucket_id='mail-attachments' and split_part(name,'/',1)=(select auth.uid())::text and name ~ '^[0-9a-f-]{36}/[0-9a-f-]{36}$' and exists(select 1 from public.profiles where id=(select auth.uid())));
create policy pixelmail_read on storage.objects for select to authenticated using(bucket_id='mail-attachments' and (split_part(name,'/',1)=(select auth.uid())::text or exists(select 1 from public.mailbox m where m.owner=(select auth.uid()) and m.original_folder in ('inbox','sent') and m.attachments @> jsonb_build_array(jsonb_build_object('path',storage.objects.name)))));
create function pixelmail_private.send_mail(targets text[],mail_subject text,mail_body text,mail_attachments jsonb,mail_thread uuid,draft_id uuid) returns void language plpgsql security definer set search_path='' as $$
declare sender_name text; recipient_id uuid; target text; used integer; tid uuid; mid uuid:=gen_random_uuid(); n integer;
begin
 if auth.uid() is null then raise exception 'Sign in first'; end if;
 select username into sender_name from public.profiles where id=auth.uid();
 if sender_name is null then raise exception 'Choose a username first'; end if;
 if targets is null or cardinality(targets) not between 1 and 10 or array_position(targets,null) is not null then raise exception 'Choose 1 to 10 recipients'; end if;
 select array_agg(distinct t) into targets from unnest(targets) as t;
 n:=cardinality(targets);
 if mail_subject is null or mail_body is null or char_length(mail_subject)>160 or char_length(mail_body)>20000 or not pixelmail_private.valid_attachments(mail_attachments) or (btrim(mail_subject)='' and btrim(mail_body)='' and jsonb_array_length(mail_attachments)=0) then raise exception 'Invalid message'; end if;
 if draft_id is not null then perform 1 from public.mailbox where id=draft_id and owner=auth.uid() and folder='drafts' for update; if not found then raise exception 'Draft not found'; end if; end if;
 if mail_thread is not null and not exists(select 1 from public.mailbox where owner=auth.uid() and original_folder<>'drafts' and (thread_id=mail_thread or id=mail_thread)) then raise exception 'Conversation not found'; end if;
 if exists(select 1 from jsonb_array_elements(mail_attachments) a where split_part(a->>'path','/',1)<>auth.uid()::text or not exists(select 1 from storage.objects o where o.bucket_id='mail-attachments' and o.name=a->>'path' and (o.metadata->>'size')::bigint=(a->>'size')::bigint)) then raise exception 'Attachment missing or invalid'; end if;
 tid:=coalesce(mail_thread,gen_random_uuid());
 insert into pixelmail_private.mail_rate(owner,window_start,sent_count) values(auth.uid(),now(),n)
 on conflict(owner) do update set window_start=case when pixelmail_private.mail_rate.window_start<now()-interval '1 hour' then now() else pixelmail_private.mail_rate.window_start end,sent_count=case when pixelmail_private.mail_rate.window_start<now()-interval '1 hour' then n else pixelmail_private.mail_rate.sent_count+n end returning sent_count into used;
 if used>30 then raise exception 'Hourly sending limit reached'; end if;
 foreach target in array targets loop
 if target !~ '^[a-z0-9_]{3,24}$' then raise exception 'Invalid recipient'; end if;
 select id into recipient_id from public.profiles where username=target;
 if recipient_id is null then raise exception 'Recipient not found'; end if;
 insert into public.mailbox(owner,sender,recipient,subject,body,folder,original_folder,read,attachments,thread_id,message_id) values(recipient_id,sender_name,target,mail_subject,mail_body,'inbox','inbox',false,mail_attachments,tid,mid);
 end loop;
 insert into public.mailbox(owner,sender,recipient,subject,body,folder,original_folder,read,attachments,thread_id,message_id) values(auth.uid(),sender_name,array_to_string(targets,', '),mail_subject,mail_body,'sent','sent',true,mail_attachments,tid,mid);
 if draft_id is not null then delete from public.mailbox where id=draft_id and owner=auth.uid() and folder='drafts'; end if;
end $$;
revoke all on function pixelmail_private.send_mail(text[],text,text,jsonb,uuid,uuid) from public,anon;
grant execute on function pixelmail_private.send_mail(text[],text,text,jsonb,uuid,uuid) to authenticated;
create function public.send_mail_v6(targets text[],mail_subject text,mail_body text,mail_attachments jsonb,mail_thread uuid default null,draft_id uuid default null) returns void language sql security invoker set search_path='' as $$ select pixelmail_private.send_mail(targets,mail_subject,mail_body,mail_attachments,mail_thread,draft_id) $$;
revoke all on function public.send_mail_v6(text[],text,text,jsonb,uuid,uuid) from public,anon;
grant execute on function public.send_mail_v6(text[],text,text,jsonb,uuid,uuid) to authenticated;
alter publication supabase_realtime add table public.mailbox;
