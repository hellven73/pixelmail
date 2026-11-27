CREATE OR REPLACE FUNCTION pixelmail_private.send_mail(targets text[], mail_subject text, mail_body text, mail_attachments jsonb, mail_thread uuid, draft_id uuid)
 RETURNS void
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare sender_name text; recipient_id uuid; target text; used integer; tid uuid; mid uuid:=gen_random_uuid(); n integer; path_lock text;
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
 for path_lock in select distinct a->>'path' from jsonb_array_elements(mail_attachments) a order by 1 loop
  perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(path_lock,0));
 end loop;
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
end $function$

