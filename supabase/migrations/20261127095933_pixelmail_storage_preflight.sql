CREATE OR REPLACE FUNCTION pixelmail_private.can_upload_attachment(object_name text, object_metadata jsonb)
 RETURNS boolean
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare account uuid:=(select auth.uid()); new_size bigint; own_count bigint; own_size bigint; all_count bigint; all_size bigint;
begin
 if account is null or split_part(object_name,'/',1)<>account::text or object_name !~ '^[0-9a-f-]{36}/[0-9a-f-]{36}$' or not exists(select 1 from public.profiles where id=account) then return false; end if;
 new_size:=case when coalesce(object_metadata->>'size','') ~ '^[0-9]{1,10}$' then (object_metadata->>'size')::bigint else 26214400 end;
 if new_size>26214400 then return false; end if;
 perform pg_catalog.pg_advisory_xact_lock(70911703);
 select count(*),coalesce(sum(case when coalesce(metadata->>'size','') ~ '^[0-9]{1,10}$' then (metadata->>'size')::bigint else 26214400 end),0),
 count(*) filter(where split_part(name,'/',1)=account::text),
 coalesce(sum(case when coalesce(metadata->>'size','') ~ '^[0-9]{1,10}$' then (metadata->>'size')::bigint else 26214400 end) filter(where split_part(name,'/',1)=account::text),0)
 into all_count,all_size,own_count,own_size from storage.objects where bucket_id='mail-attachments';
 return own_count<100 and own_size+new_size<=104857600 and all_count<5000 and all_size+new_size<=734003200;
end $function$

