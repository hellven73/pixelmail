create function pixelmail_private.can_upload_attachment(object_name text, object_metadata jsonb) returns boolean language plpgsql security definer set search_path='' as $$
declare account uuid:=(select auth.uid()); new_size bigint; own_count bigint; own_size bigint; all_count bigint; all_size bigint;
begin
 if account is null or split_part(object_name,'/',1)<>account::text or object_name !~ '^[0-9a-f-]{36}/[0-9a-f-]{36}$' or not exists(select 1 from public.profiles where id=account) then return false; end if;
 if coalesce(object_metadata->>'size','') !~ '^[0-9]{1,10}$' then return false; end if;
 new_size:=(object_metadata->>'size')::bigint;
 if new_size>26214400 then return false; end if;
 perform pg_catalog.pg_advisory_xact_lock(70911703);
 select count(*),coalesce(sum(case when coalesce(metadata->>'size','') ~ '^[0-9]{1,10}$' then (metadata->>'size')::bigint else 26214400 end),0),
 count(*) filter(where split_part(name,'/',1)=account::text),
 coalesce(sum(case when coalesce(metadata->>'size','') ~ '^[0-9]{1,10}$' then (metadata->>'size')::bigint else 26214400 end) filter(where split_part(name,'/',1)=account::text),0)
 into all_count,all_size,own_count,own_size from storage.objects where bucket_id='mail-attachments';
 return own_count<100 and own_size+new_size<=104857600 and all_count<5000 and all_size+new_size<=734003200;
end $$;
revoke all on function pixelmail_private.can_upload_attachment(text,jsonb) from public,anon;
grant execute on function pixelmail_private.can_upload_attachment(text,jsonb) to authenticated;
drop policy pixelmail_upload on storage.objects;
create policy pixelmail_upload on storage.objects for insert to authenticated with check(bucket_id='mail-attachments' and pixelmail_private.can_upload_attachment(name,metadata));
create function pixelmail_private.can_delete_attachment(object_name text) returns boolean language plpgsql security definer set search_path='' as $$
begin
 if auth.uid() is null or split_part(object_name,'/',1)<>auth.uid()::text then return false; end if;
 perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(object_name,0));
 return not exists(select 1 from public.mailbox m where m.attachments @> jsonb_build_array(jsonb_build_object('path',object_name)));
end $$;
revoke all on function pixelmail_private.can_delete_attachment(text) from public,anon;
grant execute on function pixelmail_private.can_delete_attachment(text) to authenticated;
create policy pixelmail_delete_unreferenced on storage.objects for delete to authenticated using(bucket_id='mail-attachments' and pixelmail_private.can_delete_attachment(name));
