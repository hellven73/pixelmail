create or replace function pixelmail_private.create_internal_profile() returns trigger language plpgsql security definer set search_path='' as $$
declare requested text;
begin
 if new.raw_app_meta_data->>'pixelmail_internal'='true' and not exists(select 1 from public.profiles where id=new.id) then
 requested:=split_part(new.email,'@',1);
 if new.email<>requested||'@pixelmail.invalid' or requested !~ '^[a-z0-9_]{3,24}$' or requested in ('admin','support','pixelmail','system','postmaster') then raise exception 'Invalid PixelMail address'; end if;
 insert into public.profiles(id,username) values(new.id,requested) on conflict(id) do nothing;
 end if;
 return new;
end $$;
create trigger pixelmail_internal_signup_metadata after update of raw_app_meta_data on auth.users for each row execute function pixelmail_private.create_internal_profile();
create function public.pixelmail_provision_profile(account_id uuid) returns void language plpgsql security definer set search_path='' as $$
declare requested text;
begin
 select split_part(email,'@',1) into requested from auth.users where id=account_id and raw_app_meta_data->>'pixelmail_internal'='true' and email ~ '^[a-z0-9_]{3,24}@pixelmail[.]invalid$';
 if requested is null or requested in ('admin','support','pixelmail','system','postmaster') then raise exception 'Invalid internal account'; end if;
 insert into public.profiles(id,username) values(account_id,requested) on conflict(id) do nothing;
end $$;
revoke all on function public.pixelmail_provision_profile(uuid) from public,anon,authenticated;
grant execute on function public.pixelmail_provision_profile(uuid) to service_role;
