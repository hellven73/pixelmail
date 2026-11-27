create table pixelmail_private.signup_rate(id integer primary key check(id=1),window_start timestamptz not null,attempts integer not null);
alter table pixelmail_private.signup_rate enable row level security;
create function public.pixelmail_reserve_signup() returns boolean language plpgsql security definer set search_path='' as $$
declare n integer;
begin
 insert into pixelmail_private.signup_rate(id,window_start,attempts) values(1,now(),1)
 on conflict(id) do update set window_start=case when pixelmail_private.signup_rate.window_start<now()-interval '1 hour' then now() else pixelmail_private.signup_rate.window_start end,attempts=case when pixelmail_private.signup_rate.window_start<now()-interval '1 hour' then 1 else pixelmail_private.signup_rate.attempts+1 end returning attempts into n;
 return n<=30 and (select count(*) from public.profiles)<1000;
end $$;
revoke all on function public.pixelmail_reserve_signup() from public,anon,authenticated;
grant execute on function public.pixelmail_reserve_signup() to service_role;
create function pixelmail_private.create_internal_profile() returns trigger language plpgsql security definer set search_path='' as $$
declare requested text;
begin
 if new.raw_app_meta_data->>'pixelmail_internal'='true' then
 requested:=split_part(new.email,'@',1);
 if new.email<>requested||'@pixelmail.invalid' or requested !~ '^[a-z0-9_]{3,24}$' or requested in ('admin','support','pixelmail','system','postmaster') then raise exception 'Invalid PixelMail address'; end if;
 insert into public.profiles(id,username) values(new.id,requested);
 end if;
 return new;
end $$;
revoke all on function pixelmail_private.create_internal_profile() from public,anon,authenticated;
create trigger pixelmail_internal_signup after insert on auth.users for each row execute function pixelmail_private.create_internal_profile();
create or replace function pixelmail_private.claim_username(requested text) returns void language plpgsql security definer set search_path='' as $$
begin
 if auth.uid() is null or not exists(select 1 from auth.users where id=auth.uid() and email=requested||'@pixelmail.invalid' and raw_app_meta_data->>'pixelmail_internal'='true') then raise exception 'Use a registered PixelMail account'; end if;
 if requested is null or requested !~ '^[a-z0-9_]{3,24}$' or requested in ('admin','support','pixelmail','system','postmaster') then raise exception 'Choose a different username'; end if;
 insert into public.profiles(id,username) values(auth.uid(),requested);
exception when unique_violation then raise exception 'Username unavailable or already set';
end $$;
