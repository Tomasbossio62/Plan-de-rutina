-- PLAN DE RUTINA · Instalación inicial en un proyecto propio de Supabase.
-- 1. Authentication > Users > Add user: crear SOLO tu usuario administrador.
-- 2. Reemplazar TU_CORREO_AQUI al final por el correo de ese usuario.
-- 3. Ejecutar este archivo completo en SQL Editor.
-- 4. Desactivar nuevos registros en Authentication > Providers > Email.
-- Nunca colocar service_role ni secret keys en el sitio.
begin;
create table if not exists public.plan_admins (
 user_id uuid primary key references auth.users(id) on delete cascade
);
alter table public.plan_admins enable row level security;
revoke all on public.plan_admins from anon, authenticated;
create or replace function public.is_plan_admin() returns boolean
language sql stable security definer set search_path = '' as $$
 select exists(select 1 from public.plan_admins where user_id = auth.uid());
$$;
revoke all on function public.is_plan_admin() from public;
grant execute on function public.is_plan_admin() to authenticated;
create table if not exists public.exercises (
 id uuid primary key,
 content jsonb not null check(jsonb_typeof(content) = 'object' and octet_length(content::text) < 20000),
 created_at timestamptz not null default now()
);
create table if not exists public.routines (
 id uuid primary key,
 label text not null check(length(label) between 1 and 80),
 token text not null unique check(length(token) between 40 and 100),
 items jsonb not null check(jsonb_typeof(items)='array' and octet_length(items::text) < 250000),
 note text not null default '' check(length(note)<=1500),
 active boolean not null default true,
 revision integer not null default 1,
 updated_at timestamptz not null default now()
);
create table if not exists public.routine_history (
 id bigint generated always as identity primary key,
 routine_id uuid not null references public.routines(id) on delete cascade,
 revision integer not null,
 label text not null,
 items jsonb not null,
 note text not null,
 created_at timestamptz not null,
 unique(routine_id,revision)
);
alter table public.exercises enable row level security;
alter table public.routines enable row level security;
alter table public.routine_history enable row level security;
revoke all on public.exercises,public.routines,public.routine_history from anon,authenticated;
grant select,insert,update,delete on public.exercises to authenticated;
grant select on public.routines,public.routine_history to authenticated;
drop policy if exists admin_exercises on public.exercises;
create policy admin_exercises on public.exercises for all to authenticated using(public.is_plan_admin()) with check(public.is_plan_admin());
drop policy if exists admin_routines_read on public.routines;
create policy admin_routines_read on public.routines for select to authenticated using(public.is_plan_admin());
drop policy if exists admin_history_read on public.routine_history;
create policy admin_history_read on public.routine_history for select to authenticated using(public.is_plan_admin());
create or replace function public.save_routine(
 p_id uuid,p_label text,p_token text,p_items jsonb,p_note text,p_active boolean,p_expected_revision integer
) returns jsonb language plpgsql security definer set search_path='' as $$
declare old public.routines; next_rev integer; ts timestamptz := now(); item jsonb;
begin
 if not public.is_plan_admin() then raise exception 'Acceso no autorizado' using errcode='42501'; end if;
 if p_label is null or length(trim(p_label)) not between 1 and 80 or
    p_note is null or length(p_note)>1500 or p_items is null or jsonb_typeof(p_items)<>'array' or
    jsonb_array_length(p_items) not between 1 and 150 or octet_length(p_items::text)>250000 or
    p_expected_revision is null or p_expected_revision<0 or p_token is null or p_token !~ '^[a-zA-Z0-9-]{40,100}$' or p_active is null then
   raise exception 'Revisá los datos de la rutina';
 end if;
 for item in select * from jsonb_array_elements(p_items) loop
  if jsonb_typeof(item)<>'object' or item->'exercise' is null or
     coalesce(item->'exercise'->>'name','')='' or
     coalesce(item->'exercise'->>'url','') !~ '^https://' or
     coalesce(item->'exercise'->>'block','') not in ('Movilidad','Fuerza','Equilibrio','Salto','Control motor','Potencia','Acondicionamiento','Edema','Trote') then
    raise exception 'Cada ejercicio debe tener nombre, bloque y video HTTPS';
  end if;
 end loop;
 -- Serializar guardados del mismo plan incluso durante la creación.
 perform pg_advisory_xact_lock(hashtextextended(p_id::text,0));
 select * into old from public.routines where id=p_id for update;
 if found then
  if old.revision<>p_expected_revision then raise exception 'CONFLICT: la rutina cambió en otro dispositivo'; end if;
  if old.label=trim(p_label) and old.items=p_items and old.note=p_note and old.active=p_active then
   return jsonb_build_object('revision',old.revision,'updated_at',old.updated_at);
  end if;
  insert into public.routine_history(routine_id,revision,label,items,note,created_at)
  values(old.id,old.revision,old.label,old.items,old.note,old.updated_at);
  next_rev:=old.revision+1;
  update public.routines set label=trim(p_label),items=p_items,note=p_note,active=p_active,revision=next_rev,updated_at=ts where id=p_id;
 else
  if p_expected_revision<>0 then raise exception 'CONFLICT: la rutina no está disponible'; end if;
  next_rev:=1;
  insert into public.routines(id,label,token,items,note,active,revision,updated_at)
  values(p_id,trim(p_label),p_token,p_items,p_note,p_active,next_rev,ts);
 end if;
 return jsonb_build_object('revision',next_rev,'updated_at',ts);
end; $$;
revoke all on function public.save_routine(uuid,text,text,jsonb,text,boolean,integer) from public;
grant execute on function public.save_routine(uuid,text,text,jsonb,text,boolean,integer) to authenticated;
-- Un único plan por nombre completo; para actualizar se edita el mismo plan.
create unique index if not exists plan_unique_patient_name on public.routines(lower(regexp_replace(trim(label),'\s+',' ','g')));
-- El paciente puede consultar un solo plan conociendo su token.
-- Nunca se publica una lista de pacientes ni el historial.
create or replace function public.get_patient_routine(p_token text) returns jsonb
language sql stable security definer set search_path='' as $$
 select jsonb_build_object('label',label,'items',items,'note',note,'updated_at',updated_at)
 from public.routines where token=p_token and active=true and length(p_token) between 40 and 100;
$$;
revoke all on function public.get_patient_routine(text) from public;
grant execute on function public.get_patient_routine(text) to anon,authenticated;

-- Gestión explícita de rutinas e historial. Ninguna de estas funciones es pública.
create or replace function public.delete_plan_routine(p_id uuid,p_expected_revision integer) returns void
language plpgsql security definer set search_path='' as $$
declare current_revision integer;
begin
 if not public.is_plan_admin() then raise exception 'Acceso no autorizado' using errcode='42501'; end if;
 perform pg_advisory_xact_lock(hashtextextended(p_id::text,0));
 select revision into current_revision from public.routines where id=p_id for update;
 if not found then raise exception 'La rutina no existe'; end if;
 if p_expected_revision is null or current_revision<>p_expected_revision then raise exception 'CONFLICT: la rutina cambió en otro dispositivo'; end if;
 delete from public.routines where id=p_id;
end $$;
revoke all on function public.delete_plan_routine(uuid,integer) from public,anon,authenticated;
grant execute on function public.delete_plan_routine(uuid,integer) to authenticated;
create or replace function public.delete_plan_history(p_id uuid,p_revision integer) returns integer
language plpgsql security definer set search_path='' as $$
declare n integer;
begin
 if not public.is_plan_admin() then raise exception 'Acceso no autorizado' using errcode='42501'; end if;
 perform pg_advisory_xact_lock(hashtextextended(p_id::text,0));
 delete from public.routine_history where routine_id=p_id and (p_revision is null or revision=p_revision);
 get diagnostics n=row_count;
 return n;
end $$;
revoke all on function public.delete_plan_history(uuid,integer) from public,anon,authenticated;
grant execute on function public.delete_plan_history(uuid,integer) to authenticated;
create or replace function public.get_plan_video_references() returns jsonb
language plpgsql stable security definer set search_path='' as $$
declare result jsonb;
begin
 if not public.is_plan_admin() then raise exception 'Acceso no autorizado' using errcode='42501'; end if;
 select coalesce(jsonb_agg(distinct u),'[]'::jsonb) into result from (
  select content->>'url' u from public.exercises
  union all select item->'exercise'->>'url' from public.routines r cross join lateral jsonb_array_elements(r.items) item
  union all select item->'exercise'->>'url' from public.routine_history h cross join lateral jsonb_array_elements(h.items) item
 ) refs where u is not null;
 return result;
end $$;
revoke all on function public.get_plan_video_references() from public,anon,authenticated;
grant execute on function public.get_plan_video_references() to authenticated;
create or replace function public.plan_video_is_used(p_name text) returns boolean
language sql stable security definer set search_path='' as $$
 select exists(select 1 from (
  select content->>'url' u from public.exercises
  union all select item->'exercise'->>'url' from public.routines r cross join lateral jsonb_array_elements(r.items) item
  union all select item->'exercise'->>'url' from public.routine_history h cross join lateral jsonb_array_elements(h.items) item
 ) refs where right(u,length('/exercise-videos/'||p_name))='/exercise-videos/'||p_name);
$$;
revoke all on function public.plan_video_is_used(text) from public,anon,authenticated;
grant execute on function public.plan_video_is_used(text) to authenticated;

-- Los videos son recursos de ejercicios, sin datos de pacientes.
-- Son públicos para permitir reproducción sin cuentas; NO subir material confidencial.
insert into storage.buckets(id,name,public,file_size_limit,allowed_mime_types)
values('exercise-videos','exercise-videos',true,52428800,array['video/mp4','video/webm','video/quicktime'])
on conflict(id) do nothing;
drop policy if exists plan_admin_video_insert on storage.objects;
create policy plan_admin_video_insert on storage.objects for insert to authenticated
with check(bucket_id='exercise-videos' and public.is_plan_admin());
drop policy if exists plan_admin_video_select on storage.objects;
create policy plan_admin_video_select on storage.objects for select to authenticated
using(bucket_id='exercise-videos' and public.is_plan_admin());
drop policy if exists plan_admin_video_delete on storage.objects;
create policy plan_admin_video_delete on storage.objects for delete to authenticated
using(bucket_id='exercise-videos' and public.is_plan_admin() and not public.plan_video_is_used(name));
-- Este paso falla a propósito si no configuraste el correo o no creaste el usuario.
do $$
declare admin_id uuid;
begin
 select id into admin_id from auth.users where lower(email)=lower('TU_CORREO_AQUI');
 if admin_id is null then raise exception 'Primero creá tu usuario en Authentication y reemplazá TU_CORREO_AQUI por su correo.'; end if;
 insert into public.plan_admins(user_id) values(admin_id) on conflict do nothing;
end $$;
commit;
