-- 新疆旅行助手 v0.4：轻量跨设备同步后端
-- 通过 security definer RPC 暴露最小能力；底表不对 anon/authenticated 直接开放。

create extension if not exists pgcrypto;

create table if not exists public.sync_profiles (
  id uuid primary key default gen_random_uuid(),
  nickname_normalized text not null,
  nickname_display text not null,
  pin_hash text not null,
  failed_attempts integer not null default 0,
  locked_until timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists sync_profiles_nickname_idx
  on public.sync_profiles (nickname_normalized);

create table if not exists public.user_states (
  profile_id uuid primary key references public.sync_profiles(id) on delete cascade,
  state jsonb not null default '{}'::jsonb,
  revision bigint not null default 1,
  updated_at timestamptz not null default now()
);

create table if not exists public.sync_sessions (
  id uuid primary key default gen_random_uuid(),
  profile_id uuid not null references public.sync_profiles(id) on delete cascade,
  token_hash text not null unique,
  expires_at timestamptz not null,
  created_at timestamptz not null default now()
);

create index if not exists sync_sessions_profile_idx
  on public.sync_sessions (profile_id);
create index if not exists sync_sessions_expiry_idx
  on public.sync_sessions (expires_at);

alter table public.sync_profiles enable row level security;
alter table public.user_states enable row level security;
alter table public.sync_sessions enable row level security;

revoke all on public.sync_profiles from anon, authenticated;
revoke all on public.user_states from anon, authenticated;
revoke all on public.sync_sessions from anon, authenticated;

create or replace function public.normalize_nickname(p_nickname text)
returns text
language sql
immutable
set search_path = public
as $$
  select lower(regexp_replace(trim(coalesce(p_nickname, '')), '\s+', ' ', 'g'));
$$;

create or replace function public.merge_state(p_cloud jsonb, p_local jsonb)
returns jsonb
language plpgsql
immutable
set search_path = public
as $$
declare
  cloud jsonb := coalesce(p_cloud, '{}'::jsonb);
  local_state jsonb := coalesce(p_local, '{}'::jsonb);
begin
  -- 首版服务端保存完整状态。不同设备提交时以客户端完整状态为准；
  -- revision 防止无提示覆盖，冲突时由 sync_state 返回云端状态供前端逐项合并后重试。
  return cloud || local_state || jsonb_build_object('schemaVersion', 2);
end;
$$;

create or replace function public.enter_sync(
  p_nickname text,
  p_pin text,
  p_initial_state jsonb default '{}'::jsonb
)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  v_norm text;
  v_profile public.sync_profiles%rowtype;
  v_state public.user_states%rowtype;
  v_token text;
  v_token_hash text;
  v_is_new boolean := false;
begin
  v_norm := public.normalize_nickname(p_nickname);
  if char_length(v_norm) < 1 or char_length(v_norm) > 24 then
    raise exception 'INVALID_NICKNAME';
  end if;
  if coalesce(p_pin, '') !~ '^[0-9]{6}$' then
    raise exception 'INVALID_PIN';
  end if;

  select * into v_profile
  from public.sync_profiles
  where nickname_normalized = v_norm
    and (locked_until is null or locked_until <= now())
    and pin_hash = crypt(p_pin, pin_hash)
  order by created_at asc
  limit 1;

  if not found then
    insert into public.sync_profiles(nickname_normalized, nickname_display, pin_hash)
    values (v_norm, trim(p_nickname), crypt(p_pin, gen_salt('bf', 10)))
    returning * into v_profile;

    insert into public.user_states(profile_id, state)
    values (v_profile.id, public.merge_state('{}'::jsonb, p_initial_state))
    returning * into v_state;
    v_is_new := true;
  else
    update public.sync_profiles
    set failed_attempts = 0, locked_until = null, updated_at = now()
    where id = v_profile.id;

    select * into v_state from public.user_states where profile_id = v_profile.id;
    if not found then
      insert into public.user_states(profile_id, state)
      values (v_profile.id, public.merge_state('{}'::jsonb, p_initial_state))
      returning * into v_state;
    end if;
  end if;

  delete from public.sync_sessions where expires_at <= now();
  v_token := encode(gen_random_bytes(32), 'hex');
  v_token_hash := encode(digest(v_token, 'sha256'), 'hex');
  insert into public.sync_sessions(profile_id, token_hash, expires_at)
  values (v_profile.id, v_token_hash, now() + interval '30 days');

  return jsonb_build_object(
    'ok', true,
    'is_new', v_is_new,
    'profile_id', v_profile.id,
    'nickname', v_profile.nickname_display,
    'session_token', v_token,
    'session_expires_at', now() + interval '30 days',
    'state', v_state.state,
    'revision', v_state.revision,
    'updated_at', v_state.updated_at
  );
end;
$$;

create or replace function public.get_sync_state(p_session_token text)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  v_profile_id uuid;
  v_state public.user_states%rowtype;
begin
  select profile_id into v_profile_id
  from public.sync_sessions
  where token_hash = encode(digest(coalesce(p_session_token, ''), 'sha256'), 'hex')
    and expires_at > now()
  limit 1;
  if v_profile_id is null then raise exception 'INVALID_SESSION'; end if;
  select * into v_state from public.user_states where profile_id = v_profile_id;
  return jsonb_build_object('ok', true, 'state', v_state.state, 'revision', v_state.revision, 'updated_at', v_state.updated_at);
end;
$$;

create or replace function public.put_sync_state(
  p_session_token text,
  p_state jsonb,
  p_base_revision bigint
)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  v_profile_id uuid;
  v_current public.user_states%rowtype;
  v_new public.user_states%rowtype;
begin
  select profile_id into v_profile_id
  from public.sync_sessions
  where token_hash = encode(digest(coalesce(p_session_token, ''), 'sha256'), 'hex')
    and expires_at > now()
  limit 1;
  if v_profile_id is null then raise exception 'INVALID_SESSION'; end if;

  select * into v_current from public.user_states where profile_id = v_profile_id for update;
  if v_current.revision <> p_base_revision then
    return jsonb_build_object('ok', false, 'conflict', true, 'state', v_current.state, 'revision', v_current.revision, 'updated_at', v_current.updated_at);
  end if;

  update public.user_states
  set state = public.merge_state(v_current.state, p_state),
      revision = revision + 1,
      updated_at = now()
  where profile_id = v_profile_id
  returning * into v_new;

  return jsonb_build_object('ok', true, 'conflict', false, 'state', v_new.state, 'revision', v_new.revision, 'updated_at', v_new.updated_at);
end;
$$;

create or replace function public.leave_sync(p_session_token text)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
begin
  delete from public.sync_sessions
  where token_hash = encode(digest(coalesce(p_session_token, ''), 'sha256'), 'hex');
  return jsonb_build_object('ok', true);
end;
$$;

revoke all on function public.enter_sync(text, text, jsonb) from public;
revoke all on function public.get_sync_state(text) from public;
revoke all on function public.put_sync_state(text, jsonb, bigint) from public;
revoke all on function public.leave_sync(text) from public;
grant execute on function public.enter_sync(text, text, jsonb) to anon, authenticated;
grant execute on function public.get_sync_state(text) to anon, authenticated;
grant execute on function public.put_sync_state(text, jsonb, bigint) to anon, authenticated;
grant execute on function public.leave_sync(text) to anon, authenticated;
