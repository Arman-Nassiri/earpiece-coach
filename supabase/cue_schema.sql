create extension if not exists pgcrypto;

create or replace function public.set_updated_at()
returns trigger
language plpgsql
as $$
begin
  new.updated_at = timezone('utc', now());
  return new;
end;
$$;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text,
  display_name text,
  onboarding_complete boolean not null default false,
  created_at timestamptz not null default timezone('utc', now()),
  updated_at timestamptz not null default timezone('utc', now())
);

create table if not exists public.billing_accounts (
  user_id uuid primary key references auth.users(id) on delete cascade,
  plan_tier text not null default 'free',
  plan_status text not null default 'inactive',
  stripe_customer_id text unique,
  stripe_subscription_id text unique,
  current_period_end timestamptz,
  created_at timestamptz not null default timezone('utc', now()),
  updated_at timestamptz not null default timezone('utc', now()),
  constraint billing_accounts_plan_status_check check (plan_status in ('inactive', 'trialing', 'active', 'past_due', 'canceled')),
  constraint billing_accounts_plan_tier_check check (plan_tier in ('free', 'private', 'team'))
);

create table if not exists public.user_api_keys (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  provider text not null default 'openai',
  label text,
  encrypted_key text not null,
  key_last4 text not null,
  is_active boolean not null default true,
  created_at timestamptz not null default timezone('utc', now()),
  updated_at timestamptz not null default timezone('utc', now()),
  constraint user_api_keys_provider_check check (provider in ('openai'))
);

create table if not exists public.saved_scenarios (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  scenario_type text not null,
  name text not null,
  payload jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default timezone('utc', now()),
  updated_at timestamptz not null default timezone('utc', now())
);

create table if not exists public.negotiation_runs (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  mode text not null,
  scenario_name text not null,
  status text not null default 'completed',
  metadata jsonb not null default '{}'::jsonb,
  started_at timestamptz,
  ended_at timestamptz,
  created_at timestamptz not null default timezone('utc', now()),
  updated_at timestamptz not null default timezone('utc', now()),
  constraint negotiation_runs_mode_check check (mode in ('practice_text', 'practice_voice', 'live')),
  constraint negotiation_runs_status_check check (status in ('draft', 'in_progress', 'completed', 'failed'))
);

create table if not exists public.transcript_turns (
  id uuid primary key default gen_random_uuid(),
  run_id uuid not null references public.negotiation_runs(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  turn_index integer not null,
  speaker text not null,
  body text not null,
  created_at timestamptz not null default timezone('utc', now()),
  constraint transcript_turns_speaker_check check (speaker in ('user', 'ai', 'coach', 'counterparty')),
  constraint transcript_turns_order_unique unique (run_id, turn_index)
);

create table if not exists public.analysis_reports (
  id uuid primary key default gen_random_uuid(),
  run_id uuid not null unique references public.negotiation_runs(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  score text,
  verdict text,
  summary text,
  payload jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default timezone('utc', now()),
  updated_at timestamptz not null default timezone('utc', now())
);

create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.profiles (id, email, display_name)
  values (
    new.id,
    new.email,
    coalesce(new.raw_user_meta_data ->> 'display_name', '')
  )
  on conflict (id) do update
  set email = excluded.email,
      display_name = excluded.display_name,
      updated_at = timezone('utc', now());
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
after insert on auth.users
for each row execute procedure public.handle_new_user();

drop trigger if exists profiles_set_updated_at on public.profiles;
create trigger profiles_set_updated_at
before update on public.profiles
for each row execute procedure public.set_updated_at();

drop trigger if exists billing_accounts_set_updated_at on public.billing_accounts;
create trigger billing_accounts_set_updated_at
before update on public.billing_accounts
for each row execute procedure public.set_updated_at();

drop trigger if exists user_api_keys_set_updated_at on public.user_api_keys;
create trigger user_api_keys_set_updated_at
before update on public.user_api_keys
for each row execute procedure public.set_updated_at();

drop trigger if exists saved_scenarios_set_updated_at on public.saved_scenarios;
create trigger saved_scenarios_set_updated_at
before update on public.saved_scenarios
for each row execute procedure public.set_updated_at();

drop trigger if exists negotiation_runs_set_updated_at on public.negotiation_runs;
create trigger negotiation_runs_set_updated_at
before update on public.negotiation_runs
for each row execute procedure public.set_updated_at();

drop trigger if exists analysis_reports_set_updated_at on public.analysis_reports;
create trigger analysis_reports_set_updated_at
before update on public.analysis_reports
for each row execute procedure public.set_updated_at();

alter table public.profiles enable row level security;
alter table public.billing_accounts enable row level security;
alter table public.user_api_keys enable row level security;
alter table public.saved_scenarios enable row level security;
alter table public.negotiation_runs enable row level security;
alter table public.transcript_turns enable row level security;
alter table public.analysis_reports enable row level security;

drop policy if exists "profiles_own_all" on public.profiles;
create policy "profiles_own_all"
on public.profiles
for all
using (auth.uid() = id)
with check (auth.uid() = id);

drop policy if exists "billing_accounts_own_all" on public.billing_accounts;
create policy "billing_accounts_own_all"
on public.billing_accounts
for all
using (auth.uid() = user_id)
with check (auth.uid() = user_id);

drop policy if exists "user_api_keys_own_all" on public.user_api_keys;
create policy "user_api_keys_own_all"
on public.user_api_keys
for all
using (auth.uid() = user_id)
with check (auth.uid() = user_id);

drop policy if exists "saved_scenarios_own_all" on public.saved_scenarios;
create policy "saved_scenarios_own_all"
on public.saved_scenarios
for all
using (auth.uid() = user_id)
with check (auth.uid() = user_id);

drop policy if exists "negotiation_runs_own_all" on public.negotiation_runs;
create policy "negotiation_runs_own_all"
on public.negotiation_runs
for all
using (auth.uid() = user_id)
with check (auth.uid() = user_id);

drop policy if exists "transcript_turns_own_all" on public.transcript_turns;
create policy "transcript_turns_own_all"
on public.transcript_turns
for all
using (
  auth.uid() = user_id
  and exists (
    select 1
    from public.negotiation_runs runs
    where runs.id = run_id
      and runs.user_id = auth.uid()
  )
)
with check (
  auth.uid() = user_id
  and exists (
    select 1
    from public.negotiation_runs runs
    where runs.id = run_id
      and runs.user_id = auth.uid()
  )
);

drop policy if exists "analysis_reports_own_all" on public.analysis_reports;
create policy "analysis_reports_own_all"
on public.analysis_reports
for all
using (
  auth.uid() = user_id
  and exists (
    select 1
    from public.negotiation_runs runs
    where runs.id = run_id
      and runs.user_id = auth.uid()
  )
)
with check (
  auth.uid() = user_id
  and exists (
    select 1
    from public.negotiation_runs runs
    where runs.id = run_id
      and runs.user_id = auth.uid()
  )
);
