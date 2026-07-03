-- dMAT.prep — Supabase database setup
--
-- Run this entire script once in your Supabase project's SQL Editor
-- (left sidebar -> SQL Editor -> New query -> paste this -> Run).
--
-- I cannot run this myself — I have no execution access to your database.
-- This script has NOT been tested against a live database; verify it runs
-- without error and that the RLS policies behave as expected before relying
-- on them with real user data.
--
-- Patterns here follow Supabase's own documented RLS conventions as of
-- 03 Jul 2026 (supabase.com/docs/guides/database/postgres/row-level-security):
-- explicit ENABLE ROW LEVEL SECURITY, separate policies per operation (not
-- FOR ALL), and (select auth.uid()) wrapping for query-plan caching.

-- 1. Table: one row per user, linked 1:1 to Supabase's built-in auth.users table.
create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  name text not null,
  email text not null,
  plan text not null default 'free' check (plan in ('free', 'practice')),
  created_at timestamptz not null default now()
);

-- 2. Enable RLS. Without this line, the table is either fully open or fully
-- locked with no in-between — Supabase docs are explicit that this step is
-- required and not automatic for tables created via SQL (only automatic for
-- tables created through the dashboard's Table Editor UI).
alter table public.profiles enable row level security;

-- 3. Policies: a user may only see, create, and update their OWN row —
-- never another user's. Kept as separate SELECT / INSERT / UPDATE policies
-- per Supabase's current recommendation, rather than one FOR ALL policy.

drop policy if exists "Users can view their own profile" on public.profiles;
create policy "Users can view their own profile"
  on public.profiles
  for select
  to authenticated
  using ( (select auth.uid()) = id );

drop policy if exists "Users can insert their own profile" on public.profiles;
create policy "Users can insert their own profile"
  on public.profiles
  for insert
  to authenticated
  with check ( (select auth.uid()) = id );

drop policy if exists "Users can update their own profile" on public.profiles;
create policy "Users can update their own profile"
  on public.profiles
  for update
  to authenticated
  using ( (select auth.uid()) = id );

-- No DELETE policy is defined, so no one (other than an admin using the
-- secret/service key, which bypasses RLS entirely) can delete profile rows
-- through the public API. This is intentional, not an oversight — add one
-- explicitly if you want users to be able to delete their own account data.

-- 4. Auto-create a profile row whenever someone signs up via Supabase Auth,
-- so the app never has to manually insert into `profiles` after signUp().
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $func$
begin
  insert into public.profiles (id, name, email, plan)
  values (
    new.id,
    coalesce(new.raw_user_meta_data->>'name', ''),
    new.email,
    'free'
  );
  return new;
end;
$func$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();
