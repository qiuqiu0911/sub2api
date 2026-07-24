-- 允许用户平台维度配额记录 Kiro，同时保留现有 Grok 平台。
--
-- 157_user_platform_quotas_add_grok 已将 Grok 加入约束；
-- 代码层和设置层支持 Kiro 后，运行时会在记账时插入 platform='kiro'。

ALTER TABLE user_platform_quotas
  DROP CONSTRAINT IF EXISTS user_platform_quotas_platform_check;

ALTER TABLE user_platform_quotas
  ADD CONSTRAINT user_platform_quotas_platform_check
  CHECK (platform IN ('anthropic', 'openai', 'gemini', 'antigravity', 'grok', 'kiro'));
