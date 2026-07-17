BEGIN;

DROP TABLE IF EXISTS agent.dead_letters;
DROP TABLE IF EXISTS agent.queue_messages;
DROP TABLE IF EXISTS agent.task_executions;
DROP TABLE IF EXISTS agent.workflow_stages;
DROP TABLE IF EXISTS agent.workflow_definitions;
DROP TABLE IF EXISTS agent.agent_definitions;
DROP TABLE IF EXISTS agent.skill_definitions;

DROP SCHEMA IF EXISTS agent;

COMMIT;
