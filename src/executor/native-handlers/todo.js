'use strict';

/**
 * Native handlers for the TodoWrite / TodoRead tools.
 *
 * Pure functions over a caller-owned mutable `todoStore` array. No I/O,
 * no globals — the session owns the store; this module only mutates it.
 *
 * Extracted from src/runtime.js as Stage-2 of the executor migration
 * (see docs/ADAPTER-STAGE-2-MIGRATION.md). src/runtime.js re-exports
 * these so existing consumers (src/interceptor.js, tests) keep working
 * unchanged.
 */

/**
 * Returns true when this TodoWrite/TodoRead call can be served natively.
 * TodoRead: always handleable — no required inputs.
 * TodoWrite: requires input.todos to be an array.
 */
function isTodoHandleable(input, toolName) {
  if (toolName === 'TodoRead')  return true;
  if (toolName === 'TodoWrite') {
    if (!input || typeof input !== 'object') return false;
    return Array.isArray(input.todos);
  }
  return false;
}

/**
 * Handle a TodoWrite call: replace the session todo list with input.todos.
 * Returns { output: '', exitCode: 0, taskCount: N } on success.
 * Claude Code expects an empty-string response from write tools.
 */
function handleTodoWriteTool(input, todoStore) {
  const todos = input?.todos;
  if (!Array.isArray(todos)) {
    return { output: 'TodoWrite: todos must be an array', exitCode: 1, taskCount: 0 };
  }
  todoStore.splice(0, todoStore.length, ...todos);
  return { output: '', exitCode: 0, taskCount: todos.length };
}

/**
 * Handle a TodoRead call: return the session todo list as a JSON string.
 * Returns { output: string, exitCode: 0, taskCount: N }.
 */
function handleTodoReadTool(todoStore) {
  const output = JSON.stringify(todoStore, null, 2);
  return { output, exitCode: 0, taskCount: todoStore.length };
}

module.exports = {
  isTodoHandleable,
  handleTodoWriteTool,
  handleTodoReadTool,
};
