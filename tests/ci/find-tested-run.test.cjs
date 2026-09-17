const {test} = require('node:test');
const assert = require('node:assert/strict');
const findTestedRun = require('../../tools/ci/find-tested-run.cjs');

const run = {id: 42, head_sha: 'abc', head_branch: 'main', event: 'push',
  head_repository: {full_name: 'owner/repo'}, status: 'completed', conclusion: 'success'};
const artifacts = ['tested-commit', 'ela-x86_64', 'ela-arm32-le'].map(name => ({name, expired: false}));
function setup(runs, items = artifacts) {
  let sleeps = 0;
  const options = {
    github: {rest: {actions: {listWorkflowRuns: 'runs', listWorkflowRunArtifacts: 'artifacts'}},
      paginate: async (method, args) => {
        assert.equal(args.owner, 'owner');
        return method === 'runs' ? runs(sleeps) : items;
      }},
    context: {repo: {owner: 'owner', repo: 'repo'}}, core: {info() {}},
    sha: 'abc', isas: ['x86_64', 'arm32-le'], attempts: 2,
    sleep: async () => { sleeps++; },
  };
  return options;
}

test('reuses only successful, complete artifacts for the exact commit', async () => {
  assert.equal(await findTestedRun(setup(() => [run])), '42');
});
test('rejects foreign repositories, PRs, wrong commits, branches and failed runs', async () => {
  for (const change of [{head_sha: 'other'}, {event: 'pull_request'}, {head_branch: 'topic'},
    {head_repository: {full_name: 'attacker/repo'}}, {conclusion: 'failure'}, {conclusion: 'cancelled'}]) {
    assert.equal(await findTestedRun(setup(() => [{...run, ...change}])), '');
  }
});
test('missing manifest, incomplete matrix and expired artifacts require a rebuild', async () => {
  for (const items of [artifacts.slice(1), artifacts.slice(0, 2),
    artifacts.map(a => ({...a, expired: a.name === 'ela-x86_64'}))]) {
    assert.equal(await findTestedRun(setup(() => [run], items)), '');
  }
});
test('waits for a matching push instead of immediately duplicating its builds', async () => {
  const options = setup(sleeps => [{...run, status: sleeps ? 'completed' : 'in_progress'}]);
  assert.equal(await findTestedRun(options), '42');
});
test('bounded waiting falls back to a full build if a push never finishes', async () => {
  assert.equal(await findTestedRun(setup(() => [{...run, status: 'in_progress'}])) , '');
});
test('a successful API-only run without C artifacts falls back immediately', async () => {
  const options = setup(() => [run], []);
  options.sleep = () => assert.fail('should not wait for a completed run');
  assert.equal(await findTestedRun(options), '');
});
