// Only reuse completed, successful main-branch push runs from this repository.
// PR artifacts and same-branch/different-commit artifacts are never candidates.
module.exports = async function findTestedRun({github, context, core, sha, isas,
  attempts = 30, sleep = ms => new Promise(resolve => setTimeout(resolve, ms))}) {
  const repo = context.repo;
  const required = new Set(['tested-commit', ...isas.map(isa => `ela-${isa}`)]);
  for (let attempt = 0; attempt < attempts; attempt++) {
    const runs = await github.paginate(github.rest.actions.listWorkflowRuns, {
      ...repo, workflow_id: 'agent-tests.yml', head_sha: sha,
      branch: 'main', event: 'push', per_page: 100,
    });
    let pending = false;
    for (const run of runs) {
      if (run.head_sha !== sha || run.event !== 'push' || run.head_branch !== 'main' ||
          run.head_repository?.full_name !== `${repo.owner}/${repo.repo}`) continue;
      if (run.status !== 'completed') {
        pending = true;
        continue;
      }
      if (run.conclusion !== 'success') continue;
      const artifacts = await github.paginate(github.rest.actions.listWorkflowRunArtifacts,
        {...repo, run_id: run.id, per_page: 100});
      const available = new Set(artifacts.filter(a => !a.expired).map(a => a.name));
      if ([...required].every(name => available.has(name))) {
        core.info(`Reusing tested artifacts from run ${run.id} for ${sha}`);
        return String(run.id);
      }
    }
    if (!pending || attempt === attempts - 1) break;
    core.info('The push run for this commit is still testing; waiting 30 seconds.');
    await sleep(30000);
  }
  core.info('No reusable complete artifact set; a full build and test run is required.');
  return '';
};
