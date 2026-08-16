const express = require("express");
const app = express();
app.use(express.json());

const SHA40 = /^[0-9a-f]{40}$/;

function checkReleaseGate(body) {
  const violations = [];
  const { target, event, ref, workflow = {}, image = {} } = body || {};

  // 1. Permissions must be exactly this set, nothing more, nothing less
  const perms = workflow.permissions || {};
  const requiredPerms = { contents: "read", packages: "write", "id-token": "none" };
  const permKeys = Object.keys(perms);
  const extraKeys = permKeys.filter((k) => !(k in requiredPerms));
  const mismatch = Object.entries(requiredPerms).some(([k, v]) => perms[k] !== v);
  if (extraKeys.length > 0 || mismatch) {
    violations.push("EXCESS_PERMISSION");
  }

  // 2. pull_request_target is never allowed
  if (workflow.trigger === "pull_request_target") {
    violations.push("UNSAFE_PR_TRIGGER");
  }

  // 3. Tests must fully pass
  if (!workflow.testsPassed || !workflow.matrixComplete || workflow.failFast === true) {
    violations.push("TESTS_INCOMPLETE");
  }

  // 4. Third-party actions must be pinned to a full commit SHA
  const actions = workflow.actions || [];
  const hasMutableAction = actions.some((a) => {
    if (a.owner === "actions") return false; // official actions may use a tag
    return !SHA40.test(a.ref || "");
  });
  if (hasMutableAction) {
    violations.push("MUTABLE_ACTION");
  }

  // 5-9. Image hardening checks
  if (!image.multiStage) violations.push("SINGLE_STAGE_IMAGE");
  if (image.runsAsRoot) violations.push("ROOT_RUNTIME");
  if (image.secretMode === "arg" || image.secretMode === "copy") {
    violations.push("SECRET_IN_LAYER");
  }
  if ((image.criticalVulnerabilities || 0) > 0) violations.push("CRITICAL_CVE");
  if (!image.digestPinned) violations.push("UNPINNED_IMAGE");

  // 10-11. Production-only checks
  if (target === "production") {
    if (event !== "push" || ref !== "refs/heads/main") {
      violations.push("INVALID_PRODUCTION_REF");
    }
    if (workflow.environmentApproval !== true) {
      violations.push("APPROVAL_REQUIRED");
    }
  }

  return violations;
}

app.post("/release-gate", (req, res) => {
  const violations = checkReleaseGate(req.body);
  res.json({
    decision: violations.length === 0 ? "promote" : "block",
    violations,
  });
});

const PORT = process.env.PORT || 3000;
if (require.main === module) {
  app.listen(PORT, () => console.log(`Listening on ${PORT}`));
}

module.exports = { checkReleaseGate, app };
