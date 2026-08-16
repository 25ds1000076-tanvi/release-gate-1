const { checkReleaseGate } = require("./server.js");

function basePayload(overrides = {}) {
  return {
    target: "preview",
    event: "pull_request",
    ref: "refs/heads/feature",
    workflow: {
      trigger: "pull_request",
      permissions: { contents: "read", packages: "write", "id-token": "none" },
      testsPassed: true,
      matrixComplete: true,
      failFast: false,
      actions: [{ owner: "actions", name: "checkout", ref: "v4" }],
    },
    image: {
      multiStage: true,
      runsAsRoot: false,
      secretMode: "none",
      criticalVulnerabilities: 0,
      digestPinned: true,
    },
    ...overrides,
  };
}

let passed = 0;
let failed = 0;

function expect(name, actual, expected) {
  const a = JSON.stringify([...actual].sort());
  const e = JSON.stringify([...expected].sort());
  if (a === e) {
    console.log(`PASS: ${name}`);
    passed++;
  } else {
    console.log(`FAIL: ${name}\n  expected ${e}\n  got      ${a}`);
    failed++;
  }
}

// 1. Fully safe payload -> no violations
expect("safe payload", checkReleaseGate(basePayload()), []);

// 2. Excess permission (extra key)
expect(
  "excess permission (extra key)",
  checkReleaseGate(
    basePayload({
      workflow: {
        ...basePayload().workflow,
        permissions: { contents: "read", packages: "write", "id-token": "none", actions: "write" },
      },
    })
  ),
  ["EXCESS_PERMISSION"]
);

// 3. Excess permission (wrong value)
expect(
  "excess permission (wrong value)",
  checkReleaseGate(
    basePayload({
      workflow: {
        ...basePayload().workflow,
        permissions: { contents: "write", packages: "write", "id-token": "none" },
      },
    })
  ),
  ["EXCESS_PERMISSION"]
);

// 4. Unsafe PR trigger
expect(
  "unsafe pr trigger",
  checkReleaseGate(
    basePayload({ workflow: { ...basePayload().workflow, trigger: "pull_request_target" } })
  ),
  ["UNSAFE_PR_TRIGGER"]
);

// 5. Tests incomplete (failFast true)
expect(
  "tests incomplete (failFast)",
  checkReleaseGate(basePayload({ workflow: { ...basePayload().workflow, failFast: true } })),
  ["TESTS_INCOMPLETE"]
);

// 6. Tests incomplete (matrix not complete)
expect(
  "tests incomplete (matrix)",
  checkReleaseGate(
    basePayload({ workflow: { ...basePayload().workflow, matrixComplete: false } })
  ),
  ["TESTS_INCOMPLETE"]
);

// 7. Mutable action (third-party with tag instead of SHA)
expect(
  "mutable action",
  checkReleaseGate(
    basePayload({
      workflow: {
        ...basePayload().workflow,
        actions: [{ owner: "someorg", name: "some-action", ref: "v1" }],
      },
    })
  ),
  ["MUTABLE_ACTION"]
);

// 8. Third-party action pinned correctly -> no violation
expect(
  "third-party action pinned to sha",
  checkReleaseGate(
    basePayload({
      workflow: {
        ...basePayload().workflow,
        actions: [{ owner: "someorg", name: "some-action", ref: "a".repeat(40) }],
      },
    })
  ),
  []
);

// 9. Single stage image
expect(
  "single stage image",
  checkReleaseGate(basePayload({ image: { ...basePayload().image, multiStage: false } })),
  ["SINGLE_STAGE_IMAGE"]
);

// 10. Root runtime
expect(
  "root runtime",
  checkReleaseGate(basePayload({ image: { ...basePayload().image, runsAsRoot: true } })),
  ["ROOT_RUNTIME"]
);

// 11. Secret in layer (arg)
expect(
  "secret in layer (arg)",
  checkReleaseGate(basePayload({ image: { ...basePayload().image, secretMode: "arg" } })),
  ["SECRET_IN_LAYER"]
);

// 12. Secret in layer (copy)
expect(
  "secret in layer (copy)",
  checkReleaseGate(basePayload({ image: { ...basePayload().image, secretMode: "copy" } })),
  ["SECRET_IN_LAYER"]
);

// 13. BuildKit secret mode is safe
expect(
  "buildkit secret mode safe",
  checkReleaseGate(basePayload({ image: { ...basePayload().image, secretMode: "buildkit" } })),
  []
);

// 14. Critical CVE
expect(
  "critical cve",
  checkReleaseGate(
    basePayload({ image: { ...basePayload().image, criticalVulnerabilities: 3 } })
  ),
  ["CRITICAL_CVE"]
);

// 15. Unpinned image
expect(
  "unpinned image",
  checkReleaseGate(basePayload({ image: { ...basePayload().image, digestPinned: false } })),
  ["UNPINNED_IMAGE"]
);

// 16. Production requires push to main
expect(
  "production invalid ref (wrong branch)",
  checkReleaseGate(
    basePayload({
      target: "production",
      event: "push",
      ref: "refs/heads/develop",
      workflow: { ...basePayload().workflow, environmentApproval: true },
    })
  ),
  ["INVALID_PRODUCTION_REF"]
);

// 17. Production requires push event (not pull_request)
expect(
  "production invalid ref (wrong event)",
  checkReleaseGate(
    basePayload({
      target: "production",
      event: "pull_request",
      ref: "refs/heads/main",
      workflow: { ...basePayload().workflow, trigger: "pull_request", environmentApproval: true },
    })
  ),
  ["INVALID_PRODUCTION_REF"]
);

// 18. Production requires environmentApproval
expect(
  "production approval required",
  checkReleaseGate(
    basePayload({
      target: "production",
      event: "push",
      ref: "refs/heads/main",
      workflow: { ...basePayload().workflow, environmentApproval: false },
    })
  ),
  ["APPROVAL_REQUIRED"]
);

// 19. Fully valid production payload -> no violations
expect(
  "valid production payload",
  checkReleaseGate(
    basePayload({
      target: "production",
      event: "push",
      ref: "refs/heads/main",
      workflow: { ...basePayload().workflow, environmentApproval: true },
    })
  ),
  []
);

// 20. Multi-failure combination
expect(
  "multi-failure combination",
  checkReleaseGate(
    basePayload({
      target: "production",
      event: "pull_request",
      ref: "refs/heads/develop",
      workflow: {
        trigger: "pull_request_target",
        permissions: { contents: "read", packages: "write", "id-token": "write" },
        testsPassed: false,
        matrixComplete: false,
        failFast: true,
        actions: [{ owner: "someorg", name: "bad-action", ref: "main" }],
        environmentApproval: false,
      },
      image: {
        multiStage: false,
        runsAsRoot: true,
        secretMode: "copy",
        criticalVulnerabilities: 2,
        digestPinned: false,
      },
    })
  ),
  [
    "EXCESS_PERMISSION",
    "UNSAFE_PR_TRIGGER",
    "TESTS_INCOMPLETE",
    "MUTABLE_ACTION",
    "SINGLE_STAGE_IMAGE",
    "ROOT_RUNTIME",
    "SECRET_IN_LAYER",
    "CRITICAL_CVE",
    "UNPINNED_IMAGE",
    "INVALID_PRODUCTION_REF",
    "APPROVAL_REQUIRED",
  ]
);

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
