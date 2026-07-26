import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { validateRoot } from './check-react-version-alignment.mjs';

function writeJson(path, value) {
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

function createFixture({
  catalogReact = '19.2.7',
  catalogReactDom = '19.2.7',
  appDependencies = { react: 'catalog:', 'react-dom': 'catalog:' },
  extraPackages = [],
  lockReactVersions = ['19.2.7'],
  lockReactDomVersions = ['19.2.7'],
} = {}) {
  const root = mkdtempSync(join(tmpdir(), 'react-alignment-'));
  mkdirSync(join(root, 'apps', 'web-console'), { recursive: true });
  const packagePatterns = ['apps/*'];

  writeJson(join(root, 'package.json'), {
    name: 'fixture-root',
    private: true,
  });
  writeJson(join(root, 'apps', 'web-console', 'package.json'), {
    name: '@fixture/web-console',
    private: true,
    dependencies: appDependencies,
  });

  for (const fixturePackage of extraPackages) {
    const packageDir = join(root, fixturePackage.dir);
    mkdirSync(packageDir, { recursive: true });
    packagePatterns.push(fixturePackage.pattern ?? fixturePackage.dir);
    writeJson(join(packageDir, 'package.json'), fixturePackage.manifest);
  }

  writeFileSync(
    join(root, 'pnpm-workspace.yaml'),
    [
      'packages:',
      ...packagePatterns.map((pattern) => `  - "${pattern.replaceAll('\\', '/')}"`),
      '',
      'catalog:',
      `  react: ${catalogReact}`,
      `  react-dom: ${catalogReactDom}`,
      '',
    ].join('\n'),
    'utf8',
  );

  const lockLines = [
    'lockfileVersion: "9.0"',
    '',
    'packages:',
    ...lockReactVersions.map((version) => `  react@${version}:`),
    ...lockReactDomVersions.map((version) => `  react-dom@${version}(react@${lockReactVersions[0] ?? version}):`),
    '',
    'snapshots:',
    ...lockReactDomVersions.map((version) => `  react-dom@${version}(react@${lockReactVersions[0] ?? version}): {}`),
    '',
  ];
  writeFileSync(join(root, 'pnpm-lock.yaml'), lockLines.join('\n'), 'utf8');
  return root;
}

test('passes when React and React-DOM declarations and lockfile versions match', () => {
  const result = validateRoot(createFixture());
  assert.equal(result.valid, true, JSON.stringify(result.issues));
  assert.equal(result.react, '19.2.7');
  assert.equal(result.reactDom, '19.2.7');
});

test('fails when React and React-DOM catalog versions differ', () => {
  const result = validateRoot(createFixture({ catalogReact: '19.2.8', catalogReactDom: '19.2.7' }));
  assert.equal(result.valid, false);
  assert.equal(result.issues.some((issue) => issue.code === 'catalog_versions_must_match_exactly'), true);
});

test('fails when declared version constraints differ', () => {
  const result = validateRoot(
    createFixture({
      appDependencies: { react: '^19.2.7', 'react-dom': '19.2.7' },
    }),
  );
  assert.equal(result.valid, false);
  assert.equal(result.issues.some((issue) => issue.code === 'declaration_constraints_must_match_exactly'), true);
});

test('fails when lockfile resolved versions differ', () => {
  const result = validateRoot(
    createFixture({
      lockReactVersions: ['19.2.8'],
      lockReactDomVersions: ['19.2.7'],
    }),
  );
  assert.equal(result.valid, false);
  assert.equal(result.issues.some((issue) => issue.code === 'runtime_versions_must_match_exactly'), true);
});

test('fails when multiple production React runtime instances are resolved', () => {
  const result = validateRoot(
    createFixture({
      lockReactVersions: ['19.2.7', '19.2.8'],
      lockReactDomVersions: ['19.2.7'],
    }),
  );
  assert.equal(result.valid, false);
  assert.equal(result.issues.some((issue) => issue.code === 'multiple_react_runtime_instances'), true);
});

test('does not treat dev-only React fixture declarations as production runtime instances', () => {
  const result = validateRoot(
    createFixture({
      extraPackages: [
        {
          dir: join('packages', 'test-helper'),
          pattern: 'packages/*',
          manifest: {
            name: '@fixture/test-helper',
            private: true,
            devDependencies: {
              react: '19.2.8',
            },
          },
        },
      ],
    }),
  );
  assert.equal(result.valid, true, JSON.stringify(result.issues));
});

test('fails when a production workspace declares only one React runtime package', () => {
  const result = validateRoot(
    createFixture({
      appDependencies: { react: 'catalog:' },
    }),
  );
  assert.equal(result.valid, false);
  assert.equal(result.issues.some((issue) => issue.code === 'missing_pair_dependency'), true);
});
