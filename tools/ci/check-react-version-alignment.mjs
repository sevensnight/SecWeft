#!/usr/bin/env node
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const REACT_PACKAGES = ['react', 'react-dom'];
const PRODUCTION_SECTIONS = ['dependencies', 'peerDependencies', 'optionalDependencies'];
const ALL_SECTIONS = [...PRODUCTION_SECTIONS, 'devDependencies'];

function readText(path) {
  return readFileSync(path, 'utf8');
}

function readJson(path) {
  return JSON.parse(readText(path));
}

function parseArgs(argv) {
  const args = { root: process.cwd(), json: false };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--root') {
      args.root = argv[index + 1];
      index += 1;
    } else if (arg === '--json') {
      args.json = true;
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }
  return args;
}

function parseCatalog(workspaceText) {
  const catalog = new Map();
  const lines = workspaceText.split(/\r?\n/);
  let inCatalog = false;
  for (const line of lines) {
    if (/^catalog:\s*$/.test(line)) {
      inCatalog = true;
      continue;
    }
    if (inCatalog && /^\S/.test(line)) {
      break;
    }
    if (!inCatalog) {
      continue;
    }
    const match = line.match(/^\s{2}(["']?)([^"':]+)\1:\s*(.+?)\s*$/);
    if (match) {
      catalog.set(match[2], match[3].replace(/^["']|["']$/g, ''));
    }
  }
  return catalog;
}

function parseWorkspacePatterns(workspaceText) {
  const patterns = [];
  const lines = workspaceText.split(/\r?\n/);
  let inPackages = false;
  for (const line of lines) {
    if (/^packages:\s*$/.test(line)) {
      inPackages = true;
      continue;
    }
    if (inPackages && /^\S/.test(line)) {
      break;
    }
    if (!inPackages) {
      continue;
    }
    const match = line.match(/^\s*-\s*["']?(.+?)["']?\s*$/);
    if (match) {
      patterns.push(match[1]);
    }
  }
  return patterns;
}

function expandSimpleWorkspacePattern(root, pattern) {
  const normalized = pattern.replaceAll('/', sep);
  if (!normalized.includes('*')) {
    return [resolve(root, normalized)];
  }
  const parts = normalized.split(sep);
  const starIndex = parts.indexOf('*');
  if (starIndex === -1 || parts.lastIndexOf('*') !== starIndex) {
    throw new Error(`Unsupported workspace pattern for React alignment check: ${pattern}`);
  }
  const prefix = resolve(root, ...parts.slice(0, starIndex));
  const suffix = parts.slice(starIndex + 1);
  let entries = [];
  try {
    entries = readdirSync(prefix, { withFileTypes: true });
  } catch {
    return [];
  }
  return entries
    .filter((entry) => entry.isDirectory())
    .map((entry) => resolve(prefix, entry.name, ...suffix));
}

function packageJsonPaths(root, workspaceText) {
  const paths = new Set([resolve(root, 'package.json')]);
  for (const pattern of parseWorkspacePatterns(workspaceText)) {
    for (const workspaceDir of expandSimpleWorkspacePattern(root, pattern)) {
      const packagePath = resolve(workspaceDir, 'package.json');
      try {
        if (statSync(packagePath).isFile()) {
          paths.add(packagePath);
        }
      } catch {
        // Missing workspace packages are ignored here; pnpm owns workspace existence validation.
      }
    }
  }
  return [...paths].sort();
}

function normalizeSpec(packageName, spec, catalog) {
  if (spec === 'catalog:') {
    return {
      raw: spec,
      resolved: catalog.get(packageName),
      source: 'catalog',
    };
  }
  return {
    raw: spec,
    resolved: spec,
    source: 'package',
  };
}

function findDeclarationIssues(root, catalog, paths) {
  const declarations = [];
  const issues = [];
  for (const packagePath of paths) {
    const manifest = readJson(packagePath);
    const packageName = manifest.name ?? relative(root, dirname(packagePath));
    const packageRelativePath = relative(root, packagePath).replaceAll(sep, '/');
    const hasProductionReactDeclaration = PRODUCTION_SECTIONS.some((section) => {
      const deps = manifest[section] ?? {};
      return deps.react !== undefined || deps['react-dom'] !== undefined;
    });

    for (const section of ALL_SECTIONS) {
      const deps = manifest[section] ?? {};
      const reactSpec = deps.react;
      const reactDomSpec = deps['react-dom'];
      const hasReact = reactSpec !== undefined;
      const hasReactDom = reactDomSpec !== undefined;
      const devOnlyReactDeclaration = section === 'devDependencies' && !hasProductionReactDeclaration;

      if (!hasReact && !hasReactDom) {
        continue;
      }
      if (devOnlyReactDeclaration && (hasReact || hasReactDom)) {
        declarations.push({
          package: packageName,
          path: packageRelativePath,
          section,
          devOnly: true,
          react: reactSpec ?? null,
          reactDom: reactDomSpec ?? null,
        });
        continue;
      }
      if (hasReact !== hasReactDom) {
        issues.push({
          code: 'missing_pair_dependency',
          package: packageName,
          path: packageRelativePath,
          section,
          react: reactSpec ?? null,
          reactDom: reactDomSpec ?? null,
        });
        continue;
      }

      const react = normalizeSpec('react', reactSpec, catalog);
      const reactDom = normalizeSpec('react-dom', reactDomSpec, catalog);
      declarations.push({
        package: packageName,
        path: packageRelativePath,
        section,
        devOnly: false,
        react: reactSpec,
        reactDom: reactDomSpec,
        reactResolved: react.resolved,
        reactDomResolved: reactDom.resolved,
      });
      if (react.raw !== reactDom.raw) {
        issues.push({
          code: 'declaration_constraints_must_match_exactly',
          package: packageName,
          path: packageRelativePath,
          section,
          react: react.raw,
          reactDom: reactDom.raw,
        });
      }
      if (react.source === 'catalog' && react.resolved === undefined) {
        issues.push({
          code: 'missing_catalog_entry',
          package: packageName,
          path: packageRelativePath,
          section,
          dependency: 'react',
        });
      }
      if (reactDom.source === 'catalog' && reactDom.resolved === undefined) {
        issues.push({
          code: 'missing_catalog_entry',
          package: packageName,
          path: packageRelativePath,
          section,
          dependency: 'react-dom',
        });
      }
      if (react.source === 'catalog' && reactDom.source === 'catalog' && react.resolved !== reactDom.resolved) {
        issues.push({
          code: 'catalog_versions_must_match_exactly',
          package: packageName,
          path: packageRelativePath,
          section,
          react: react.resolved,
          reactDom: reactDom.resolved,
        });
      }
    }
  }
  return { declarations, issues };
}

function collectLockVersions(lockText, packageName) {
  const escaped = packageName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const pattern = new RegExp(`(?<![@A-Za-z0-9_./-])${escaped}@([0-9][A-Za-z0-9.+-]*)(?=[():\\s])`, 'g');
  return [...new Set([...lockText.matchAll(pattern)].map((match) => match[1]))].sort();
}

function validateRoot(rootInput) {
  const root = resolve(rootInput);
  const workspacePath = resolve(root, 'pnpm-workspace.yaml');
  const lockfilePath = resolve(root, 'pnpm-lock.yaml');
  const workspaceText = readText(workspacePath);
  const lockText = readText(lockfilePath);
  const catalog = parseCatalog(workspaceText);
  const paths = packageJsonPaths(root, workspaceText);
  const declarationResult = findDeclarationIssues(root, catalog, paths);
  const reactVersions = collectLockVersions(lockText, 'react');
  const reactDomVersions = collectLockVersions(lockText, 'react-dom');
  const issues = [...declarationResult.issues];

  if (reactVersions.length === 0) {
    issues.push({ code: 'lockfile_missing_resolved_dependency', dependency: 'react' });
  }
  if (reactDomVersions.length === 0) {
    issues.push({ code: 'lockfile_missing_resolved_dependency', dependency: 'react-dom' });
  }
  if (reactVersions.length > 1) {
    issues.push({ code: 'multiple_react_runtime_instances', dependency: 'react', versions: reactVersions });
  }
  if (reactDomVersions.length > 1) {
    issues.push({ code: 'multiple_react_runtime_instances', dependency: 'react-dom', versions: reactDomVersions });
  }
  if (reactVersions.length === 1 && reactDomVersions.length === 1 && reactVersions[0] !== reactDomVersions[0]) {
    issues.push({
      code: 'runtime_versions_must_match_exactly',
      react: reactVersions[0],
      reactDom: reactDomVersions[0],
    });
  }

  return {
    valid: issues.length === 0,
    react: reactVersions.length === 1 ? reactVersions[0] : reactVersions,
    reactDom: reactDomVersions.length === 1 ? reactDomVersions[0] : reactDomVersions,
    resolvedInstances: Math.max(reactVersions.length, reactDomVersions.length),
    declarations: declarationResult.declarations,
    issues,
  };
}

function formatResult(result) {
  if (result.valid) {
    return [
      'React version alignment: PASS',
      `react=${result.react}`,
      `react-dom=${result.reactDom}`,
      `resolved_instances=${result.resolvedInstances}`,
    ].join('\n');
  }

  const reason = result.issues[0]?.code ?? 'unknown';
  const lines = [
    'React version alignment: FAIL',
    `react=${Array.isArray(result.react) ? result.react.join(',') : result.react}`,
    `react-dom=${Array.isArray(result.reactDom) ? result.reactDom.join(',') : result.reactDom}`,
    `reason=${reason}`,
    'issues=',
  ];
  for (const issue of result.issues) {
    lines.push(`  - ${JSON.stringify(issue)}`);
  }
  return lines.join('\n');
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const result = validateRoot(args.root);
  if (args.json) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    console.log(formatResult(result));
  }
  if (!result.valid) {
    process.exitCode = 1;
  }
}

const currentFile = fileURLToPath(import.meta.url);
if (process.argv[1] && resolve(process.argv[1]) === currentFile) {
  main();
}

export {
  collectLockVersions,
  findDeclarationIssues,
  formatResult,
  parseCatalog,
  parseWorkspacePatterns,
  validateRoot,
};
