import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

const root = process.cwd();
const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'aml-consumer-compat-'));
let tarballPath = null;

function run(command, args, cwd) {
  return execFileSync(command, args, {
    cwd,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe']
  }).trim();
}

function resolveNpmCli() {
  const nodeDir = path.dirname(process.execPath);
  const candidates = process.platform === 'win32'
    ? [path.join(nodeDir, 'node_modules', 'npm', 'bin', 'npm-cli.js')]
    : [
        path.join(nodeDir, '..', 'lib', 'node_modules', 'npm', 'bin', 'npm-cli.js'),
        path.join(nodeDir, 'node_modules', 'npm', 'bin', 'npm-cli.js')
      ];
  const found = candidates.find(candidate => fs.existsSync(candidate));
  if (!found) throw new Error(`Unable to locate npm-cli.js next to Node runtime ${process.execPath}`);
  return path.resolve(found);
}

function runNpm(args, cwd) {
  return run(process.execPath, [resolveNpmCli(), ...args], cwd);
}

try {
  const matrix = JSON.parse(fs.readFileSync(path.join(root, 'compatibility-matrix.json'), 'utf8'));
  const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  if (matrix.package !== pkg.name) throw new Error('Compatibility matrix package name does not match package.json');
  if (matrix.runtime?.node_engine !== pkg.engines?.node) throw new Error('Compatibility matrix Node engine does not match package.json');

  const packResult = JSON.parse(runNpm(['pack', '--json'], root))[0];
  tarballPath = path.join(root, packResult.filename);
  if (!fs.existsSync(tarballPath)) throw new Error(`npm pack did not create ${tarballPath}`);

  fs.writeFileSync(path.join(tempRoot, 'package.json'), '{"private":true,"type":"module"}\n');
  fs.writeFileSync(path.join(tempRoot, 'sample.aml'), `transmission "consumer-compat" {\n  title: "Consumer compatibility"\n  engram proof {\n    value: "Cross-platform package smoke test"\n    purpose: "verify installed AML consumer path"\n    memory_role: "compatibility_fixture"\n    user_effect: "clarity"\n    attention_cost: 1\n    restoration_value: 3\n  }\n}\n`);

  runNpm(['install', '--ignore-scripts', '--save-exact', tarballPath], tempRoot);
  const apiOutput = run(process.execPath, ['-e', "import('aml-core').then(m=>{if(!m||Object.keys(m).length===0)process.exit(2);console.log(Object.keys(m).length)}).catch(e=>{console.error(e);process.exit(1)})"], tempRoot);

  const installedRoot = path.join(tempRoot, 'node_modules', pkg.name);
  const doctorOutput = run(process.execPath, [path.join(installedRoot, 'bin', 'aml-doctor.js')], tempRoot);
  const validateOutput = run(process.execPath, [path.join(installedRoot, 'bin', 'aml.js'), 'validate', 'sample.aml'], tempRoot);

  const report = {
    protocol: 'aml-consumer-compatibility-report/1',
    package: pkg.name,
    version: pkg.version,
    platform: process.platform,
    architecture: process.arch,
    node: process.version,
    npm_pack: {
      filename: packResult.filename,
      integrity: packResult.integrity || null,
      shasum: packResult.shasum || null,
      size: packResult.size || null
    },
    checks: {
      clean_tarball_install: true,
      javascript_api_import: true,
      exported_symbol_count: Number(apiOutput),
      aml_doctor: doctorOutput.length > 0,
      aml_cli_validate: /VALID:/i.test(validateOutput)
    },
    claim_boundary: matrix.claim_boundary
  };

  if (!report.checks.aml_doctor || !report.checks.aml_cli_validate) {
    throw new Error('Installed-package doctor or CLI validation did not produce the expected success signal');
  }

  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
} finally {
  if (tarballPath && fs.existsSync(tarballPath)) fs.rmSync(tarballPath, { force: true });
  fs.rmSync(tempRoot, { recursive: true, force: true });
}
