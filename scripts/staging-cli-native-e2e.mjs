#!/usr/bin/env node
// Real staging browser -> native CLI -> certificate -> sign/verify.
// No mocked HTTP, token extraction, secret files, or passwords in argv.
import { spawnSync } from 'node:child_process';
import { createHash, randomUUID, X509Certificate } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir, platform, tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { parseEnv } from 'node:util';

const STAGING = 'https://staging.tzap.org';
const PIN = 'sha256:372ea5b33397e51ad76922338bb2613c822809d327d144d7974a99035006dc5a';
const repo = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const target = process.env.ZM_STAGING_BASE_URL || STAGING;
if (target !== STAGING) throw new Error('Only the staging service is permitted');
const binary = process.env.ZM_STAGING_BINARY || join(repo, 'target', 'debug', platform() === 'win32' ? 'zm.exe' : 'zm');
const work = mkdtempSync(join(tmpdir(), 'zmanager-live-staging-'));
const stateDir = join(work, 'state');
mkdirSync(stateDir, { mode: 0o700 });
const account = `staging-e2e-${platform()}-${randomUUID()}`;
const report = { target, platform: platform(), account_key: account, work_dir: work, checks: [], completed: false };
let stage = 'preflight';
let browser;
let cleanupPending = false;
const privateValues = [];

function check(condition, message) {
  if (!condition) throw new Error(message);
}
function pass(name) {
  report.checks.push(name);
  console.log(`PASS ${name}`);
}
function cli(args, { input, expectFailure = false, contextual = true } = {}) {
  const command = [...args, ...(contextual ? ['--state-dir', stateDir, '--account-key', account] : []), '--json'];
  const result = spawnSync(binary, command, { input, encoding: 'utf8', timeout: 120_000, windowsHide: true });
  const output = `${result.stdout || ''}${result.stderr || ''}`;
  for (const value of privateValues) check(!value || !output.includes(value), 'CLI output contained confidential input');
  check(!result.error, `${args.slice(0, 2).join(' ')} could not finish`);
  check(expectFailure ? result.status !== 0 : result.status === 0, `${args.slice(0, 2).join(' ')} returned an unexpected exit status`);
  let value;
  try { value = JSON.parse(result.stdout); } catch { throw new Error('CLI did not return JSON'); }
  return value;
}
function envFile(path) {
  const values = parseEnv(readFileSync(path, 'utf8'));
  for (let pass = 0; pass < 5; pass += 1) {
    for (const [key, value] of Object.entries(values)) {
      const alias = value.match(/^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$|^\$([A-Za-z_][A-Za-z0-9_]*)$/);
      if (alias && values[alias[1] || alias[2]]) values[key] = values[alias[1] || alias[2]];
    }
  }
  return values;
}
function pinnedRoot() {
  if (process.env.ZM_STAGING_ROOT_CERT) return process.env.ZM_STAGING_ROOT_CERT;
  const sources = join(process.env.CARGO_HOME || join(homedir(), '.cargo'), 'registry', 'src');
  for (const directory of readdirSync(sources)) {
    const path = join(sources, directory, 'tzap-plugin-signing-0.2.7', 'src', 'trust', 'tzap-staging-root-ca-2026.pem');
    if (existsSync(path)) return path;
  }
  throw new Error('Published TZAP 0.2.7 staging root was not found');
}
async function request(path) {
  const url = new URL(path, STAGING);
  check(url.origin === STAGING, 'Non-staging request refused');
  const response = await fetch(url, { redirect: 'manual', signal: AbortSignal.timeout(30_000) });
  check(response.ok, `Staging request returned HTTP ${response.status}`);
  return response.json();
}
function assertNoSecretFiles() {
  for (const name of readdirSync(stateDir)) {
    check(!['auth-pending.json', 'auth-session.json'].includes(name), 'Legacy secret file was created');
    const path = join(stateDir, name);
    if (!name.endsWith('.json')) continue;
    const content = readFileSync(path, 'utf8');
    check(!/"(?:pkce_verifier|access_token|private_key_der)"\s*:/.test(content), 'Secret material appeared in state metadata');
    for (const value of privateValues) check(!value || !content.includes(value), 'Confidential input appeared in state metadata');
  }
}

try {
  const credentialsPath = process.env.ZM_STAGING_ENV_FILE;
  check(credentialsPath && existsSync(credentialsPath), 'ZM_STAGING_ENV_FILE must name the ignored staging credential file');
  const values = envFile(credentialsPath);
  const email = values.STAGING_TEST_RECIPIENT_1_EMAIL || values.STAGING_TEST_USER;
  const password = values.STAGING_TEST_RECIPIENT_1_PASSWORD || values.STAGING_TEST_PASSWORD;
  check(email && password, 'Staging test credentials are unavailable');
  privateValues.push(password);
  const rootPath = pinnedRoot();
  const root = new X509Certificate(readFileSync(rootPath));
  check(`sha256:${createHash('sha256').update(root.raw).digest('hex')}` === PIN, 'Staging trust root did not match the published pin');
  const health = await request('/actuator/health');
  check(health.status === 'UP', 'Staging is not healthy');
  const roots = await request('/v1/trust/roots');
  check(Array.isArray(roots) && roots.some(item => item.certificateFingerprint === PIN && item.status === 'active'), 'Staging does not publish the pinned active root');
  pass('staging-health-and-pinned-trust');

  stage = 'native-login-start';
  const login = cli(['auth', 'login', '--environment', 'staging', '--auth-base-url', STAGING, '--account-base-url', STAGING, '--signing-base-url', STAGING]);
  cleanupPending = true;
  check(login.status === 'pending', 'CLI did not create a pending login');
  const launch = new URL(login.launch_url);
  check(launch.origin === STAGING && launch.searchParams.get('client_id') === 'zmanager-cli', 'CLI launch binding is incorrect');
  check(launch.searchParams.get('redirect_uri') === 'tzap://auth/callback' && launch.searchParams.get('state') === login.state, 'CLI callback binding is incorrect');
  check(launch.searchParams.get('code_challenge_method') === 'S256' && launch.searchParams.get('code_challenge')?.length >= 43, 'CLI PKCE binding is incorrect');
  assertNoSecretFiles();
  pass('native-pending-verifier-not-on-disk');

  stage = 'real-staging-browser-login';
  const playwrightRoot = process.env.ZM_PLAYWRIGHT_ROOT || resolve(repo, '../zmanager-desktop');
  const { chromium } = createRequire(join(playwrightRoot, 'package.json'))('playwright');
  browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();
  let forbiddenRequest = false;
  await page.route('**/*', async route => {
    const url = new URL(route.request().url());
    if (url.protocol === 'https:' && url.origin === STAGING) return route.continue();
    if (url.protocol === 'tzap:') return route.continue();
    forbiddenRequest = true;
    return route.abort();
  });
  await page.goto(launch.toString(), { waitUntil: 'domcontentloaded', timeout: 30_000 });
  await page.locator('input[type=email]').fill(email);
  await page.locator('input[type=password]').fill(password);
  const responsePromise = page.waitForResponse(response => {
    const url = new URL(response.url());
    return url.origin === STAGING && url.pathname === '/v1/login/email' && response.request().method() === 'POST';
  }, { timeout: 30_000 });
  await page.locator('button[type=submit]').click();
  const response = await responsePromise;
  check(response.ok(), `Staging browser login returned HTTP ${response.status()}`);
  const completion = await response.json();
  check(typeof completion.handoff_code === 'string', 'Staging browser login did not issue a handoff');
  privateValues.push(completion.handoff_code);
  check(!forbiddenRequest, 'The staging browser attempted a non-staging request');
  const callback = new URL('tzap://auth/callback');
  callback.searchParams.set('state', login.state);
  callback.searchParams.set('handoff_code', completion.handoff_code);
  // This is the supported detached/manual transfer. The server response and
  // browser are real; no response interception/fulfillment substitutes data.
  await page.waitForURL('**/auth/native/complete', { timeout: 10_000 }).catch(() => {});
  const copyPanel = page.locator('textarea[aria-label="CLI callback"]');
  report.hosted_copy_panel_available = await copyPanel.isVisible();
  if (report.hosted_copy_panel_available) check(await copyPanel.inputValue() === callback.toString(), 'Hosted copy panel has a different callback');
  await browser.close();
  browser = undefined;
  pass('real-browser-staging-password-pkce-handoff');

  stage = 'native-callback';
  const invalid = new URL(callback);
  invalid.searchParams.set('state', 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq');
  cli(['auth', 'callback', '--stdin'], { input: `${invalid}\n`, expectFailure: true });
  const authenticated = cli(['auth', 'callback', '--stdin'], { input: `${callback}\n` });
  report.callback_result = {
    authenticated: authenticated.authenticated === true,
    expired: typeof authenticated.expired === 'boolean' ? authenticated.expired : null,
    signing_ready: authenticated.signing_ready === true,
    status: typeof authenticated.status === 'string' ? authenticated.status : null,
    stage: typeof authenticated.stage === 'string' ? authenticated.stage : null,
  };
  check(
    authenticated.authenticated === true && authenticated.expired !== true && authenticated.signing_ready === true,
    `CLI did not save an active session and ready signing identity (authenticated=${String(authenticated.authenticated)}, expired=${String(authenticated.expired)}, signing_ready=${String(authenticated.signing_ready)}, status=${String(authenticated.status)}, stage=${String(authenticated.stage)})`,
  );
  cli(['auth', 'callback', '--stdin'], { input: `${callback}\n`, expectFailure: true });
  const status = cli(['auth', 'status']);
  check(status.authenticated === true && status.expired === false, 'Native session did not survive CLI process restart');
  assertNoSecretFiles();
  pass('native-stdin-callback-invalid-state-replay-and-restart');

  stage = 'server-issued-device-certificate';
  const enrolled = cli(['auth', 'cert', 'enroll', '--service-base-url', STAGING, '--trusted-root-cert', rootPath]);
  const certificate = enrolled.certificate;
  check(certificate?.certificate_id && certificate.state === 'active', 'CLI did not store an active server certificate');
  report.certificate_id = certificate.certificate_id;
  report.certificate_sha256 = certificate.certificate_sha256;
  report.public_device_id = certificate.public_device_id;
  assertNoSecretFiles();
  pass('server-certificate-validated-and-native-key-persisted');

  stage = 'sign-offline-and-live-verify';
  const document = join(work, 'document.json');
  const envelope = join(work, 'signed-envelope.json');
  const liveStatus = join(work, 'certificate-status.json');
  writeFileSync(document, JSON.stringify({ tzap_payload_version: 1, title: 'Native CLI staging E2E', run: account }), { mode: 0o600 });
  cli(['tzap', 'sign', document, '--certificate-id', certificate.certificate_id, '--output', envelope]);
  const offline = cli(['tzap', 'verify', envelope, '--custom-trust-root-cert', rootPath], { contextual: false });
  check(offline.state === 'cryptographically_intact_offline', 'Offline cryptographic verification failed');
  const current = await request(`/v1/status/certificates/by-fingerprint/${encodeURIComponent(certificate.certificate_sha256)}`);
  writeFileSync(liveStatus, JSON.stringify(current), { mode: 0o600 });
  const online = cli(['tzap', 'verify', envelope, '--custom-trust-root-cert', rootPath, '--status-response', liveStatus], { contextual: false });
  check(online.state === 'valid_now', 'Staging did not confirm current certificate validity');
  pass('sign-offline-verify-and-real-staging-status');
  report.completed = true;
} catch (error) {
  report.failure_stage = stage;
  const message = String(error?.message || 'unexpected failure');
  report.failure = privateValues.some(value => value && message.includes(value)) || message.includes('handoff_code=') ? 'Confidential detail omitted' : message.split('\n')[0];
  console.error(`FAIL ${stage}: ${report.failure}`);
  process.exitCode = 1;
} finally {
  if (browser) await browser.close().catch(() => {});
  if (cleanupPending) {
    try { cli(['auth', 'forget']); report.native_session_cleanup = true; }
    catch { report.native_session_cleanup = false; }
  }
  report.finished_at = new Date().toISOString();
  writeFileSync(join(work, 'report.json'), JSON.stringify(report, null, 2), { mode: 0o600 });
  console.log(`Report: ${join(work, 'report.json')}`);
}
