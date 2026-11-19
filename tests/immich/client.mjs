// Runs in a fresh private-network client with no application data mounts.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

const input = [];
for await (const chunk of process.stdin) input.push(chunk);
const { credentials, seed, expected, image } = JSON.parse(Buffer.concat(input));
const png = Buffer.from(image, 'base64');
const filename = 'colour-study.png';
const albumName = 'Colour studies';
const timestamp = '2026-01-03T12:05:06.000Z';
const url = 'http://server:2283/api';
let stage = 'ready';
let status = 0;
let token;

async function request(path, { method = 'GET', data, multipart, raw = false, anonymous = false } = {}) {
  const headers = {};
  if (token && !anonymous) headers.Authorization = 'Bearer ' + token;
  if (data) headers['Content-Type'] = 'application/json';
  const response = await fetch(url + path, {
    method, headers, body: multipart ?? (data && JSON.stringify(data)),
    signal: AbortSignal.timeout(10000), redirect: 'error',
  });
  status = response.status;
  if (anonymous) {
    assert.equal(status, 401);
    return;
  }
  assert.ok(response.ok);
  return raw ? Buffer.from(await response.arrayBuffer()) : response.json();
}

try {
  const limit = Date.now() + 180000;
  while (true) {
    try {
      const ping = await request('/server/ping');
      assert.equal(ping.res, 'pong');
      break;
    } catch {
      if (Date.now() > limit) throw new Error('deadline');
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
  }
  stage = 'version';
  const { major, minor, patch } = await request('/server/version');
  assert.equal([major, minor, patch].join('.'), '3.2.4');
  if (seed) {
    stage = 'signup';
    await request('/auth/admin-sign-up', { method: 'POST', data: { ...credentials, name: 'Synthetic owner' } });
  }
  stage = 'login';
  const login = await request('/auth/login', { method: 'POST', data: credentials });
  token = login.accessToken;
  assert.ok(token && login.userId);
  const owner = await request('/users/me');
  assert.equal(owner.id, login.userId);
  assert.equal(owner.email, credentials.email);
  let assetId = expected?.assetId;
  let albumId = expected?.albumId;
  if (seed) {
    stage = 'upload';
    const form = new FormData();
    form.set('assetData', new Blob([png], { type: 'image/png' }), filename);
    form.set('fileCreatedAt', timestamp);
    form.set('fileModifiedAt', timestamp);
    const upload = await request('/assets', { method: 'POST', multipart: form });
    assert.equal(upload.status, 'created');
    assetId = upload.id;
    stage = 'album_create';
    albumId = (await request('/albums', {
      method: 'POST', data: { albumName, assetIds: [assetId] },
    })).id;
  }
  stage = 'metadata';
  const asset = await request('/assets/' + assetId);
  assert.equal(asset.id, assetId);
  assert.equal(asset.ownerId, owner.id);
  assert.equal(asset.originalFileName, filename);
  assert.equal(asset.type, 'IMAGE');
  const album = await request('/albums/' + albumId);
  assert.equal(album.albumName, albumName);
  assert.equal(album.assetCount, 1);
  assert.equal(album.shared, false);
  const containing = await request('/albums?assetId=' + assetId);
  assert.deepEqual(containing.map(a => a.id), [albumId]);
  stage = 'protected_original';
  await request('/assets/' + assetId + '/original', { anonymous: true });
  const original = await request('/assets/' + assetId + '/original', { raw: true });
  assert.deepEqual(original, png);
  const receipt = { ownerId: owner.id, assetId, albumId, bytes: original.length,
    originalSha256: createHash('sha256').update(original).digest('hex') };
  if (expected) assert.deepEqual(receipt, expected);
  process.stdout.write(JSON.stringify(receipt));
} catch {
  process.stderr.write('TRIAL_API_' + stage + '_' + status + '\n');
  process.exitCode = 1;
}
