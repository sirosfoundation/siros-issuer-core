#!/usr/bin/env node
// siros-issuer-core conformance dev portal (Mode A, design §7.2).
//
// The "integrating application" for conformance runs: a login form that
// authenticates a test user, calls the issuer's authorize-complete
// endpoint with a client-assertion JWT, and redirects the suite's browser
// back with the authorization code. Local-test tooling only: it accepts
// any username and must never be deployed anywhere real.
//
// Env:
//   ISSUER_URL          http://siros-issuer-core:8080
//   PORTAL_BIND         0.0.0.0:8080
//   INTEGRATOR_JWK_PATH /etc/siros-issuer-portal/integrator.jwk

import { readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { SignJWT, importJWK } from 'jose';

const ISSUER_URL = process.env.ISSUER_URL || 'http://siros-issuer-core:8080';
const BIND = process.env.PORTAL_BIND || '0.0.0.0:8080';
const JWK_PATH =
  process.env.INTEGRATOR_JWK_PATH || '/etc/siros-issuer-portal/integrator.jwk';

const jwk = JSON.parse(readFileSync(JWK_PATH, 'utf-8'));
const key = await importJWK(jwk, jwk.alg || 'ES256');

const now = () => Math.floor(Date.now() / 1000);

async function clientAssertion() {
  return new SignJWT({})
    .setProtectedHeader({ alg: jwk.alg || 'ES256', kid: jwk.kid, jwk: { ...jwk, d: undefined } })
    .setIssuer(jwk.kid)
    .setSubject(jwk.kid)
    .setAudience(ISSUER_URL)
    .setIssuedAt(now())
    .setExpirationTime(now() + 300)
    .sign(key);
}

// Test subjects (conformance fixtures): everything the catalog's mandatory
// claims demand. Never real personal data.
const SUBJECTS = {
  'test-user-001': {
    given_name: 'Conformance',
    family_name: 'Tester',
    birth_date: '1982-07-12',
  },
};

const page = (body) =>
  `<!doctype html><html><head><title>siros dev portal</title></head><body>${body}</body></html>`;

createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);

  if (req.method === 'GET' && url.pathname === '/login') {
    const issuer_state = url.searchParams.get('issuer_state') || '';
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end(
      page(
        `<form method="POST" action="/login">
           <input type="hidden" name="issuer_state" value="${issuer_state}"/>
           <label>Username <input name="username" value="test-user-001"/></label>
           <button type="submit">Log in</button>
         </form>`,
      ),
    );
    return;
  }

  if (req.method === 'POST' && url.pathname === '/login') {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const body = new URLSearchParams(Buffer.concat(chunks).toString());
    const issuer_state = body.get('issuer_state') || '';
    const username = body.get('username') || 'test-user-001';
    const subject = SUBJECTS[username] || SUBJECTS['test-user-001'];

    const assertion = await clientAssertion();
    const response = await fetch(
      `${ISSUER_URL}/api/v1/issuance/sessions/${encodeURIComponent(issuer_state)}/authorize`,
      {
        method: 'POST',
        headers: {
          authorization: `Bearer ${assertion}`,
          'content-type': 'application/json',
        },
        body: JSON.stringify({ subject }),
      },
    );
    if (!response.ok) {
      res.writeHead(502, { 'content-type': 'text/html' });
      res.end(
        page(
          `<pre>authorize-complete failed: ${response.status} ${await response.text()}</pre>`,
        ),
      );
      return;
    }
    const reply = await response.json();
    res.writeHead(302, { location: reply.redirect });
    res.end();
    return;
  }

  res.writeHead(404, { 'content-type': 'text/plain' });
  res.end('not found');
}).listen(BIND, () => {
  console.log(`dev portal on http://${BIND} → ${ISSUER_URL}`);
});