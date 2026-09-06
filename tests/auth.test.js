/**
 * MAVERICK — Google Authentication & Session Guard Unit Tests
 * Smart India Hackathon 2026
 */

import assert from 'node:assert';
import { test } from 'node:test';

// Mock browser localStorage for node test runner
class MockLocalStorage {
  constructor() {
    this.store = {};
  }
  getItem(key) {
    return this.store[key] || null;
  }
  setItem(key, value) {
    this.store[key] = String(value);
  }
  removeItem(key) {
    delete this.store[key];
  }
  clear() {
    this.store = {};
  }
}

globalThis.localStorage = new MockLocalStorage();
globalThis.window = {
  location: { pathname: '/maverick/' },
  google: {
    accounts: {
      id: {
        disableAutoSelect: () => {}
      }
    }
  }
};

import { 
  getCurrentUser, 
  storeUserSession, 
  logout, 
  decodeJwtPayload,
  getGoogleClientId 
} from '../src/services/authService.js';

test('[+] Google Authentication Service Tests', async (t) => {
  await t.test('1. Returns null when no active session in storage', () => {
    localStorage.clear();
    const user = getCurrentUser();
    assert.strictEqual(user, null, 'Unauthenticated user must return null');
  });

  await t.test('2. Decodes Base64Url JWT token payload correctly', () => {
    // Standard mock OpenID Connect JWT payload
    const mockPayload = {
      sub: 'google-sub-1234567890',
      name: 'Cyber Analyst Test',
      email: 'analyst.test@gov-organization.in',
      picture: 'https://example.com/photo.jpg',
      exp: Math.floor(Date.now() / 1000) + 3600
    };
    const b64Payload = Buffer.from(JSON.stringify(mockPayload)).toString('base64url');
    const mockJwt = `header.${b64Payload}.signature`;

    const decoded = decodeJwtPayload(mockJwt);
    assert.ok(decoded, 'JWT payload should decode cleanly');
    assert.strictEqual(decoded.sub, mockPayload.sub);
    assert.strictEqual(decoded.email, mockPayload.email);
    assert.strictEqual(decoded.name, mockPayload.name);
  });

  await t.test('3. Stores user session and returns current user', () => {
    localStorage.clear();
    const stored = storeUserSession({
      id: 'usr-101',
      name: 'Dr. Jane Forensics',
      email: 'jane.forensics@cert-in.org',
      picture: 'https://cert-in.org/jane.jpg'
    });

    assert.ok(stored, 'Stored session must be returned');
    assert.strictEqual(stored.email, 'jane.forensics@cert-in.org');
    assert.ok(stored.expiresAt > Date.now(), 'Session expiration must be set in the future');

    const retrieved = getCurrentUser();
    assert.ok(retrieved, 'Current user must be retrieved from storage');
    assert.strictEqual(retrieved.email, 'jane.forensics@cert-in.org');
    assert.strictEqual(retrieved.name, 'Dr. Jane Forensics');
  });

  await t.test('4. Clears session and returns null when session is expired', () => {
    localStorage.clear();
    storeUserSession({
      id: 'expired-usr',
      name: 'Expired Analyst',
      email: 'expired@cert-in.org',
      expiresAt: Date.now() - 5000 // 5 seconds in the past
    });

    const user = getCurrentUser();
    assert.strictEqual(user, null, 'Expired session must return null and be wiped');
    assert.strictEqual(localStorage.getItem('maverick_auth_user'), null, 'Expired session must be removed from storage');
  });

  await t.test('5. Logout cleans up session from storage', () => {
    storeUserSession({
      id: 'active-usr',
      name: 'Active Analyst',
      email: 'active@cert-in.org'
    });

    assert.ok(getCurrentUser() !== null, 'Session should exist before logout');
    logout();
    assert.strictEqual(getCurrentUser(), null, 'Session should be null after logout');
    assert.strictEqual(localStorage.getItem('maverick_auth_user'), null);
  });
});
