/*
 * Copyright 2026 The Backstage Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { encryptToken, decryptToken } from './tokenEncryption';

describe('tokenEncryption', () => {
  // 32-byte key for AES-256
  const key = Buffer.from('a'.repeat(64), 'hex').toString('base64');

  it('should round-trip encrypt and decrypt a token', async () => {
    const plaintext = 'gho_abc123_my_github_token';
    const encrypted = encryptToken(plaintext, key);
    expect(encrypted).not.toBe(plaintext);
    expect(encrypted).toContain('.'); // iv.tag.ciphertext format

    const decrypted = decryptToken(encrypted, key);
    expect(decrypted).toBe(plaintext);
  });

  it('should produce different ciphertexts for the same input', () => {
    const plaintext = 'same-token';
    const a = encryptToken(plaintext, key);
    const b = encryptToken(plaintext, key);
    expect(a).not.toBe(b); // random IV each time
  });

  it('should throw on tampered ciphertext', () => {
    const encrypted = encryptToken('token', key);
    const tampered = `${encrypted.slice(0, -2)}xx`;
    expect(() => decryptToken(tampered, key)).toThrow();
  });

  it('should throw on wrong key', () => {
    const encrypted = encryptToken('token', key);
    const wrongKey = Buffer.from('b'.repeat(64), 'hex').toString('base64');
    expect(() => decryptToken(encrypted, wrongKey)).toThrow();
  });
});
