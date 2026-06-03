import { describe, it, expect } from 'vitest';
import { selectLockfileVersionForEntry } from './inspect.js';

describe('selectLockfileVersionForEntry', () => {
  it('does not apply top-level lockfile mapping for transitive entries', () => {
    const lockfileVersions = new Map([['tmp', '0.2.5']]);
    const entry = { name: 'tmp', versionSpec: '0.2.4', scope: 'transitive' };

    expect(selectLockfileVersionForEntry(entry, lockfileVersions)).toBeNull();
  });

  it('applies lockfile mapping for non-transitive entries', () => {
    const lockfileVersions = new Map([['postcss', '8.5.8']]);
    const entry = {
      name: 'postcss',
      versionSpec: '^8.4.31',
      scope: 'dependencies',
    };

    expect(selectLockfileVersionForEntry(entry, lockfileVersions)).toBe(
      '8.5.8',
    );
  });

  it('returns null when mapping is missing', () => {
    const lockfileVersions = new Map();
    const entry = {
      name: 'uuid',
      versionSpec: '^8.3.2',
      scope: 'dependencies',
    };

    expect(selectLockfileVersionForEntry(entry, lockfileVersions)).toBeNull();
  });
});
