import { describe, expect, it } from 'vitest';
import { toDomain } from './WebFilter';

describe('toDomain', () => {
  it('reduces a pasted URL to its host name', () => {
    expect(toDomain(' https://www.Example.com:8443/path?q=1#x ')).toBe('www.example.com');
    expect(toDomain('*.ads.example.net')).toBe('ads.example.net');
    expect(toDomain('example.org.')).toBe('example.org');
  });

  it('rejects anything that is not a domain name', () => {
    for (const bad of ['', 'localhost', '10.0.0.1', 'exa mple.com', '-bad.com', 'a..b.com', 'http://']) {
      expect(toDomain(bad)).toBeNull();
    }
  });
});
