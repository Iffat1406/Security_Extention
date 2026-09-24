import { describe, expect, it } from 'vitest';
import { classifyPage } from '../src/detection/exclusions';
import { approximateSiteOf, hostMatchesDomain, isSameSite } from '../src/detection/domain';

describe('classifyPage — §30.2 page types that are never scanned', () => {
  it.each([
    ['chrome://settings', 'BROWSER_INTERNAL'],
    ['edge://flags', 'BROWSER_INTERNAL'],
    ['chrome-extension://abcdefghijklmnop/popup.html', 'BROWSER_INTERNAL'],
    ['moz-extension://1234/page.html', 'BROWSER_INTERNAL'],
    ['about:blank', 'BLANK_PAGE'],
    ['https://chromewebstore.google.com/detail/x', 'WEB_STORE'],
    ['https://chrome.google.com/webstore/detail/x', 'WEB_STORE'],
    ['file:///C:/Users/me/doc.html', 'LOCAL_FILE'],
    ['http://localhost:3000/', 'LOCAL_ADDRESS'],
    ['http://127.0.0.1:8080/', 'LOCAL_ADDRESS'],
    ['http://[::1]/', 'LOCAL_ADDRESS'],
    ['http://printer.local/', 'LOCAL_ADDRESS'],
    ['http://10.0.0.5/', 'PRIVATE_NETWORK'],
    ['http://172.16.4.2/', 'PRIVATE_NETWORK'],
    ['http://192.168.1.1/', 'PRIVATE_NETWORK'],
    ['http://169.254.169.254/', 'PRIVATE_NETWORK'],
    ['http://[fd00::1]/', 'PRIVATE_NETWORK'],
    ['view-source:https://example.com', 'VIEW_SOURCE'],
    ['data:text/html,hi', 'DATA_URL'],
    ['blob:https://example.com/uuid', 'DATA_URL'],
    ['https://example.com/report.pdf', 'PDF_VIEWER'],
    ['ftp://example.com/', 'UNSUPPORTED_SCHEME'],
    ['not a url', 'INVALID_URL'],
  ])('%s -> %s', (url, reason) => {
    expect(classifyPage(url)).toEqual({ scannable: false, reason });
  });

  it('scans an ordinary public https page', () => {
    expect(classifyPage('https://www.example.com/a?b=c')).toEqual({
      scannable: true,
      host: 'www.example.com',
      origin: 'https://www.example.com',
      protocol: 'https:',
      localOnly: false,
    });
  });

  it('scans public IP addresses (§30.3)', () => {
    expect(classifyPage('http://93.184.216.34/').scannable).toBe(true);
  });

  it('allows local addresses as local-only when the user opts in', () => {
    const result = classifyPage('http://localhost:3000/', { scanLocalAddresses: true });
    expect(result).toMatchObject({ scannable: true, localOnly: true });
  });

  it('never un-excludes private networks, even with the local setting on', () => {
    expect(classifyPage('http://192.168.1.1/', { scanLocalAddresses: true })).toEqual({
      scannable: false,
      reason: 'PRIVATE_NETWORK',
    });
  });
});

describe('§23.2 exclusion list semantics', () => {
  const excludedDomains = ['internal.company.com'];

  it('an entry excludes the domain and all of its subdomains', () => {
    expect(classifyPage('https://internal.company.com/', { excludedDomains }).scannable).toBe(false);
    expect(classifyPage('https://intranet.internal.company.com/', { excludedDomains })).toEqual({
      scannable: false,
      reason: 'USER_EXCLUDED',
    });
  });

  it('but not the parent domain', () => {
    expect(classifyPage('https://company.com/', { excludedDomains }).scannable).toBe(true);
  });

  it('matching is on label boundaries, not substrings', () => {
    expect(hostMatchesDomain('notinternal.company.com', 'internal.company.com')).toBe(false);
  });
});

describe('approximate site grouping (third-party ratio only)', () => {
  it('groups subdomains and handles common multi-part suffixes', () => {
    expect(approximateSiteOf('cdn.example.com')).toBe('example.com');
    expect(approximateSiteOf('www.bbc.co.uk')).toBe('bbc.co.uk');
    expect(isSameSite('a.example.com', 'b.example.com')).toBe(true);
    expect(isSameSite('example.com', 'tracker.net')).toBe(false);
  });
});
