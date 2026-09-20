import { describe, expect, it } from 'vitest';
import { AppError } from '../src/lib/errors';
import { validateOutboundUrl } from '../src/services/url-safety.service';

async function expectAppErrorCode(promise: Promise<unknown>, code: string) {
  try {
    await promise;
    expect.unreachable('expected validateOutboundUrl to throw');
  } catch (error) {
    expect(error).toBeInstanceOf(AppError);
    expect((error as AppError).code).toBe(code);
  }
}

describe('validateOutboundUrl — §20.4/§20.5', () => {
  it('rejects a disallowed scheme', async () => {
    await expectAppErrorCode(validateOutboundUrl('file:///etc/passwd'), 'UNSUPPORTED_SCHEME');
    await expectAppErrorCode(validateOutboundUrl('chrome-extension://abc/page.html'), 'UNSUPPORTED_SCHEME');
    await expectAppErrorCode(validateOutboundUrl('javascript:alert(1)'), 'UNSUPPORTED_SCHEME');
  });

  it('rejects credentials embedded in the URL', async () => {
    await expectAppErrorCode(validateOutboundUrl('http://user:pass@example.com'), 'INVALID_URL');
  });

  it('rejects a URL over 2048 characters', async () => {
    await expectAppErrorCode(
      validateOutboundUrl(`https://example.com/${'a'.repeat(2048)}`),
      'URL_TOO_LONG'
    );
  });

  it('rejects the hostname deny-list (localhost, .local, .internal)', async () => {
    await expectAppErrorCode(validateOutboundUrl('http://localhost/'), 'BLOCKED_TARGET');
    await expectAppErrorCode(validateOutboundUrl('http://foo.localhost/'), 'BLOCKED_TARGET');
    await expectAppErrorCode(validateOutboundUrl('http://printer.local/'), 'BLOCKED_TARGET');
    await expectAppErrorCode(validateOutboundUrl('http://service.internal/'), 'BLOCKED_TARGET');
    await expectAppErrorCode(validateOutboundUrl('http://metadata.google.internal/'), 'BLOCKED_TARGET');
  });

  it('rejects an IPv4 loopback literal', async () => {
    await expectAppErrorCode(validateOutboundUrl('http://127.0.0.1/'), 'BLOCKED_TARGET');
  });

  it('rejects RFC1918 private ranges', async () => {
    await expectAppErrorCode(validateOutboundUrl('http://10.0.0.5/'), 'BLOCKED_TARGET');
    await expectAppErrorCode(validateOutboundUrl('http://192.168.1.1/'), 'BLOCKED_TARGET');
  });

  it('rejects the cloud metadata address explicitly', async () => {
    await expectAppErrorCode(validateOutboundUrl('http://169.254.169.254/latest/meta-data/'), 'BLOCKED_TARGET');
  });

  it('rejects an IPv6 loopback literal', async () => {
    await expectAppErrorCode(validateOutboundUrl('http://[::1]/'), 'BLOCKED_TARGET');
  });

  it('rejects an IPv4-mapped IPv6 loopback literal', async () => {
    await expectAppErrorCode(validateOutboundUrl('http://[::ffff:127.0.0.1]/'), 'BLOCKED_TARGET');
  });

  it('rejects encoded-bypass IPv4 forms (decimal, octal, hex)', async () => {
    await expectAppErrorCode(validateOutboundUrl('http://2130706433/'), 'BLOCKED_TARGET');
    await expectAppErrorCode(validateOutboundUrl('http://0177.0.0.1/'), 'BLOCKED_TARGET');
    await expectAppErrorCode(validateOutboundUrl('http://0x7f000001/'), 'BLOCKED_TARGET');
  });

  it('accepts a public IP literal and pins it', async () => {
    const result = await validateOutboundUrl('https://93.184.216.34/');
    expect(result.pinnedIp).toBe('93.184.216.34');
    expect(result.ipFamily).toBe(4);
    expect(result.protocol).toBe('https:');
    expect(result.port).toBe(443);
  });

  it('resolves and accepts a real public hostname', async () => {
    const result = await validateOutboundUrl('https://example.com/');
    expect(result.hostname).toBe('example.com');
    expect(result.pinnedIp).toBeTruthy();
    expect([4, 6]).toContain(result.ipFamily);
  });
});
