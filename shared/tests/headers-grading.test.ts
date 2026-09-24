import { describe, expect, it } from 'vitest';
import { collectHeaders, gradeSecurityHeaders, scoreToGrade } from '../src/detection/headers-grading';

const allGood = {
  'Content-Security-Policy': "default-src 'self'",
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
  'X-Frame-Options': 'DENY',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'camera=(), microphone=()',
};

describe('gradeSecurityHeaders — Feature 4 weights and §26.2 cases', () => {
  it('all six valid headers score 100 / A', () => {
    const result = gradeSecurityHeaders(allGood);
    expect(result).toMatchObject({ score: 100, grade: 'A', missing: [], invalid: [] });
    expect(result.present).toHaveLength(6);
  });

  it('no headers score 0 / F', () => {
    const result = gradeSecurityHeaders({});
    expect(result).toMatchObject({ score: 0, grade: 'F', present: [] });
    expect(result.missing).toHaveLength(6);
  });

  it('applies the documented weights (CSP 30, HSTS 25, XFO 20, XCTO 15, RP 5, PP 5)', () => {
    expect(gradeSecurityHeaders({ 'content-security-policy': "default-src 'self'" }).score).toBe(30);
    expect(gradeSecurityHeaders({ 'strict-transport-security': 'max-age=100' }).score).toBe(25);
    expect(gradeSecurityHeaders({ 'x-frame-options': 'SAMEORIGIN' }).score).toBe(20);
    expect(gradeSecurityHeaders({ 'x-content-type-options': 'nosniff' }).score).toBe(15);
    expect(gradeSecurityHeaders({ 'referrer-policy': 'no-referrer' }).score).toBe(5);
    expect(gradeSecurityHeaders({ 'permissions-policy': 'geolocation=()' }).score).toBe(5);
  });

  it('header names are case-insensitive', () => {
    expect(gradeSecurityHeaders({ 'X-CONTENT-TYPE-OPTIONS': 'nosniff' }).present).toEqual(['x-content-type-options']);
  });

  it('malformed values score 0 and are listed as invalid', () => {
    const result = gradeSecurityHeaders({
      'X-Content-Type-Options': 'yes please',
      'Strict-Transport-Security': 'max-age=0',
      'X-Frame-Options': 'ALLOW-FROM https://example.com',
    });
    expect(result.score).toBe(0);
    expect(result.invalid.sort()).toEqual(['strict-transport-security', 'x-content-type-options', 'x-frame-options']);
  });

  it('duplicate headers are joined per RFC 9110 rather than the last one winning', () => {
    const map = collectHeaders([
      { name: 'Referrer-Policy', value: 'garbage' },
      { name: 'referrer-policy', value: 'no-referrer' },
    ]);
    expect(map.get('referrer-policy')).toBe('garbage, no-referrer');
    expect(
      gradeSecurityHeaders([
        { name: 'Referrer-Policy', value: 'garbage' },
        { name: 'referrer-policy', value: 'no-referrer' },
      ]).present
    ).toContain('referrer-policy');
  });

  it('grade boundaries A–F are inclusive at the lower bound', () => {
    expect(scoreToGrade(90)).toBe('A');
    expect(scoreToGrade(89)).toBe('B');
    expect(scoreToGrade(75)).toBe('B');
    expect(scoreToGrade(74)).toBe('C');
    expect(scoreToGrade(60)).toBe('C');
    expect(scoreToGrade(59)).toBe('D');
    expect(scoreToGrade(40)).toBe('D');
    expect(scoreToGrade(39)).toBe('F');
    expect(scoreToGrade(0)).toBe('F');
  });

  it('truncates stored header values to 512 characters', () => {
    const long = `default-src 'self' ${'a'.repeat(1000)}`;
    expect(gradeSecurityHeaders({ 'content-security-policy': long }).details['content-security-policy']).toHaveLength(512);
  });
});
