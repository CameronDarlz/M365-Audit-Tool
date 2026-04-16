/**
 * AuditReportPDF — @react-pdf/renderer document
 *
 * Rules followed to avoid blank-page bugs:
 *  - Zero HTML elements: only Document, Page, View, Text, Link
 *  - Fonts: built-in Helvetica / Helvetica-Bold / Courier (no Font.register needed)
 *  - Styles: no CSS shorthand that react-pdf rejects (border, gap, grid)
 *  - Colors passed as hex strings
 */
import { Document, Page, View, Text, Link, StyleSheet } from '@react-pdf/renderer';
import type { ScoredAudit } from '../../types/audit';
import { remediationSteps } from '../../engine/remediationSteps';

// ─── Colour palette ───────────────────────────────────────────────────────────
const C = {
  bg:       '#080d18',
  surface:  '#0f172a',
  card:     '#162032',
  border:   '#1e3a5f',
  text:     '#e2e8f0',
  muted:    '#64748b',
  good:     '#34d399',
  fair:     '#fbbf24',
  poor:     '#fb923c',
  critical: '#f87171',
  blue:     '#38bdf8',
  white:    '#ffffff',
};

function gradeHex(grade: string): string {
  if (grade === 'good')     return C.good;
  if (grade === 'fair')     return C.fair;
  if (grade === 'poor')     return C.poor;
  return C.critical;
}

function severityHex(sev: string): string {
  if (sev === 'critical') return C.critical;
  if (sev === 'high')     return '#fb923c';
  if (sev === 'medium')   return '#fbbf24';
  if (sev === 'low')      return C.blue;
  return C.muted;
}

function fmtMins(mins: number): string {
  if (mins < 60) return `~${mins} min`;
  const h = Math.floor(mins / 60);
  const m = mins % 60;
  return m > 0 ? `~${h}h ${m}m` : `~${h}h`;
}

// ─── Styles ───────────────────────────────────────────────────────────────────
const s = StyleSheet.create({
  page: {
    backgroundColor: C.bg,
    color: C.text,
    fontFamily: 'Helvetica',
    fontSize: 9,
    paddingTop: 36,
    paddingBottom: 36,
    paddingHorizontal: 36,
  },

  // Cover
  coverWrap: { alignItems: 'center', paddingVertical: 40 },
  coverEyebrow: { fontSize: 7, color: C.muted, letterSpacing: 2, textTransform: 'uppercase', marginBottom: 10 },
  coverTitle: { fontSize: 22, fontFamily: 'Helvetica-Bold', color: C.white, marginBottom: 4 },
  coverDomain: { fontSize: 9, color: C.muted, marginBottom: 20 },
  scoreCircle: {
    width: 80, height: 80, borderRadius: 40,
    borderWidth: 3, borderStyle: 'solid',
    alignItems: 'center', justifyContent: 'center',
    marginBottom: 12,
  },
  scoreNumber: { fontSize: 26, fontFamily: 'Helvetica-Bold' },
  scoreDenom: { fontSize: 7, color: C.muted },
  gradePill: {
    paddingHorizontal: 12, paddingVertical: 4,
    borderRadius: 20, borderWidth: 1, borderStyle: 'solid',
    marginBottom: 10,
  },
  gradePillText: { fontSize: 8, fontFamily: 'Helvetica-Bold', letterSpacing: 1, textTransform: 'uppercase' },
  coverDate: { fontSize: 8, color: C.muted },

  // Section
  section: {
    borderWidth: 1, borderStyle: 'solid', borderColor: C.border,
    borderRadius: 8, backgroundColor: C.surface,
    padding: 14, marginBottom: 14,
  },
  sectionTitle: {
    fontSize: 11, fontFamily: 'Helvetica-Bold', color: C.white,
    borderBottomWidth: 1, borderBottomStyle: 'solid', borderBottomColor: C.border,
    paddingBottom: 6, marginBottom: 10,
  },
  bodyText: { fontSize: 8, color: C.muted, lineHeight: 1.5 },

  // Severity count row
  sevRow: { flexDirection: 'row', marginBottom: 10 },
  sevBox: {
    flex: 1, alignItems: 'center',
    borderWidth: 1, borderStyle: 'solid', borderColor: C.border,
    borderRadius: 6, backgroundColor: C.card,
    paddingVertical: 6, marginRight: 6,
  },
  sevNum: { fontSize: 14, fontFamily: 'Helvetica-Bold' },
  sevLabel: { fontSize: 6, color: C.muted, textTransform: 'uppercase', letterSpacing: 0.5, marginTop: 2 },

  // Category score bars
  catRow: { marginBottom: 8 },
  catHeader: { flexDirection: 'row', justifyContent: 'space-between', marginBottom: 2 },
  catName: { fontSize: 8, color: C.text },
  catScore: { fontSize: 8, fontFamily: 'Helvetica-Bold' },
  barBg: { height: 4, borderRadius: 2, backgroundColor: C.card },
  barFill: { height: 4, borderRadius: 2 },

  // Finding card
  findingCard: {
    borderWidth: 1, borderStyle: 'solid', borderColor: C.border,
    borderRadius: 6, backgroundColor: C.card,
    padding: 8, marginBottom: 6,
  },
  findingHeader: { flexDirection: 'row', justifyContent: 'space-between', marginBottom: 3 },
  findingTitle: { fontSize: 8, fontFamily: 'Helvetica-Bold', color: C.white, flex: 1, marginRight: 6 },
  effortBadge: {
    fontSize: 6, fontFamily: 'Helvetica-Bold',
    borderWidth: 1, borderStyle: 'solid',
    borderRadius: 10, paddingHorizontal: 5, paddingVertical: 2,
  },
  findingDesc: { fontSize: 7, color: C.muted, lineHeight: 1.4, marginBottom: 2 },
  findingRec: { fontSize: 7, color: C.text, lineHeight: 1.4 },
  affectedText: { fontSize: 6, color: C.muted, fontFamily: 'Courier', marginTop: 2 },

  // Severity group header
  sevGroupLabel: { fontSize: 8, fontFamily: 'Helvetica-Bold', textTransform: 'uppercase', letterSpacing: 0.5, marginBottom: 5 },

  // Roadmap item
  roadmapItem: {
    borderWidth: 1, borderStyle: 'solid', borderColor: C.border,
    borderRadius: 6, marginBottom: 8, overflow: 'hidden',
  },
  roadmapHeader: {
    flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center',
    padding: 8, borderBottomWidth: 1, borderBottomStyle: 'solid', borderBottomColor: C.border,
    backgroundColor: C.card,
  },
  roadmapIdx: {
    width: 16, height: 16, borderRadius: 8,
    backgroundColor: C.border,
    alignItems: 'center', justifyContent: 'center',
    marginRight: 6,
  },
  roadmapIdxText: { fontSize: 6, color: C.muted, fontFamily: 'Helvetica-Bold' },
  roadmapTitle: { fontSize: 8, fontFamily: 'Helvetica-Bold', color: C.white, flex: 1 },
  roadmapTime: { fontSize: 7, color: C.muted },
  roadmapBody: { padding: 8 },
  roadmapWhy: { fontSize: 7, color: C.muted, lineHeight: 1.4, marginBottom: 5, fontStyle: 'italic' },
  stepRow: { flexDirection: 'row', marginBottom: 3 },
  stepNum: {
    width: 14, height: 14, borderRadius: 7,
    backgroundColor: C.border,
    alignItems: 'center', justifyContent: 'center',
    marginRight: 5, flexShrink: 0,
  },
  stepNumText: { fontSize: 5.5, color: C.muted, fontFamily: 'Helvetica-Bold' },
  stepText: { fontSize: 7, color: C.text, lineHeight: 1.4, flex: 1 },
  caveatText: { fontSize: 7, color: C.fair, marginTop: 4 },

  // Road section header
  roadSectionTitle: { fontSize: 9, fontFamily: 'Helvetica-Bold', marginBottom: 3 },
  roadSectionSub: { fontSize: 7, color: C.muted, marginBottom: 8 },

  // Footer
  footer: { textAlign: 'center', fontSize: 7, color: C.muted, marginTop: 10 },

  // Page number
  pageNum: { position: 'absolute', bottom: 18, right: 36, fontSize: 7, color: C.muted },
});

// ─── Sub-components ──────────────────────────────────────────────────────────

function CoverPage({ audit }: { audit: ScoredAudit }) {
  const { overallScore, overallGrade, result, findings } = audit;
  const org = result.org.organization;
  const domain = result.emailSecurity.domain
    || org?.verifiedDomains.find(d => d.isDefault)?.name
    || '—';
  const color = gradeHex(overallGrade);
  const gradeLabel = { good: 'Good', fair: 'Fair', poor: 'Poor', critical: 'Critical' }[overallGrade] ?? overallGrade;
  const auditedAt = new Date(result.auditedAt).toLocaleString('en-GB', {
    day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit',
  });

  const quickWins = findings.filter(f => f.effort === 'quick-win').length;
  const medium    = findings.filter(f => f.effort === 'medium').length;
  const project   = findings.filter(f => f.effort === 'project').length;

  return (
    <Page size="A4" style={s.page}>
      <View style={s.coverWrap}>
        <Text style={s.coverEyebrow}>Microsoft 365 Security Audit Report</Text>
        <Text style={s.coverTitle}>{org?.displayName ?? domain}</Text>
        <Text style={s.coverDomain}>{domain}</Text>

        <View style={[s.scoreCircle, { borderColor: color }]}>
          <Text style={[s.scoreNumber, { color }]}>{overallScore}</Text>
          <Text style={s.scoreDenom}>/ 100</Text>
        </View>

        <View style={[s.gradePill, { borderColor: color }]}>
          <Text style={[s.gradePillText, { color }]}>{gradeLabel} Security Posture</Text>
        </View>

        <Text style={s.coverDate}>Audited: {auditedAt}</Text>

        <View style={{ marginTop: 24, width: '100%', maxWidth: 300 }}>
          <View style={[s.section, { marginBottom: 0 }]}>
            <Text style={[s.sectionTitle, { marginBottom: 6 }]}>Findings at a Glance</Text>
            <View style={{ flexDirection: 'row', justifyContent: 'space-between' }}>
              {(['critical', 'high', 'medium', 'low', 'info'] as const).map(sev => {
                const count = findings.filter(f => f.severity === sev).length;
                return (
                  <View key={sev} style={s.sevBox}>
                    <Text style={[s.sevNum, { color: severityHex(sev) }]}>{count}</Text>
                    <Text style={s.sevLabel}>{sev}</Text>
                  </View>
                );
              })}
            </View>
            <View style={{ marginTop: 8 }}>
              <Text style={s.bodyText}>
                {findings.length} total · {quickWins} quick wins · {medium} medium · {project} project
              </Text>
            </View>
          </View>
        </View>
      </View>
      <Text style={s.footer}>Prepared by North Stream Systems · Point-in-time assessment · No data stored</Text>
    </Page>
  );
}

function ScoresPage({ audit }: { audit: ScoredAudit }) {
  const { scores, overallScore, overallGrade, result } = audit;
  const gradeLabel = { good: 'Good', fair: 'Fair', poor: 'Poor', critical: 'Critical' }[overallGrade] ?? overallGrade;
  const org = result.org.organization;
  const domain = result.emailSecurity.domain
    || org?.verifiedDomains.find(d => d.isDefault)?.name || '—';
  const auditedAt = new Date(result.auditedAt).toLocaleString('en-GB', {
    day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit',
  });

  return (
    <Page size="A4" style={s.page}>
      {/* Executive summary */}
      <View style={s.section}>
        <Text style={s.sectionTitle}>Executive Summary</Text>
        <Text style={s.bodyText}>
          This report summarises the Microsoft 365 security posture of {org?.displayName ?? domain} as assessed on {auditedAt}.
          {' '}The tenant achieved an overall security score of {overallScore}/100 ({gradeLabel}).
        </Text>
      </View>

      {/* Category scores */}
      <View style={s.section}>
        <Text style={s.sectionTitle}>Security Category Scores</Text>
        {Object.entries(scores)
          .sort(([, a], [, b]) => a.score - b.score)
          .map(([key, cat]) => {
            const color = gradeHex(cat.grade);
            const catGradeLabel = { good: 'Good', fair: 'Fair', poor: 'Poor', critical: 'Critical' }[cat.grade] ?? cat.grade;
            return (
              <View key={key} style={s.catRow}>
                <View style={s.catHeader}>
                  <Text style={s.catName}>{cat.label}</Text>
                  <Text style={[s.catScore, { color }]}>{cat.score}/100 — {catGradeLabel} (weight {(cat.weight * 100).toFixed(0)}%)</Text>
                </View>
                <View style={s.barBg}>
                  <View style={[s.barFill, { width: `${cat.score}%`, backgroundColor: color }]} />
                </View>
              </View>
            );
          })}
      </View>
      <Text style={s.pageNum} render={({ pageNumber }) => `${pageNumber}`} fixed />
    </Page>
  );
}

function FindingsPage({ audit }: { audit: ScoredAudit }) {
  const { findings } = audit;
  const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'] as const;
  const effortLabel = (e: string) =>
    e === 'quick-win' ? '⚡ Quick' : e === 'medium' ? '⚙ Medium' : '📋 Project';

  return (
    <Page size="A4" style={s.page}>
      <View style={s.section}>
        <Text style={s.sectionTitle}>Findings ({findings.length})</Text>

        {SEVERITY_ORDER.map(sev => {
          const group = findings.filter(f => f.severity === sev);
          if (group.length === 0) return null;
          const color = severityHex(sev);
          return (
            <View key={sev}>
              <Text style={[s.sevGroupLabel, { color, marginBottom: 4 }]}>
                {sev.toUpperCase()} ({group.length})
              </Text>
              {group.map(f => (
                <View key={f.id} style={s.findingCard}>
                  <View style={s.findingHeader}>
                    <Text style={s.findingTitle}>{f.title}</Text>
                    <View style={[s.effortBadge, { borderColor: color }]}>
                      <Text style={[s.effortBadge, { color, borderWidth: 0, padding: 0 }]}>{effortLabel(f.effort)}</Text>
                    </View>
                  </View>
                  <Text style={s.findingDesc}>{f.description}</Text>
                  <Text style={s.findingRec}>{f.recommendation}</Text>
                  {(f.affectedCount ?? 0) > 0 && (
                    <Text style={s.affectedText}>{f.affectedCount} affected</Text>
                  )}
                </View>
              ))}
            </View>
          );
        })}
      </View>
      <Text style={s.pageNum} render={({ pageNumber }) => `${pageNumber}`} fixed />
    </Page>
  );
}

function RoadmapPage({ audit }: { audit: ScoredAudit }) {
  const { findings } = audit;
  const quickWins = findings.filter(f => f.effort === 'quick-win');
  const medium    = findings.filter(f => f.effort === 'medium');
  const project   = findings.filter(f => f.effort === 'project');

  const sections = [
    { title: 'Quick Wins', subtitle: 'Complete first — single portal change, under 30 mins, no user impact', color: C.good,     items: quickWins },
    { title: 'Medium Effort', subtitle: 'Schedule this week — requires planning or user communication',        color: C.fair,     items: medium    },
    { title: 'Project Work', subtitle: 'Scope and plan — multi-week, coordination required',                   color: '#fb923c',  items: project   },
  ];

  return (
    <Page size="A4" style={s.page}>
      <View style={s.section}>
        <Text style={s.sectionTitle}>Remediation Roadmap</Text>

        {sections.map(sec => {
          if (sec.items.length === 0) return null;
          return (
            <View key={sec.title}>
              <Text style={[s.roadSectionTitle, { color: sec.color }]}>{sec.title}</Text>
              <Text style={s.roadSectionSub}>{sec.subtitle}</Text>

              {sec.items.map((f, idx) => {
                const guide = remediationSteps[f.id] ?? null;
                return (
                  <View key={f.id} style={s.roadmapItem}>
                    <View style={s.roadmapHeader}>
                      <View style={{ flexDirection: 'row', alignItems: 'center', flex: 1 }}>
                        <View style={s.roadmapIdx}>
                          <Text style={s.roadmapIdxText}>{idx + 1}</Text>
                        </View>
                        <Text style={s.roadmapTitle}>{f.title}</Text>
                      </View>
                      {guide && (
                        <Text style={s.roadmapTime}>{fmtMins(guide.estimatedMinutes)}</Text>
                      )}
                    </View>

                    <View style={s.roadmapBody}>
                      {guide ? (
                        <>
                          {guide.whyItMatters && (
                            <Text style={s.roadmapWhy}>"{guide.whyItMatters}"</Text>
                          )}
                          {guide.steps.map((step, i) => (
                            <View key={i} style={s.stepRow}>
                              <View style={s.stepNum}>
                                <Text style={s.stepNumText}>{i + 1}</Text>
                              </View>
                              <Text style={s.stepText}>{step}</Text>
                            </View>
                          ))}
                          {guide.caveats && (
                            <Text style={s.caveatText}>⚠ {guide.caveats}</Text>
                          )}
                          {guide.docsUrl && (
                            <Link src={guide.docsUrl} style={{ fontSize: 7, color: C.blue, marginTop: 4 }}>
                              Microsoft documentation ↗
                            </Link>
                          )}
                        </>
                      ) : (
                        <Text style={s.stepText}>{f.recommendation}</Text>
                      )}
                    </View>
                  </View>
                );
              })}
            </View>
          );
        })}
      </View>
      <Text style={s.pageNum} render={({ pageNumber }) => `${pageNumber}`} fixed />
    </Page>
  );
}

// ─── Root document ────────────────────────────────────────────────────────────

interface AuditReportPDFProps {
  audit: ScoredAudit;
}

export function AuditReportPDF({ audit }: AuditReportPDFProps) {
  // Debug: confirm data is present
  console.log('[AuditReportPDF] rendering — findings:', audit.findings.length, 'score:', audit.overallScore);

  return (
    <Document
      title={`M365 Security Audit — ${audit.result.org.organization?.displayName ?? 'Tenant'}`}
      author="North Stream Systems TenantAudit"
    >
      <CoverPage   audit={audit} />
      <ScoresPage  audit={audit} />
      <FindingsPage  audit={audit} />
      <RoadmapPage audit={audit} />
    </Document>
  );
}
