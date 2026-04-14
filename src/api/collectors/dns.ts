import { EmailSecurityData, DnsResponse } from '../../types/audit';

const DNS_API = 'https://dns.google/resolve';

async function queryDns(name: string, type: string): Promise<string[]> {
  try {
    const res = await fetch(`${DNS_API}?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`);
    if (!res.ok) return [];
    const data: DnsResponse = await res.json();
    return data.Answer?.map(a => a.data) ?? [];
  } catch {
    return [];
  }
}

export async function collectDns(domain: string): Promise<EmailSecurityData> {
  try {
    const [txtRecords, dmarcRecords, dkim1Records, dkim2Records, mxRecords] = await Promise.all([
      queryDns(domain, 'TXT'),
      queryDns(`_dmarc.${domain}`, 'TXT'),
      queryDns(`selector1._domainkey.${domain}`, 'TXT'),
      queryDns(`selector2._domainkey.${domain}`, 'TXT'),
      queryDns(domain, 'MX'),
    ]);

    const spfRecord = txtRecords.find(r => r.includes('v=spf1')) ?? null;
    const dmarcRecord = dmarcRecords.find(r => r.includes('v=DMARC1')) ?? null;
    const dkim1Record = dkim1Records.find(r => r.includes('v=DKIM1')) ?? null;
    const dkim2Record = dkim2Records.find(r => r.includes('v=DKIM1')) ?? null;

    return {
      domain,
      spfRecord,
      dmarcRecord,
      dkim1Record,
      dkim2Record,
      mxRecords,
      error: null,
    };
  } catch (e) {
    return {
      domain,
      spfRecord: null,
      dmarcRecord: null,
      dkim1Record: null,
      dkim2Record: null,
      mxRecords: [],
      error: (e as Error).message,
    };
  }
}
