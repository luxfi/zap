/**
 * @hanzo/zap-mdns — mDNS publish + browse for Hanzo services per HIP-0069.
 *
 * Single source of truth for the service-type, TXT key list, and role enum
 * across every Node service in the Hanzo stack (hanzo-iam, hanzo-desktop,
 * @hanzo/extension's native-messaging helper).
 */
import { Bonjour, type Service as BonjourService } from 'bonjour-service';
import * as os from 'os';

export const SERVICE_TYPE = 'hanzo' as const; // bonjour adds the _ + _tcp + .local. parts

export type Role =
  | 'mcp' | 'iam' | 'kms' | 'mpc' | 'base' | 'engine'
  | 'browser' | 'node' | 'desktop' | 'gateway' | 'static';

export interface PublishOptions {
  role: Role;
  port: number;
  version: string;
  serverId?: string;          // defaults to <role>-<host>-<pid>
  org?: string;               // default 'hanzo'
  proto?: string;             // default 'zap/1'
  capabilities?: string[];
  agentLabel?: string;
  auth?: 'none' | 'iam' | 'mtls';
}

export interface HanzoService {
  role: Role;
  serverId: string;
  org: string;
  version: string;
  proto: string;
  capabilities: string[];
  agentLabel: string;
  auth: string;
  host: string;
  port: number;
}

export class Publisher {
  constructor(private bonjour: Bonjour, private svc: BonjourService) {}
  close(): Promise<void> {
    return new Promise((resolve) => {
      this.svc.stop(() => {
        this.bonjour.destroy();
        resolve();
      });
    });
  }
  get url(): string {
    return `ws://${os.hostname()}:${this.svc.port}/`;
  }
}

export function publish(opts: PublishOptions): Publisher {
  const host = os.hostname();
  const serverId = opts.serverId ?? `${opts.role}-${host}-${process.pid}`;
  const txt: Record<string, string> = {
    role: opts.role,
    server_id: serverId,
    org: opts.org ?? 'hanzo',
    version: opts.version,
    proto: opts.proto ?? 'zap/1',
    capabilities: (opts.capabilities ?? []).join(','),
    auth: opts.auth ?? 'none',
  };
  if (opts.agentLabel) txt.agent_label = opts.agentLabel;

  const bonjour = new Bonjour();
  const svc = bonjour.publish({
    name: serverId,
    type: SERVICE_TYPE,
    port: opts.port,
    txt,
  });
  return new Publisher(bonjour, svc);
}

/** Browse the LAN for Hanzo services. Optionally filter by role. */
export function browse(opts: { role?: Role; timeoutMs?: number } = {}): Promise<HanzoService[]> {
  const timeout = opts.timeoutMs ?? 2000;
  const bonjour = new Bonjour();
  const found: HanzoService[] = [];

  return new Promise((resolve) => {
    const browser = bonjour.find({ type: SERVICE_TYPE }, (svc: BonjourService) => {
      const txt = (svc.txt ?? {}) as Record<string, string>;
      const role = txt.role as Role;
      if (!role) return;
      if (opts.role && role !== opts.role) return;
      const ipv4 = (svc.addresses ?? []).find((a) => /^\d+\.\d+\.\d+\.\d+$/.test(a));
      found.push({
        role,
        serverId: txt.server_id ?? svc.name,
        org: txt.org ?? 'hanzo',
        version: txt.version ?? '',
        proto: txt.proto ?? 'zap/1',
        capabilities: (txt.capabilities ?? '').split(',').filter(Boolean),
        agentLabel: txt.agent_label ?? '',
        auth: txt.auth ?? 'none',
        host: ipv4 ?? svc.host ?? '127.0.0.1',
        port: svc.port,
      });
    });
    setTimeout(() => {
      browser.stop();
      bonjour.destroy();
      resolve(found);
    }, timeout);
  });
}
