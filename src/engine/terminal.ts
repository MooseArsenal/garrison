// A small Windows command emulator. Output is derived from the host's live
// state so what the trainee sees is consistent with Task Manager / Device
// Manager / Directory. Commands can also mutate state (ipconfig /renew,
// taskkill, w32tm /resync, gpupdate).

import type { Host, World } from './types';
import { findUser } from './world';

export interface TermResult {
  output: string;
  /** canonical action name for the action log, e.g. 'ipconfig', 'ping' */
  action: string;
  target?: string;
  mutated?: boolean;
}

function pad(s: string | number, n: number): string {
  return String(s).padEnd(n);
}

export function runCommand(world: World, host: Host, raw: string): TermResult {
  const line = raw.trim();
  const [cmd0, ...args] = line.split(/\s+/);
  const cmd = (cmd0 ?? '').toLowerCase();
  const argl = args.map((a) => a.toLowerCase());
  const net = host.network;

  switch (cmd) {
    case '':
      return { output: '', action: 'noop' };
    case 'help':
      return {
        action: 'help',
        output: `Supported: ipconfig [/all|/release|/renew|/flushdns], ping <host>, tracert <host>, nslookup <name>, netstat -ano, tasklist, taskkill /PID <n> /F, sfc /scannow, dism, gpupdate /force, whoami [/groups], systeminfo, w32tm /resync, net user <user> /domain, hostname, dir <path>, schtasks /query, sc query <svc>, sc start|stop <svc>, cls`,
      };
    case 'cls':
      return { output: '\u0000CLEAR', action: 'cls' };
    case 'hostname':
      return { output: host.id.toLowerCase(), action: 'hostname' };
    case 'whoami': {
      const owner = host.owner ?? 'nobody';
      if (argl.includes('/groups')) {
        const u = findUser(world, owner);
        const groups = u ? u.groups : [];
        return {
          action: 'whoami_groups', target: owner,
          output: `GROUP INFORMATION\n-----------------\n${['Everyone', 'BUILTIN\\Users', 'NT AUTHORITY\\INTERACTIVE', ...groups.map((g) => 'KESTREL\\' + g)].map((g) => pad(g, 40) + 'Mandatory group, Enabled by default, Enabled group').join('\n')}\n\n(Note: token reflects groups at LOGON time. Group changes need a fresh logon.)`,
        };
      }
      return { output: `kestrel\\${owner}`, action: 'whoami', target: owner };
    }
    case 'ipconfig': {
      if (argl.includes('/release')) {
        if (!net.dhcp) return { output: 'The operation failed as no adapter is in the state permissible for this operation (static IP).', action: 'ipconfig_release' };
        net.ip = '0.0.0.0';
        return { output: `Windows IP Configuration\n\n${net.adapter}:\n   IPv4 Address. . . . . . . . . . . : (released)`, action: 'ipconfig_release', mutated: true };
      }
      if (argl.includes('/renew')) {
        if (!net.dhcp) return { output: 'The operation failed as no adapter is in the state permissible for this operation (static IP).', action: 'ipconfig_renew' };
        if (net.adapterStatus !== 'up') return { output: `An error occurred while renewing interface ${net.adapter}: unable to contact your DHCP server (media disconnected).`, action: 'ipconfig_renew' };
        const exhausted = (host as unknown as { _dhcpExhausted?: boolean })._dhcpExhausted;
        if (exhausted || net.ip.startsWith('169.254')) {
          const scopeName = world.servers.flatMap((s) => s.dhcpScopes ?? []).find((sc) => sc.status === 'exhausted');
          if (scopeName) return { output: `An error occurred while renewing interface ${net.adapter}: unable to contact your DHCP server. Request has timed out.\n\n(No DHCPOFFER received)`, action: 'ipconfig_renew' };
          // repaired scope: hand out an address
          net.ip = host.ip.startsWith('169.254') ? '10.10.20.' + (200 + (host.id.length % 40)) : host.ip;
          host.ip = net.ip;
          return { output: `Windows IP Configuration\n\n${net.adapter}:\n   IPv4 Address. . . . . . . . . . . : ${net.ip}\n   Subnet Mask . . . . . . . . . . . : ${net.mask}\n   Default Gateway . . . . . . . . . : ${net.gateway}`, action: 'ipconfig_renew', mutated: true };
        }
        net.ip = host.ip;
        return { output: `Windows IP Configuration\n\n${net.adapter}:\n   IPv4 Address. . . . . . . . . . . : ${net.ip}\n   Subnet Mask . . . . . . . . . . . : ${net.mask}\n   Default Gateway . . . . . . . . . : ${net.gateway}`, action: 'ipconfig_renew', mutated: true };
      }
      if (argl.includes('/flushdns')) return { output: 'Windows IP Configuration\n\nSuccessfully flushed the DNS Resolver Cache.', action: 'ipconfig_flushdns', mutated: true };
      const all = argl.includes('/all');
      const disc = net.adapterStatus !== 'up';
      const lines = [
        'Windows IP Configuration', '',
        ...(all ? [`   Host Name . . . . . . . . . . . . : ${host.id}`, `   Primary Dns Suffix  . . . . . . . : kestrel.local`, `   DNS Suffix Search List. . . . . . : kestrel.local`, ''] : []),
        `${net.adapter}:`, '',
        ...(disc ? [`   Media State . . . . . . . . . . . : Media disconnected`] : [
          ...(all ? [`   Physical Address. . . . . . . . . : ${host.mac}`, `   DHCP Enabled. . . . . . . . . . . : ${net.dhcp ? 'Yes' : 'No'}`] : []),
          `   IPv4 Address. . . . . . . . . . . : ${net.ip}${net.ip.startsWith('169.254') ? ' (Autoconfiguration)' : ''}`,
          `   Subnet Mask . . . . . . . . . . . : ${net.ip.startsWith('169.254') ? '255.255.0.0' : net.mask}`,
          `   Default Gateway . . . . . . . . . : ${net.ip.startsWith('169.254') ? '' : net.gateway}`,
          ...(all ? [`   DHCP Server . . . . . . . . . . . : ${net.dhcp && !net.ip.startsWith('169.254') ? net.gateway.replace(/\.1$/, '.5').replace('10.10.20.5', '10.10.10.5').replace('10.10.21.5', '10.10.10.5') : ''}`, `   DNS Servers . . . . . . . . . . . : ${net.dns.join('\n                                       ')}`, `   Lease Obtained. . . . . . . . . . : ${net.dhcp ? world.now.replace('T', ' ') : 'N/A'}`] : []),
        ]),
        ...(net.ssid ? ['', `   SSID  . . . . . . . . . . . . . . : ${net.ssid}`] : []),
        ...(net.vpn === 'connected' ? ['', 'Kestrel VPN (PPP adapter):', '', `   IPv4 Address. . . . . . . . . . . : ${net.ip}`] : []),
        ...(net.vpn === 'disconnected' ? ['', 'Kestrel VPN (PPP adapter):', '', `   Media State . . . . . . . . . . . : Media disconnected`] : []),
      ];
      return { output: lines.join('\n'), action: all ? 'ipconfig_all' : 'ipconfig' };
    }
    case 'ping': {
      const target = args[0];
      if (!target) return { output: 'Usage: ping <host>', action: 'ping' };
      const t = target.toLowerCase();
      const noNet = net.adapterStatus !== 'up' || net.ip.startsWith('169.254') || net.ip === '0.0.0.0';
      const isGw = t === net.gateway;
      const wrongDns = net.dns.some((d) => !['10.10.10.5', '10.10.10.6', '10.20.10.5'].includes(d));
      const isIp = /^\d+\.\d+\.\d+\.\d+$/.test(t);
      const knownNames: Record<string, string> = { 'fs01': '10.10.10.20', 'den-fs01': '10.10.10.20', 'fs01.kestrel.local': '10.10.10.20', 'den-dc01': '10.10.10.5', 'dc01': '10.10.10.5', 'print01': '10.10.10.25', 'den-print01': '10.10.10.25', 'erp.kestrel.local': '10.10.10.40', 'erp': '10.10.10.40', 'den-app01': '10.10.10.40', 'kestreldynamics.com': '198.51.100.20', 'www.google.com': '142.250.72.4', 'google.com': '142.250.72.4' };
      if (noNet && !isGw) return { output: `Pinging ${target}... \nPING: transmit failed. General failure.`, action: 'ping', target: t };
      if (noNet) return { output: `Pinging ${target} with 32 bytes of data:\nRequest timed out.\nRequest timed out.\nRequest timed out.\nRequest timed out.\n\nPing statistics for ${target}: Packets: Sent = 4, Received = 0, Lost = 4 (100% loss)`, action: 'ping', target: t };
      let ip = t;
      if (!isIp) {
        const dnsDown = (host as unknown as { _dnsBroken?: boolean })._dnsBroken || wrongDns;
        if (dnsDown || !knownNames[t]) return { output: `Ping request could not find host ${target}. Please check the name and try again.`, action: 'ping', target: t };
        ip = knownNames[t];
      }
      const srv = world.servers.find((s) => s.ip === ip);
      if (srv && srv.status === 'offline') return { output: `Pinging ${target} [${ip}] with 32 bytes of data:\nRequest timed out.\nRequest timed out.\nRequest timed out.\nRequest timed out.\n\nPing statistics for ${ip}: Packets: Sent = 4, Received = 0, Lost = 4 (100% loss)`, action: 'ping', target: t };
      const external = !ip.startsWith('10.');
      const inetDown = (host as unknown as { _inetBroken?: boolean })._inetBroken;
      if (external && inetDown) return { output: `Pinging ${target} [${ip}] with 32 bytes of data:\nRequest timed out.\nRequest timed out.\nRequest timed out.\nRequest timed out.\n\nPing statistics for ${ip}: Packets: Sent = 4, Received = 0, Lost = 4 (100% loss)`, action: 'ping', target: t };
      const ms = external ? 18 : isGw ? 1 : 2;
      return { output: `Pinging ${target}${isIp ? '' : ' [' + ip + ']'} with 32 bytes of data:\n${Array(4).fill(`Reply from ${ip}: bytes=32 time=${ms}ms TTL=${external ? 116 : 128}`).join('\n')}\n\nPing statistics for ${ip}: Packets: Sent = 4, Received = 4, Lost = 0 (0% loss)`, action: 'ping', target: t };
    }
    case 'tracert': {
      const target = args[0] ?? '';
      return { output: `Tracing route to ${target}\n  1     1 ms   ${net.gateway}\n  2     3 ms   10.10.1.1\n  3    12 ms   198.51.100.1\n  4    18 ms   ${target}\n\nTrace complete.`, action: 'tracert', target: target.toLowerCase() };
    }
    case 'nslookup': {
      const name = (args[0] ?? '').toLowerCase();
      if (!name) return { output: `Default Server:  den-dc01.kestrel.local\nAddress:  ${net.dns[0]}`, action: 'nslookup' };
      const wrongDns = net.dns.some((d) => !['10.10.10.5', '10.10.10.6', '10.20.10.5'].includes(d));
      const dnsDown = (host as unknown as { _dnsBroken?: boolean })._dnsBroken || wrongDns || net.ip.startsWith('169.254') || net.adapterStatus !== 'up';
      if (dnsDown) return { output: `Server:  UnKnown\nAddress:  ${net.dns[0]}\n\n*** UnKnown can't find ${name}: Server failed`, action: 'nslookup', target: name };
      const recs = world.servers.flatMap((s) => s.dnsRecords ?? []);
      const rec = recs.find((r) => r.name.toLowerCase() === name || r.name.toLowerCase() === name + '.kestrel.local');
      const ext: Record<string, string> = { 'www.google.com': '142.250.72.4', 'google.com': '142.250.72.4', 'kestreldynamics.com': '198.51.100.20', 'login.worksuite-mail.net': '52.96.1.10' };
      const answer = rec?.value ?? ext[name];
      if (!answer) return { output: `Server:  den-dc01.kestrel.local\nAddress:  ${net.dns[0]}\n\n*** den-dc01.kestrel.local can't find ${name}: Non-existent domain`, action: 'nslookup', target: name };
      return { output: `Server:  den-dc01.kestrel.local\nAddress:  ${net.dns[0]}\n\nName:    ${name}\nAddress:  ${answer}`, action: 'nslookup', target: name };
    }
    case 'netstat': {
      const conns = (host as unknown as { _connections?: { proto: string; local: string; remote: string; state: string; pid: number }[] })._connections ?? [];
      const base = [
        { proto: 'TCP', local: `${net.ip}:49712`, remote: '52.96.1.10:443', state: 'ESTABLISHED', pid: 3120 },
        { proto: 'TCP', local: `${net.ip}:49720`, remote: '52.113.194.132:443', state: 'ESTABLISHED', pid: 3388 },
        { proto: 'TCP', local: `${net.ip}:49733`, remote: '142.250.72.4:443', state: 'ESTABLISHED', pid: 3610 },
        { proto: 'TCP', local: `${net.ip}:49740`, remote: '34.117.59.81:443', state: 'ESTABLISHED', pid: 1450 },
        { proto: 'TCP', local: `${net.ip}:49751`, remote: '10.10.10.20:445', state: 'ESTABLISHED', pid: 4 },
        { proto: 'TCP', local: '0.0.0.0:135', remote: '0.0.0.0:0', state: 'LISTENING', pid: 812 },
        { proto: 'TCP', local: '0.0.0.0:445', remote: '0.0.0.0:0', state: 'LISTENING', pid: 4 },
      ];
      const rows = [...base, ...conns].map((c) => `  ${pad(c.proto, 6)}${pad(c.local, 24)}${pad(c.remote, 24)}${pad(c.state, 14)}${c.pid}`);
      return { output: `Active Connections\n\n  Proto  Local Address           Foreign Address         State          PID\n${rows.join('\n')}`, action: 'netstat' };
    }
    case 'tasklist': {
      const rows = host.processes.map((p) => `${pad(p.name, 28)}${pad(p.pid, 8)}${pad(p.user.replace('KESTREL\\', ''), 18)}${String(Math.round(p.mem * 1024)).padStart(10)} K`);
      return { output: `Image Name                  PID     Session Name        Mem Usage\n========================= ======== ================ ============\n${rows.join('\n')}`, action: 'tasklist' };
    }
    case 'taskkill': {
      const pidIdx = argl.indexOf('/pid');
      const imIdx = argl.indexOf('/im');
      let proc = undefined as undefined | Host['processes'][number];
      if (pidIdx >= 0) proc = host.processes.find((p) => p.pid === Number(args[pidIdx + 1]));
      if (imIdx >= 0) proc = host.processes.find((p) => p.name.toLowerCase() === argl[imIdx + 1]);
      if (!proc) return { output: 'ERROR: The process not found.', action: 'taskkill' };
      host.processes = host.processes.filter((p) => p !== proc && p.parentPid !== proc!.pid);
      return { output: `SUCCESS: The process "${proc.name}" with PID ${proc.pid} has been terminated.`, action: 'taskkill', target: proc.name.toLowerCase(), mutated: true };
    }
    case 'sfc':
      return { output: 'Beginning system scan.  This process will take some time.\n\nVerification 100% complete.\n\nWindows Resource Protection did not find any integrity violations.', action: 'sfc' };
    case 'dism':
      return { output: 'Deployment Image Servicing and Management tool\nVersion: 10.0.26100.1\n\nImage Version: 10.0.26100.1742\n\n[==========================100.0%==========================]\nThe restore operation completed successfully.\nThe operation completed successfully.', action: 'dism' };
    case 'gpupdate':
      return { output: 'Updating policy...\n\nComputer Policy update has completed successfully.\nUser Policy update has completed successfully.', action: 'gpupdate', mutated: true };
    case 'systeminfo':
      return {
        action: 'systeminfo',
        output: `Host Name:                 ${host.id}\nOS Name:                   Microsoft ${host.os}\nOS Version:                10.0.${host.build ?? '26100'}\nSystem Boot Time:          ${new Date(new Date(world.now).getTime() - host.uptimeHours * 3600e3).toISOString().replace('T', ' ').slice(0, 16)}\nSystem Uptime:             ${Math.floor(host.uptimeHours / 24)} Days, ${host.uptimeHours % 24} Hours\nTime Zone:                 ${host.timeZone ?? 'Mountain Standard Time'}\nDomain:                    ${host.domainJoined ? 'kestrel.local' : 'WORKGROUP'}\nLogon Server:              \\\\DEN-DC01\nTotal Physical Memory:     16,384 MB\nHotfix(s):                 Last installed ${host.updates.lastInstalled.slice(0, 10)}, ${host.updates.pending} pending\nNetwork Card(s):           ${net.adapter} - ${net.ip}`,
      };
    case 'w32tm': {
      if (argl.includes('/resync')) {
        const skew = host.clockSkewSec ?? 0;
        host.clockSkewSec = 0;
        return { output: `Sending resync command to local computer\nThe command completed successfully.${skew ? `\n(Clock adjusted by ${skew} seconds.)` : ''}`, action: 'w32tm_resync', mutated: true };
      }
      return { output: `Leap Indicator: 0(no warning)\nSource: DEN-DC01.kestrel.local\nPhase Offset: ${host.clockSkewSec ?? 0}s`, action: 'w32tm' };
    }
    case 'net': {
      if (argl[0] === 'user' && args[1]) {
        const u = findUser(world, args[1]);
        if (!u) return { output: 'The user name could not be found.', action: 'net_user', target: args[1].toLowerCase() };
        return {
          action: 'net_user', target: u.id,
          output: `User name                    ${u.id}\nFull Name                    ${u.displayName}\nAccount active               ${u.enabled ? 'Yes' : 'No'}\nAccount locked out           ${u.lockedOut ? 'Yes' : 'No'}\nPassword last set            ${host.clockSkewSec ? '?' : u.passwordLastSet.replace('T', ' ')}\nPassword expires             ${u.passwordNeverExpires ? 'Never' : u.passwordExpired ? 'EXPIRED' : new Date(new Date(u.passwordLastSet).getTime() + 90 * 86400e3).toISOString().slice(0, 10)}\nLast logon                   ${u.lastLogon.replace('T', ' ')}\nGlobal Group memberships     ${u.groups.map((g) => '*' + g).join(' ')}\nThe command completed successfully.`,
        };
      }
      return { output: 'The syntax of this command is:\n\nNET USER <username> /DOMAIN', action: 'net' };
    }
    case 'dir': {
      const p = (args[0] ?? 'C:\\').toLowerCase();
      const files = host.files.filter((f) => f.path.toLowerCase().startsWith(p) || p === 'c:\\');
      if (!files.length) return { output: `File Not Found`, action: 'dir', target: p };
      return { output: ` Directory of ${args[0] ?? 'C:\\'}\n\n${files.map((f) => `${f.modified.replace('T', ' ').slice(0, 16)}   ${String(f.size).padStart(12)} ${f.path.split('\\').pop() || f.path}`).join('\n')}`, action: 'dir', target: p };
    }
    case 'schtasks':
      return { output: `Folder: \\\n${host.scheduledTasks.map((t) => `${pad(t.name, 36)}${pad(t.trigger, 20)}${t.action}   (author: ${t.author})`).join('\n')}`, action: 'schtasks' };
    case 'sc': {
      const sub = argl[0]; const name = args[1];
      const s = host.services.find((x) => x.name.toLowerCase() === (name ?? '').toLowerCase());
      if (!s) return { output: '[SC] OpenService FAILED 1060:\n\nThe specified service does not exist as an installed service.', action: 'sc', target: name?.toLowerCase() };
      if (sub === 'query') return { output: `SERVICE_NAME: ${s.name}\n        DISPLAY_NAME: ${s.displayName}\n        STATE              : ${s.status.toUpperCase()}\n        START_TYPE         : ${s.startType.toUpperCase()}${s.path ? `\n        BINARY_PATH_NAME   : ${s.path}` : ''}`, action: 'sc_query', target: s.name.toLowerCase() };
      if (sub === 'start') { s.status = 'running'; return { output: `SERVICE_NAME: ${s.name}\n        STATE : 4  RUNNING`, action: 'sc_start', target: s.name.toLowerCase(), mutated: true }; }
      if (sub === 'stop') { s.status = 'stopped'; return { output: `SERVICE_NAME: ${s.name}\n        STATE : 1  STOPPED`, action: 'sc_stop', target: s.name.toLowerCase(), mutated: true }; }
      return { output: 'Usage: sc query|start|stop <service>', action: 'sc' };
    }
    default:
      return { output: `'${cmd0}' is not recognized as an internal or external command,\noperable program or batch file.`, action: 'unknown', target: cmd };
  }
}
