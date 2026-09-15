import type React from 'react';
import { Queue } from './Queue';
import { Kb } from './Kb';
import { Directory } from './Directory';
import { RemoteDesktop } from './RemoteDesktop';
import { ServerRoom } from './ServerRoom';
import { Assets } from './Assets';
import { Mail } from './Mail';
import { Chat } from './Chat';
import { Siem } from './Siem';
import { Edr } from './Edr';
import { Intel } from './Intel';
import { Perimeter } from './Perimeter';
import { Incident } from './Incident';

export const TOOL_COMPONENTS: Record<string, React.ComponentType> = {
  queue: Queue,
  kb: Kb,
  directory: Directory,
  rdp: RemoteDesktop,
  server: ServerRoom,
  assets: Assets,
  mail: Mail,
  chat: Chat,
  siem: Siem,
  edr: Edr,
  intel: Intel,
  perimeter: Perimeter,
  incident: Incident,
};
