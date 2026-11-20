/**
 * Module loading sink hook (README "Code", `code.include`): a module
 * specifier passed to `require` (and the functions `module.createRequire`
 * returns, which go through the same method) is checked during a request for
 * a name or path that came from input. Dynamic `import()` is resolved by the
 * ESM loader and is not covered here.
 *
 * `Module.prototype.require` is also wrapped by require-in-the-middle (the
 * SDK's own instrumentations and OpenTelemetry's), so this hook follows the
 * same rules as the others: one generation per install, a wrapper checks only
 * while its generation is current, and uninstall restores the original only
 * where RASP's wrapper is still on top.
 */
import Module = require('module');
import { isAbsolute } from 'path';
import { currentContext, inputsOf } from '../context';
import { detectInclude } from '../detect';
import { check, isActive, strongest } from '../engine';
import { detectUploadInclude, locationCount } from '../upload-taint';

type Require = (this: unknown, id: string) => unknown;
type Target = { require: Require };
type Saved = { target: Target; descriptor: PropertyDescriptor; wrapper: Require };

/** Node's own `Module.prototype` (tests pass a stand-in: under Jest it is Jest's). */
const proto = (Module as unknown as { prototype: Target }).prototype;
let installed: Saved | undefined;
let generation = 0;
let checking = false;

function inspect(id: unknown, parent: unknown): void {
  if (checking || typeof id !== 'string' || !isActive()) return;
  const ctx = currentContext();
  checking = true;
  try {
    // SHIELD: uploads — loading an uploaded file as code (`backdoor.include`), in a request or not.
    const backdoor = locationCount() ? detectUploadInclude(resolved(id, parent)) : null;
    if (!ctx?.inRequest && !backdoor) return;
    check('module.require', () => strongest(backdoor, ctx?.inRequest ? detectInclude(id, inputsOf(ctx)) : null));
  } finally {
    checking = false;
  }
}

/** The file a specifier loads, by Node's own resolution; undefined when it cannot be resolved (Node then throws as before). */
function resolved(id: string, parent: unknown): string | undefined {
  try {
    const r = (Module as unknown as { _resolveFilename?: (id: string, parent: unknown) => string })._resolveFilename;
    return typeof r === 'function' ? r(id, parent) : isAbsolute(id) ? id : undefined;
  } catch {
    // Not resolvable (a file not there yet, a stand-in loader): an absolute path is still the file it names.
    return isAbsolute(id) ? id : undefined;
  }
}

/** Wraps `Module.prototype.require`. Idempotent; never throws. */
export function installIncludeHooks(target: Target = proto): boolean {
  if (installed) return true;
  try {
    const descriptor = Object.getOwnPropertyDescriptor(target, 'require');
    if (!descriptor || typeof descriptor.value !== 'function') return false;
    const original = descriptor.value as Require;
    const gen = ++generation;
    const wrapper = function (this: unknown, id: string): unknown {
      if (gen === generation) inspect(id, this);
      return Reflect.apply(original, this, [id]);
    } as Require;
    for (const key of Reflect.ownKeys(original)) {
      if (key === 'prototype') continue;
      Object.defineProperty(wrapper, key, Object.getOwnPropertyDescriptor(original, key)!);
    }
    Object.defineProperty(target, 'require', { ...descriptor, value: wrapper });
    installed = { target, descriptor, wrapper };
    return true;
  } catch {
    return false;
  }
}

/** Ends this generation; puts the original back where RASP's wrapper is still on top. Idempotent. */
export function uninstallIncludeHooks(): void {
  if (!installed) return;
  generation++;
  const { target, descriptor, wrapper } = installed;
  if (Object.getOwnPropertyDescriptor(target, 'require')?.value === wrapper) Object.defineProperty(target, 'require', descriptor);
  installed = undefined;
}
