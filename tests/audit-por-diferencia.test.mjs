// Prueba el script EMBEBIDO en .github/workflows/pnpm-audit.yml (el mismo texto que corre en
// los repos consumidores), con un pnpm falso que lee `audit.json` del directorio donde corre.
// Cada caso monta un repo git con dos commits (base y head) y mide el código de salida:
// 0 sin avisos nuevos · 1 hay nuevos · 2 no se pudo medir.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync, spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const aqui = dirname(fileURLToPath(import.meta.url))
const yml = readFileSync(join(aqui, '..', '.github/workflows/pnpm-audit.yml'), 'utf8')
const ini = yml.indexOf("<<'AUDIT_EOF'\n") + "<<'AUDIT_EOF'\n".length
const fin = yml.indexOf('          AUDIT_EOF')
assert.ok(ini > 20 && fin > ini, 'no se encontró el script embebido en el workflow')
const sangria = '          '
const script = yml
  .slice(ini, fin)
  .split('\n')
  .map((l) => (l.startsWith(sangria) ? l.slice(sangria.length) : l))
  .join('\n')

const tmp = mkdtempSync(join(tmpdir(), 'prueba-audit-'))
const scriptPath = join(tmp, 'audit.mjs')
const fakePath = join(tmp, 'fake-pnpm.mjs')
writeFileSync(scriptPath, script)
// pnpm falso: imprime audit.json del cwd y sale 1 (como pnpm audit cuando encuentra algo).
writeFileSync(fakePath, "import{readFileSync}from'node:fs';process.stdout.write(readFileSync('audit.json','utf8'));process.exit(1)\n")

const aviso = (ghsa, severity = 'high', rango = '<=4.0.7') => ({
  github_advisory_id: ghsa,
  module_name: 'picomatch',
  severity,
  vulnerable_versions: rango,
  title: `aviso ${ghsa}`,
})
const json = (...avisos) => JSON.stringify({ advisories: Object.fromEntries(avisos.map((a, i) => [i, a])) })

function git(cwd, ...args) {
  return execFileSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@t', ...args], { cwd, encoding: 'utf8' }).trim()
}

/** Repo con dos commits: devuelve {dir, base}. `head` y `base` son el texto de audit.json. */
function repo(base, head) {
  const dir = mkdtempSync(join(tmp, 'r-'))
  git(dir, 'init', '-q')
  writeFileSync(join(dir, 'pnpm-lock.yaml'), 'lockfileVersion: 9\n')
  writeFileSync(join(dir, 'audit.json'), base)
  git(dir, 'add', '.')
  git(dir, 'commit', '-q', '-m', 'base')
  const sha = git(dir, 'rev-parse', 'HEAD')
  writeFileSync(join(dir, 'audit.json'), head)
  git(dir, 'commit', '-q', '--allow-empty', '-am', 'head')
  return { dir, sha }
}

function correr(dir, baseSha) {
  const env = { ...process.env, PNPM_CMD: `node ${fakePath}` }
  delete env.BASE_SHA
  if (baseSha) env.BASE_SHA = baseSha
  const r = spawnSync('node', [scriptPath], { cwd: dir, env, encoding: 'utf8' })
  return { code: r.status, out: r.stdout + r.stderr }
}

test('base = head → 0', () => {
  const j = json(aviso('GHSA-aaaa'))
  const { dir, sha } = repo(j, j)
  assert.equal(correr(dir, sha).code, 0)
})

test('aviso high nuevo → 1', () => {
  const { dir, sha } = repo(json(), json(aviso('GHSA-nuevo')))
  const r = correr(dir, sha)
  assert.equal(r.code, 1)
  assert.match(r.out, /GHSA-nuevo/)
})

test('deuda heredada: el mismo aviso en la base no bloquea → 0', () => {
  const j = json(aviso('GHSA-viejo'))
  const { dir, sha } = repo(j, j)
  const r = correr(dir, sha)
  assert.equal(r.code, 0)
  assert.match(r.out, /Deuda heredada/)
})

test('aviso critical nuevo → 1', () => {
  const { dir, sha } = repo(json(), json(aviso('GHSA-crit', 'critical')))
  assert.equal(correr(dir, sha).code, 1)
})

test('aviso nuevo solo moderate/low → 0', () => {
  const { dir, sha } = repo(json(), json(aviso('GHSA-bajo', 'moderate')))
  assert.equal(correr(dir, sha).code, 0)
})

test('JSON ilegible en el head → 2 (nunca 0)', () => {
  const { dir, sha } = repo(json(), 'esto no es json')
  assert.equal(correr(dir, sha).code, 2)
})

test('JSON sin advisories → 2', () => {
  const { dir, sha } = repo(json(), '{"error":"registro caído"}')
  assert.equal(correr(dir, sha).code, 2)
})

test('sin BASE_SHA → 2', () => {
  const { dir } = repo(json(), json())
  assert.equal(correr(dir, undefined).code, 2)
})

test('base inalcanzable (fallo de git) → 2, no 1', () => {
  const { dir } = repo(json(), json(aviso('GHSA-x')))
  assert.equal(correr(dir, '0000000000000000000000000000000000000001').code, 2)
})
